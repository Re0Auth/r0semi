package observability

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The alerting rules and the Grafana dashboard are operational artifacts that
// read this package's metrics by name. A renamed metric leaves them silently
// broken — a PromQL expression that matches nothing does not error, it just
// returns no data, and an alert that never fires looks exactly like a system
// that is always healthy. This test is the machine check that keeps the
// artifacts and the code agreeing, the same way openapi_test.go keeps the spec
// and the routes agreeing.
//
// Paths are relative to this package's directory, which is the working directory
// of a test binary.

const (
	rulesPath     = "../../deploy/prometheus/re0auth.rules.yml"
	dashboardPath = "../../deploy/grafana/re0auth-dashboard.json"
)

// metricToken matches a Prometheus metric name belonging to this service. The
// lowercase form excludes the product name in prose ("Re0Auth") and the
// dashboard uid ("re0auth-overview", which has a hyphen).
var metricToken = regexp.MustCompile(`re0auth_[a-z0-9_]+`)

// declaredMetricNames returns every metric name this package can emit, by
// recording one of each and scraping the result. It is deliberately generated
// from the live registry rather than from a hand-maintained list: a list is one
// more thing that can drift from the code, which is the whole problem.
func declaredMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	m := New()

	// A request through the middleware materialises the golden signals; a gauge
	// with no series (in-flight) exports nothing until it is used.
	handler := m.Middleware(
		func(*http.Request) string { return "business" },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
	)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil))

	// And one of every domain signal, so its vector has a child to export.
	m.ObserveLogin("github", LoginSuccess)
	m.ObserveTokenIssued("authorization_code")
	m.ObserveTokenError("refresh_token", "invalid_grant")
	m.ObserveDeviceDecision(DeviceApproved)
	m.ObserveRevocation(RevocationGrant)
	m.ObserveTokensRevoked(RevocationKillSwitch, 1)
	m.ObserveAdminAction(AdminKillSwitch)
	m.ObserveAuditVerify(VerifyOK)
	m.ObserveUpstreamFetch("phigros", "next-phi", UpstreamOK)
	m.ObserveUpstreamRefresh(RefreshRejected)
	m.ObserveVaultOperation("use", "ok", time.Millisecond)

	names := make(map[string]bool)
	for _, line := range strings.Split(scrape(t, m), "\n") {
		if !strings.HasPrefix(line, "re0auth_") {
			continue
		}
		name, _, _ := strings.Cut(line, "{")
		name, _, _ = strings.Cut(name, " ")
		names[name] = true
	}
	if len(names) < 12 {
		t.Fatalf("only %d metric names were materialised; the list is too small to be a real set:\n%v", len(names), names)
	}
	return names
}

// TestAlertRulesReferenceDeclaredMetrics also checks the rules' structure, so a
// rule that is syntactically fine but would never notify anyone (no severity, no
// summary) fails here.
func TestAlertRulesReferenceDeclaredMetrics(t *testing.T) {
	declared := declaredMetricNames(t)
	raw, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read %s: %v", rulesPath, err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Expr        string            `yaml:"expr"`
				For         string            `yaml:"for"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s does not parse: %v", rulesPath, err)
	}
	if len(doc.Groups) == 0 || len(doc.Groups[0].Rules) == 0 {
		t.Fatal("the rules file declares no rules")
	}

	seen := make(map[string]bool)
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				t.Errorf("group %q has a rule with no alert name", g.Name)
				continue
			}
			if seen[r.Alert] {
				t.Errorf("alert %q is declared twice", r.Alert)
			}
			seen[r.Alert] = true
			if r.Expr == "" {
				t.Errorf("alert %q has no expr", r.Alert)
			}
			severity := r.Labels["severity"]
			switch severity {
			case "critical", "warning":
				// A fault alert fires on a sustained condition, so it needs a
				// window; one without `for` pages on a single scrape.
				if r.For == "" {
					t.Errorf("alert %q (%s) has no for clause", r.Alert, severity)
				}
			case "info":
				// A notification is a fact, not a threshold; `for` is optional.
				if r.For == "" && !strings.Contains(r.Expr, "increase(") {
					t.Errorf("alert %q is info but neither bounded by `for` nor an increase() over a window", r.Alert)
				}
			default:
				t.Errorf("alert %q has severity %q, want critical|warning|info", r.Alert, severity)
			}
			if r.Annotations["summary"] == "" || r.Annotations["runbook_url"] == "" {
				t.Errorf("alert %q needs a summary and a runbook_url", r.Alert)
			}
			for _, name := range metricToken.FindAllString(r.Expr, -1) {
				if name == "re0auth_" { // the prose form "re0auth_*" in a comment
					continue
				}
				if !declared[name] {
					t.Errorf("alert %q references %q, which this package does not declare", r.Alert, name)
				}
			}
		}
	}
	if len(seen) < 8 {
		t.Errorf("only %d alerts defined; expected the full SLO set from docs/slo.md", len(seen))
	}
}

// TestDashboardReferencesDeclaredMetrics catches a renamed metric or a typo in a
// panel expression, which Grafana renders as an empty graph rather than an error.
func TestDashboardReferencesDeclaredMetrics(t *testing.T) {
	declared := declaredMetricNames(t)
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read %s: %v", dashboardPath, err)
	}
	var doc struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", dashboardPath, err)
	}
	if len(doc.Panels) == 0 {
		t.Fatal("the dashboard has no panels")
	}

	// Every metric named anywhere in the file must be declared, not only those in
	// target expressions — a typo in a description is a smaller sin, but the same
	// scan is what keeps this from having to know the schema.
	var names []string
	for _, name := range metricToken.FindAllString(string(raw), -1) {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "re0auth_" {
			continue
		}
		if !declared[name] {
			t.Errorf("the dashboard references %q, which this package does not declare", name)
		}
	}
}
