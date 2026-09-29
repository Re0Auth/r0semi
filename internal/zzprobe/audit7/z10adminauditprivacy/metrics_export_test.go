//go:build audit7

// Zone-10 guards: what the metrics exposition and the account export can be made
// to carry.
package z10adminauditprivacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/observability"
)

// TestZ10ExportedMetricsHaveBoundedLabelsAndNoAccountIdentity.
//
// Labels that come from the request are the classic way to turn a metrics
// endpoint into an unbounded map, and an account id in a label would be personal
// data leaving the service on every scrape. Both are asserted through the real
// scrape handler after real traffic, with the traffic's own request present in the
// exposition as the positive control.
func TestZ10ExportedMetricsHaveBoundedLabelsAndNoAccountIdentity(t *testing.T) {
	metrics := observability.New()
	env := newProbeEnv(t, probeOptions{Metrics: metrics, Sessions: &probeSessions{n: 1}})

	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want %q", got, env.adminUser)
	}
	// A mutating admin action, so admin_actions_total is populated.
	resp := b.do(http.MethodPost, "/v1/admin/kill_switch", `{"target":"all"}`, jsonHeaders(b.csrf()))
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("kill_switch = %d (%s), want 200", resp.StatusCode, body)
	}
	// A method a caller invents, which must not become a label value.
	weird := env.newBrowser()
	resp = weird.do("X-EVIL-"+strings.Repeat("A", 40), "/v1/me", "", nil)
	_ = bodyOf(t, resp)
	// And the account export, whose path carries no value but whose session does.
	resp = b.get("/v1/account/export")
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d (%s), want 200", resp.StatusCode, body)
	}

	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	expo := rec.Body.String()

	if !strings.Contains(expo, "re0auth_http_requests_total") {
		t.Fatalf("the scrape carries no request counter at all; the probe would pass vacuously:\n%s", expo)
	}
	if !strings.Contains(expo, `method="other"`) {
		t.Errorf("a request whose method is a token no client would send is not collapsed into the bounded " +
			"\"other\" label; the metric set can be grown by the caller")
	}
	for _, forbidden := range []string{"X-EVIL", "usr_", string(env.adminUser)} {
		if forbidden == "" {
			continue
		}
		if strings.Contains(expo, forbidden) {
			t.Errorf("the metrics exposition carries %q; account identities and request-chosen values must "+
				"not reach a label", forbidden)
		}
	}
}

// TestZ10ExportIsAJSONDocumentWithNoSpreadsheetSink.
//
// The export is the one place a whole account's data leaves in one response, so
// what it is (JSON, not a CSV a spreadsheet would interpret) and that it carries
// no credential and exactly one account id are worth pinning. There is no CSV or
// text sink anywhere on this path; this guards against one being added.
func TestZ10ExportIsAJSONDocumentWithNoSpreadsheetSink(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})

	other := env.newBrowser()
	otherID := other.signIn("someone-else")

	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want %q", got, env.adminUser)
	}

	resp := b.get("/v1/account/export")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/account/export = %d (%s), want 200", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || strings.Contains(ct, "csv") {
		t.Errorf("export Content-Type = %q, want application/json and never a CSV a spreadsheet would interpret", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("export Content-Disposition = %q, want an attachment", cd)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("export Cache-Control = %q, want no-store", cc)
	}

	var doc struct {
		Profile struct {
			UserID string `json:"user_id"`
		} `json:"profile"`
		Notice struct {
			CredentialsExcluded bool `json:"credentials_excluded"`
		} `json:"notice"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the export is not a JSON document: %v (%s)", err, body)
	}
	if doc.Profile.UserID != string(env.adminUser) {
		t.Errorf("export profile.user_id = %q, want %q", doc.Profile.UserID, env.adminUser)
	}
	if !doc.Notice.CredentialsExcluded {
		t.Errorf("the export does not declare that credentials were excluded")
	}
	if strings.Contains(body, otherID) {
		t.Errorf("the export names another account (%q)", otherID)
	}
	if n := strings.Count(body, "usr_"); n != 1 {
		t.Errorf("the export carries %d account ids, want exactly 1 (the caller's own)", n)
	}
}
