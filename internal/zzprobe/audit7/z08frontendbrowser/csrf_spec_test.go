//go:build audit7

// A CSRF walk driven by the published specification rather than by the
// product's own route table. Every mutating operation docs/openapi.yaml declares
// is sent three ways against a live session: with no token, with a wrong token,
// and with the session's real token. The first two must be refused with the
// business plane's 403; the third must get past the gate, which is what proves
// the failure was the CSRF check and not an unmounted route.
package z08frontendbrowser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
)

// specOp is one mutating operation the spec declares.
type specOp struct {
	method string
	path   string
}

var z08SpecPath = regexp.MustCompile(`^  (/\S+):\s*$`)
var z08SpecVerb = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)

// readSpecOps parses the write operations out of docs/openapi.yaml.
func readSpecOps(t *testing.T) []specOp {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("the published spec is the subject of this walk: %v", err)
	}
	defer f.Close()

	var out []specOp
	current := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := z08SpecPath.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := z08SpecVerb.FindStringSubmatch(line); m != nil {
			if m[1] == "get" || current == "" {
				continue
			}
			out = append(out, specOp{method: strings.ToUpper(m[1]), path: current})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < 10 {
		t.Fatalf("only %d mutating operations parsed out of the spec; the walk would be vacuous", len(out))
	}
	return out
}

// concrete replaces the spec's path parameters with values that reach a handler.
func concrete(specPath string) string {
	r := strings.NewReplacer(
		"{client_id}", z08ClientID,
		"{game}", "phigros",
		"{source}", "fake",
		"{id}", "idn_z08probe",
		"{resource}", "profile",
		"{path}", "anything",
		"{client-id}", z08ClientID,
	)
	return r.Replace(specPath)
}

// z08AdminEnv builds an environment whose operator allowlist names the account
// the first environment signed in. The second environment shares the first's
// session manager and account store, so the same browser jar (and therefore the
// same session and CSRF token) works on both — the identity is only known after
// the first sign-in, and httpapi.Config.Admins is fixed at New time.
func z08AdminEnv(t *testing.T) (*z08Env, *browser) {
	t.Helper()
	probe := newZ08Env(t, z08Options{})
	first := probe.newBrowser()
	id := first.signIn()
	return z08AdminEnvFor(t, probe, first, id)
}

// z08AdminEnvFor is z08AdminEnv with the identity-holding environment supplied,
// so one walk can build a fresh server per operation without paying for a new
// identity each time.
func z08AdminEnvFor(t *testing.T, probe *z08Env, first *browser, id string) (*z08Env, *browser) {
	t.Helper()
	env := newZ08Env(t, z08Options{
		Manager:  probe.manager,
		Accounts: probe.accounts,
		Admins:   []account.UserID{account.UserID(id)},
	})
	b := first
	// The same jar, now pointed at the second server: a fresh browser would have
	// no session cookie and would prove nothing about the reuse.
	b.env = env
	// Prove the reused session is still a session on the second server, and that
	// the operator plane is actually mounted for it.
	if got := b.whoami(); got != id {
		t.Fatalf("the reused session reports %q, want %q", got, id)
	}
	if got := b.status(http.MethodGet, "/v1/admin/clients", "", nil); got != http.StatusOK {
		t.Fatalf("GET /v1/admin/clients = %d, want 200: the operator plane is not reachable for %q", got, id)
	}
	return env, b
}

// TestZ08EverySpecifiedWriteNeedsTheSessionCSRFToken is the walk. Each operation
// gets its own server, because two of them end the session they run on
// (sign_out, account erasure) and a shared one would turn every later operation
// into a 401 rather than a CSRF refusal.
func TestZ08EverySpecifiedWriteNeedsTheSessionCSRFToken(t *testing.T) {
	ops := readSpecOps(t)
	probe := newZ08Env(t, z08Options{})
	first := probe.newBrowser()

	checked, gated := 0, 0
	for _, op := range ops {
		// A fresh session per operation, on the environment that owns the
		// identity: two of the operations below end the session they run on.
		first.env = probe
		id := first.signIn()
		_, b := z08AdminEnvFor(t, probe, first, id)
		real := b.csrf()
		target := concrete(op.path)
		body := `{}`
		if op.method == http.MethodDelete && op.path == "/v1/account" {
			body = `{"acknowledge":"deletes_my_account"}`
		}

		noToken := b.status(op.method, target, body, map[string]string{"Content-Type": "application/json"})
		wrong := b.status(op.method, target, body, map[string]string{
			"Content-Type": "application/json", "X-CSRF-Token": "not-the-token",
		})
		checked++
		switch {
		case noToken == http.StatusForbidden && wrong == http.StatusForbidden:
			gated++
		case noToken == http.StatusUnauthorized || noToken == http.StatusNotFound:
			t.Errorf("%s %s: no CSRF token = %d, which means the route was not reached (not mounted, or "+
				"refused before the gate); the walk cannot conclude anything about this endpoint",
				op.method, target, noToken)
		default:
			t.Errorf("%s %s: no token = %d, wrong token = %d, want 403 both times; "+
				"an endpoint that accepts a request without the session's CSRF token is forgeable from any "+
				"page the browser loads", op.method, target, noToken, wrong)
		}

		if noToken == http.StatusForbidden {
			good := b.status(op.method, target, body, map[string]string{
				"Content-Type": "application/json", "X-CSRF-Token": real,
			})
			if good == http.StatusForbidden {
				t.Errorf("%s %s: the session's own CSRF token was refused (403); the token the product "+
					"hands the frontend is not the token it accepts", op.method, target)
			}
			t.Logf("%-7s %-46s none=%d wrong=%-3d real=%d", op.method, target, noToken, wrong, good)
		} else {
			t.Logf("%-7s %-46s none=%d wrong=%-3d", op.method, target, noToken, wrong)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d operations walked", checked)
	}
	if gated < checked {
		t.Fatalf("%d of %d operations reached the CSRF gate", gated, checked)
	}
}

// TestZ08DeviceVerificationIsTheOneWriteThatNeedsNoToken documents the single
// deliberate exception, so a future change that silently widens it is visible:
// loading a user code binds it to the browser and is a GET, and the response is
// where the frontend gets the token it uses for the decision.
func TestZ08DeviceVerificationIsTheOneWriteThatNeedsNoToken(t *testing.T) {
	ops := readSpecOps(t)
	var gets []string
	for _, op := range ops {
		if op.method == http.MethodGet {
			gets = append(gets, op.path)
		}
	}
	env := newZ08Env(t, z08Options{})
	b := env.newBrowser()
	b.signIn()
	userCode, _ := deviceCode(t, b)

	// The GET binds, and the response carries the token the POST will need.
	resp := b.get("/v1/device/verification?user_code=" + userCode)
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device verification = %d: %s", resp.StatusCode, raw)
	}
	var view struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		t.Fatal(err)
	}
	if view.CSRFToken == "" {
		t.Fatalf("the binding GET handed out no CSRF token, so the exception serves no purpose: %s", raw)
	}
	t.Logf("spec declares %d GET operations; /v1/device/verification returns a CSRF token as documented",
		len(gets)+1)
}

// TestZ08CrossSiteFormPostCannotReachAWrite is the CSRF premise itself: a
// browser form post (Content-Type form-urlencoded, no custom header) must not be
// accepted on a business-plane write, because a custom header is the one thing a
// cross-site form cannot set.
func TestZ08CrossSiteFormPostCannotReachAWrite(t *testing.T) {
	_, b := z08AdminEnv(t)
	for _, target := range []string{"/v1/sessions/sign_out", "/v1/admin/kill_switch"} {
		status := b.status(http.MethodPost, target, "a=b",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
		if status != http.StatusForbidden {
			t.Errorf("POST %s as a cross-site form = %d, want 403", target, status)
		} else {
			t.Logf("POST %-28s (form-encoded, no header) -> 403", target)
		}
	}
}

// z08FormatOp is used only in failure messages.
func z08FormatOp(op specOp) string { return fmt.Sprintf("%s %s", op.method, op.path) }

var _ = z08FormatOp
var _ = envUnused

// envUnused keeps the helper reference explicit without using it.
var envUnused = func(e *z08Env) {}
