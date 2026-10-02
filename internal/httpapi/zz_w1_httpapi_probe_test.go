package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// S04-7: a consent-seam store fault is a 500 + audit; an expired request is 400.
// ---------------------------------------------------------------------------

// w1InteractionStub is an authorization.Interaction whose every call a test can
// script. The OP never fails its own seam, so this is the only way the HTTP
// layer's classification branches are reachable.
type w1InteractionStub struct {
	view        authorization.View
	describeErr error
	approveErr  error
	denyErr     error
}

func (w1InteractionStub) ValidID(string) bool { return true }

func (s w1InteractionStub) DescribeAuthorization(context.Context, string) (authorization.View, error) {
	if s.describeErr != nil {
		return authorization.View{}, s.describeErr
	}
	return s.view, nil
}

func (s w1InteractionStub) ApproveAuthorization(context.Context, string, string, []oauth.Scope, []oauth.Scope) (string, error) {
	if s.approveErr != nil {
		return "", s.approveErr
	}
	return "/oauth/authorize/callback?id=stub", nil
}

func (s w1InteractionStub) DenyAuthorization(context.Context, string) (string, error) {
	if s.denyErr != nil {
		return "", s.denyErr
	}
	return "https://app.example/cb?error=access_denied", nil
}

// TestW1S04_7ConsentSeamFaultIs500AndAudited pins the fault half of S04-7. Before
// the fix every non-oauth error from DescribeAuthorization was answered 404
// "authorization request expired": a store outage looked like a dead link, and
// nothing was recorded.
func TestW1S04_7ConsentSeamFaultIs500AndAudited(t *testing.T) {
	logger := audit.NewMemoryLogger()
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{
		Authorization: w1InteractionStub{describeErr: errors.New("store: connection refused")},
		AuditLog:      logger,
	})
	browser := newBrowser(t)
	signIn(t, browser, base)
	handle := authorize(t, browser, base, "verifier-verifier-verifier-verifier-verifier", "account.id", "st")

	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("consent fault = %d (%v), want 500: a store outage must not look like an expired link",
			resp.StatusCode, body)
	}
	if body["code"] != "internal_error" {
		t.Fatalf("code = %v, want internal_error", body["code"])
	}
	if detail, _ := body["detail"].(string); strings.Contains(detail, "connection refused") {
		t.Fatalf("the store's error text leaked to the browser: %q", detail)
	}

	// The fault is recorded, not just logged.
	found := false
	for _, e := range logger.Events() {
		if e.Action == "auth.authorization.fault" && e.Outcome == audit.OutcomeError {
			found = true
			if e.Detail["operation"] != "describe" {
				t.Errorf("audit detail operation = %q, want describe", e.Detail["operation"])
			}
		}
	}
	if !found {
		t.Fatalf("no auth.authorization.fault audit row was written: %+v", logger.Events())
	}
}

// TestW1S04_7ExpiredRequestIs400 pins the other half: a request the engine no
// longer holds is the caller's situation, answered invalid_request (400) rather
// than disguised as anything else.
func TestW1S04_7ExpiredRequestIs400(t *testing.T) {
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{
		Authorization: w1InteractionStub{
			describeErr: fmt.Errorf("store: %w", authorization.ErrRequestExpired),
		},
	})
	browser := newBrowser(t)
	signIn(t, browser, base)
	handle := authorize(t, browser, base, "verifier-verifier-verifier-verifier-verifier", "account.id", "st")

	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "invalid_request" {
		t.Fatalf("expired request = %d (%v), want 400 invalid_request", resp.StatusCode, body)
	}
}

// TestW1S04_7DecisionSeamFaultIs500: the decision path's default branch is the
// same defect. It must be a 500 too, not a 404.
func TestW1S04_7DecisionSeamFaultIs500(t *testing.T) {
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{
		Authorization: w1InteractionStub{
			view: authorization.View{
				ID: "stub", ClientID: "cli", ClientName: "Phi CLI",
				Scopes: []oauth.Scope{oauth.ScopeAccountID},
			},
			approveErr: errors.New("store: write failed"),
		},
	})
	browser := newBrowser(t)
	signIn(t, browser, base)
	handle := authorize(t, browser, base, "verifier-verifier-verifier-verifier-verifier", "account.id", "st")

	view := decodeResp(t, getURL(t, browser, base+"/v1/authorization_requests/"+handle))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("consent view carried no csrf token: %v", view)
	}

	resp := postDecision(t, browser, base, handle, csrf, `{"decision":"approve"}`)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusInternalServerError || body["code"] != "internal_error" {
		t.Fatalf("decision fault = %d (%v), want 500 internal_error", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// Z10-5: a partially applied Kill Switch keeps its 500 but reports the counts.
// ---------------------------------------------------------------------------

// w1KillSwitchStub is an operator service whose KillSwitch a test scripts. All
// other methods answer zero values; the handler under test calls only KillSwitch.
type w1KillSwitchStub struct {
	report admin.Report
	err    error
}

func (w1KillSwitchStub) ListClients(context.Context, int, string) ([]oauth.Client, string, error) {
	return nil, "", nil
}
func (w1KillSwitchStub) Register(context.Context, string, admin.RegisterRequest) (admin.Registration, error) {
	return admin.Registration{}, nil
}
func (w1KillSwitchStub) RotateClientSecret(context.Context, string, string) (string, error) {
	return "", nil
}
func (w1KillSwitchStub) SuspendClient(context.Context, string, string) error  { return nil }
func (w1KillSwitchStub) ActivateClient(context.Context, string, string) error { return nil }
func (w1KillSwitchStub) DeleteClient(context.Context, string, string) error   { return nil }
func (s w1KillSwitchStub) KillSwitch(context.Context, string, admin.Target) (admin.Report, error) {
	return s.report, s.err
}

// TestW1Z10_5KillSwitchPartialFailureKeeps500WithCounts pins Z10-5. A sweep that
// cut some dimension and then failed keeps its 500 — never a misleading 200 — but
// the completed counts ride in the problem body, because those effects are
// irreversible and a retry is not promised.
func TestW1Z10_5KillSwitchPartialFailureKeeps500WithCounts(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	env.srv.adminSvc = w1KillSwitchStub{
		err: &admin.PartialError{
			Report: admin.Report{TokensRevoked: 3, SessionsRevoked: 2, ClientsSuspended: 1},
			Step:   "bindings",
			Err:    errors.New("bindings store down"),
		},
	}

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/kill_switch", csrf,
		map[string]any{"target": "all"})
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("partial kill switch = %d (%v), want 500", resp.StatusCode, body)
	}
	if body["code"] != "internal_error" {
		t.Fatalf("code = %v, want internal_error", body["code"])
	}
	if got, _ := body["tokens_revoked"].(float64); got != 3 {
		t.Errorf("tokens_revoked = %v, want 3 (the count already applied)", body["tokens_revoked"])
	}
	if got, _ := body["sessions_revoked"].(float64); got != 2 {
		t.Errorf("sessions_revoked = %v, want 2", body["sessions_revoked"])
	}
	if got, _ := body["clients_suspended"].(float64); got != 1 {
		t.Errorf("clients_suspended = %v, want 1", body["clients_suspended"])
	}
	if s, _ := body["bindings_error"].(string); s == "" {
		t.Errorf("bindings_error missing although the binding sweep was the failing step: %v", body)
	}
}

// ---------------------------------------------------------------------------
// Z07-9: account deletion needs a recent authentication.
// ---------------------------------------------------------------------------

// TestW1Z07_9DeleteRequiresRecentAuthentication: the window is shrunk to a
// nanosecond and the request is sent after it, so the branch is deterministic. The
// account must still exist afterwards — the refusal happens before erasure.
func TestW1Z07_9DeleteRequiresRecentAuthentication(t *testing.T) {
	env := newDeleteEnvWithReauth(t, nil, time.Nanosecond)
	browser := newBrowser(t)
	csrf := csrfFor(t, browser, env.base)

	time.Sleep(5 * time.Millisecond)

	resp, body := deleteReq(t, browser, env.base, csrf, deleteAccountAcknowledgement)
	if resp.StatusCode != http.StatusForbidden || body["code"] != "reauth_required" {
		t.Fatalf("stale delete = %d (%v), want 403 reauth_required", resp.StatusCode, body)
	}
	if _, err := env.accounts.FindByIdentity(context.Background(), "github", "42"); err != nil {
		t.Errorf("a refused deletion still removed the account: %v", err)
	}
}

// TestW1Z07_9DeleteInsideTheWindowSucceeds is the positive control: a fresh
// session inside the window deletes normally, so the guard above is not refusing
// everything.
func TestW1Z07_9DeleteInsideTheWindowSucceeds(t *testing.T) {
	env := newDeleteEnvWithReauth(t, nil, time.Hour)
	browser := newBrowser(t)
	csrf := csrfFor(t, browser, env.base)

	resp, body := deleteReq(t, browser, env.base, csrf, deleteAccountAcknowledgement)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh delete = %d (%v), want 200", resp.StatusCode, body)
	}
	if _, err := env.accounts.FindByIdentity(context.Background(), "github", "42"); err == nil {
		t.Error("the account survived a successful deletion")
	}
}

// ---------------------------------------------------------------------------
// Z20-2: raw passthrough needs the explicit <game>.raw.read scope.
// ---------------------------------------------------------------------------

// TestW1Z20_2RawNeedsTheExplicitRawScope is the finding's probe. A token that
// holds a resource scope of the source must NOT reach the raw passthrough; only a
// token holding <game>.raw.read may.
func TestW1Z20_2RawNeedsTheExplicitRawScope(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.native+json")
		_, _ = w.Write([]byte(`{"native":true}`))
	}))
	defer up.Close()

	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", Issuer: up.URL, TokenClass: "revocable", RawBase: up.URL,
		Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	b := federation.Binding{User: "usr_test", Game: "phigros", Source: "fake", Version: 1}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	v := newTestVault(t)
	seedBindingSecret(t, v, b, "up-token")
	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v, Doer: up.Client(), BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	rawReg := rawRegistry(t, "phigros")
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{fedRedirect},
		[]oauth.Scope{oauth.ScopePhigrosProfile, rawScopeFor("phigros")})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackendRegistry(t, "https://re0auth.test", clients, nil, rawReg)
	api, err := New(Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Federation:        fed,
		Scopes:            rawReg,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	rawURL := srv.URL + "/v1/games/phigros/sources/fake/raw/v1/native/scores"

	// The old rule: one of the source's resource scopes opened raw. It must not.
	atResource := mintToken(t, api.Handler(), store, "cli", "usr_test", oauth.ScopePhigrosProfile)
	resp := authedGet(t, rawURL, atResource)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("raw with only a resource scope = %d (%v), want 403", resp.StatusCode, body)
	}
	if body["code"] != "scope_not_granted" || body["required_scope"] != "phigros.raw.read" {
		t.Fatalf("problem = %v, want scope_not_granted naming phigros.raw.read", body)
	}

	// The explicit scope opens it.
	atRaw := mintToken(t, api.Handler(), store, "cli", "usr_test", rawScopeFor("phigros"))
	resp = authedGet(t, rawURL, atRaw)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw with the explicit raw scope = %d, want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// A-FE-3: the displayed scope set covers the granted set.
// ---------------------------------------------------------------------------

// TestW1AFE3ScopeViewsCoverEveryGrantedScope pins the invariant: every granted
// scope is rendered, and an undescribed one gets a system-required placeholder
// instead of being silently dropped.
func TestW1AFE3ScopeViewsCoverEveryGrantedScope(t *testing.T) {
	s := &Server{scopes: oauth.DefaultRegistry()}
	granted := []oauth.Scope{
		oauth.ScopeAccountID,
		oauth.Scope("profile"),
		oauth.Scope("openid"),
		oauth.Scope("z08.extra.read"),
		oauth.Scope("offline_access"),
	}
	views := s.scopeViews(granted)
	if len(views) != len(granted) {
		t.Fatalf("scopeViews rendered %d of %d granted scopes: the screen shows less than it grants (%v)",
			len(views), len(granted), views)
	}
	seen := map[string]bool{}
	validRisk := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	for _, v := range views {
		sc, _ := v["scope"].(string)
		seen[sc] = true
		if title, _ := v["title"].(string); title == "" {
			t.Errorf("scope %q has no title in the rendered view", sc)
		}
		if desc, _ := v["description"].(string); desc == "" {
			t.Errorf("scope %q has no description in the rendered view", sc)
		}
		risk, _ := v["risk"].(string)
		if !validRisk[risk] {
			t.Errorf("scope %q carries risk %q, which the frontend's union does not accept", sc, risk)
		}
	}
	for _, g := range granted {
		if !seen[g.String()] {
			t.Errorf("granted scope %q is missing from the displayed view %v", g, seen)
		}
	}
}

// ---------------------------------------------------------------------------
// S15-5: a declared client_addr_header with an untrusted peer warns.
// ---------------------------------------------------------------------------

// TestW1S15_5UntrustedPeerWithDeclaredHeaderWarnsOnce pins S15-5: the peer is
// still used (the safe direction), but the deployment is told once that its
// declared header is being ignored and everyone behind that address now shares
// one rate-limit bucket.
func TestW1S15_5UntrustedPeerWithDeclaredHeaderWarnsOnce(t *testing.T) {
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := &Server{clientAddrHeader: ClientAddrXForwardedFor}
	req := addrRequest("203.0.113.7:5555", "198.51.100.9")
	if got := s.clientKey(req); got != "203.0.113.7" {
		t.Fatalf("key = %q, want the peer (the safe direction)", got)
	}
	got := buf.String()
	if !strings.Contains(got, "shares one rate-limit bucket") {
		t.Fatalf("no untrusted-proxy warning was emitted:\n%s", got)
	}

	// Once, not once per request.
	buf.Reset()
	s.clientKey(req)
	if buf.Len() != 0 {
		t.Fatalf("the warning fired again on the next request:\n%s", buf.String())
	}
}

// TestW1S15_5TrustedPeerAndNoDeclarationDoNotWarn is the control: the warning is
// about a specific misconfiguration, not about the feature existing.
func TestW1S15_5TrustedPeerAndNoDeclarationDoNotWarn(t *testing.T) {
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	trusted := &Server{
		clientAddrHeader: ClientAddrXForwardedFor,
		trustedProxies:   prefixes(t, "10.0.0.0/8"),
	}
	trusted.clientKey(addrRequest("10.1.2.3:5555", "198.51.100.9"))
	if strings.Contains(buf.String(), "shares one rate-limit bucket") {
		t.Errorf("a correctly trusted proxy warned:\n%s", buf.String())
	}

	buf.Reset()
	undeclared := &Server{}
	undeclared.clientKey(addrRequest("203.0.113.7:5555", "198.51.100.9"))
	if buf.Len() != 0 {
		t.Errorf("a server that declares no header warned:\n%s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// Z20V-1: the HTTP layer hands the session account to the device decision.
// ---------------------------------------------------------------------------

// w1DeviceStub captures what the business plane passes to the device seam.
type w1DeviceStub struct {
	auth        oauth.DeviceAuthorization
	lastSubject string
	lastApprove bool
	lastCode    string
	err         error
}

func (d *w1DeviceStub) DescribeDeviceAuthorization(_ context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	a := d.auth
	if a.UserCode == "" {
		a.UserCode = userCode
	}
	return a, nil
}

func (d *w1DeviceStub) DecideDeviceAuthorization(_ context.Context, userCode, subject string, approve bool, _, _ []oauth.Scope) error {
	d.lastCode, d.lastSubject, d.lastApprove = userCode, subject, approve
	return d.err
}

// TestW1Z20V1DeviceDenyCarriesTheSessionAccount: the denial branch must hand the
// store the account that made the decision, not only the user code, so the
// audit row can answer "who refused".
func TestW1Z20V1DeviceDenyCarriesTheSessionAccount(t *testing.T) {
	dev := &w1DeviceStub{auth: oauth.DeviceAuthorization{
		Client: oauth.Client{ID: "cli", Name: "Phi CLI"},
		Scopes: oauth.DefaultRegistry().Descriptors()[:1],
	}}
	base, accounts, _ := newFlowEnvWithOptions(t, flowEnvOptions{DeviceStore: dev})
	browser := newBrowser(t)
	signIn(t, browser, base)

	uid, err := accounts.FindByIdentity(context.Background(), "github", "42")
	if err != nil {
		t.Fatal(err)
	}

	const code = "WXYZ-1234"
	view := decodeResp(t, getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(code)))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("device view carried no csrf token: %v", view)
	}

	body, _ := json.Marshal(map[string]any{"user_code": code, "decision": "deny"})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp := doReq(t, browser, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := json.Marshal(decodeResp(t, resp))
		t.Fatalf("deny = %d %s, want 200", resp.StatusCode, raw)
	}
	if dev.lastApprove {
		t.Fatal("the deny branch was read as an approval")
	}
	if dev.lastSubject != string(uid) {
		t.Fatalf("DecideDeviceAuthorization subject = %q, want the session account %q", dev.lastSubject, uid)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// postDecision sends a consent decision with the given CSRF token.
func postDecision(t *testing.T, c *http.Client, base, handle, csrf, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		base+"/v1/authorization_requests/"+handle+"/decision", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	return doReq(t, c, req)
}
