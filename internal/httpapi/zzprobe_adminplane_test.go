//go:build audit5

package httpapi

// zzprobe_adminplane_test.go - adversarial probes for the operator plane, the
// audit log, account erasure and account export (audit round 4, area
// "admin plane / audit / privacy").
//
// These are probes, not guards: several are written to FAIL where a documented
// property does not hold. Read the failure messages, not the exit code.
// Helper prefix zzAdm keeps them clear of the other probe files in this package.
//
// All comments are ASCII on purpose: an earlier edit through PowerShell mangled
// non-ASCII bytes in a sibling file.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// zzAdmProblemDetail decodes the human-readable `detail` of a problem+json body
// and closes it. It is the discriminator this file needs: the operator gate
// answers not_found / "unknown resource", while a handler that was reached
// answers its own detail.
func zzAdmProblemDetail(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var p problem
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	return p.Detail
}

// zzAdmAdminPatterns returns every declared route under /v1/admin, grouped by
// pattern with its declared method set. Deriving it from specRoutes is the
// point: a route added later is covered the day it is declared.
func zzAdmAdminPatterns(t *testing.T, srv *Server) ([]string, map[string]map[string]bool) {
	t.Helper()
	allowed := make(map[string]map[string]bool)
	var patterns []string
	for _, rt := range srv.specRoutes() {
		if !strings.HasPrefix(rt.Pattern, "/v1/admin/") {
			continue
		}
		if allowed[rt.Pattern] == nil {
			allowed[rt.Pattern] = make(map[string]bool)
			patterns = append(patterns, rt.Pattern)
		}
		allowed[rt.Pattern][rt.Method] = true
	}
	if len(patterns) < 6 {
		t.Fatalf("only %d admin patterns found; the walk is not reaching the plane", len(patterns))
	}
	return patterns, allowed
}

func zzAdmSend(t *testing.T, c *http.Client, base, method, path, csrf string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return doReq(t, c, req)
}

// ---------------------------------------------------------------------------
// P1. The wrong-verb answer never passes through the operator gate.
//
// docs/admin.md section 0 and docs/openapi.yaml ("Reading it is an operator
// act") both promise that an account which is not on the allowlist sees the
// operator plane exactly as it sees a path that does not exist: "not advertised
// to those who cannot read it". requireAdmin does answer that 404, but the
// business plane's method dispatch runs *before* any handler (server.go,
// businessPlane), so an undeclared verb is answered 405 + Allow by the dispatch
// itself, with no gate and no session. The dispatch is the change the working
// tree's CHANGELOG records ("every endpoint declares its own verbs").
// ---------------------------------------------------------------------------
func TestZZAdmWrongVerbAdvertisesTheOperatorPlaneToANonAdmin(t *testing.T) {
	env := newAdminEnv(t, false) // signed in, not on the allowlist
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	patterns, allowed := zzAdmAdminPatterns(t, env.srv)

	// Control, so a clean result cannot mean "the probe never got here": every
	// declared verb must reach the gate and be answered with the gate's 404.
	reached := 0
	for _, pattern := range patterns {
		for method := range allowed[pattern] {
			resp := zzAdmSend(t, browser, env.base, method, fillPathParams(pattern), "")
			detail := zzAdmProblemDetail(t, resp)
			if resp.StatusCode != http.StatusNotFound || detail != "unknown resource" {
				t.Fatalf("control: %s %s = %d %q, want the operator gate's 404",
					method, pattern, resp.StatusCode, detail)
			}
			reached++
		}
	}
	if reached == 0 {
		t.Fatal("the control walk asserted nothing")
	}

	leaked := 0
	for _, pattern := range patterns {
		for _, verb := range []string{
			http.MethodPut, http.MethodDelete, http.MethodPatch,
			http.MethodOptions, "TRACE",
		} {
			if allowed[pattern][verb] {
				continue
			}
			resp := zzAdmSend(t, browser, env.base, verb, fillPathParams(pattern), "")
			allow := resp.Header.Get("Allow")
			detail := zzAdmProblemDetail(t, resp)
			if resp.StatusCode == http.StatusMethodNotAllowed {
				leaked++
				t.Errorf("%s %s = 405 Allow=%q for a signed-in NON-admin: the operator plane "+
					"names itself and its method set to an account the design says must not see it",
					verb, pattern, allow)
				continue
			}
			if resp.StatusCode != http.StatusNotFound || detail != "unknown resource" {
				t.Errorf("%s %s = %d %q, want the gate's 404", verb, pattern, resp.StatusCode, detail)
			}
		}
	}
	t.Logf("wrong-verb leak on %d undeclared-verb probes", leaked)
}

// ---------------------------------------------------------------------------
// P2. The guard: every admin route, every declared verb, three populations
// (anonymous / signed-in non-admin / operator). A route that forgets the gate -
// the highest-value bug in this shape - fails the operator assertion.
// ---------------------------------------------------------------------------
func TestZZAdmEveryAdminRouteIsGatedByTheAllowlist(t *testing.T) {
	anon := newAdminEnv(t, true)
	patterns, allowed := zzAdmAdminPatterns(t, anon.srv)
	for _, pattern := range patterns {
		for method := range allowed[pattern] {
			resp := zzAdmSend(t, newBrowser(t), anon.base, method, fillPathParams(pattern), "")
			zzAdmProblemDetail(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("anonymous %s %s = %d, want 401", method, pattern, resp.StatusCode)
			}
		}
	}

	denied := newAdminEnv(t, false)
	browserDenied := newBrowser(t)
	signIn(t, browserDenied, denied.base)
	for _, pattern := range patterns {
		for method := range allowed[pattern] {
			resp := zzAdmSend(t, browserDenied, denied.base, method, fillPathParams(pattern), "")
			detail := zzAdmProblemDetail(t, resp)
			if resp.StatusCode != http.StatusNotFound || detail != "unknown resource" {
				t.Errorf("non-admin %s %s = %d %q, want 404 unknown resource",
					method, pattern, resp.StatusCode, detail)
			}
		}
	}

	// Anti-vacuous control: the same requests from an allowlisted operator must
	// not be answered by the gate. Every handler's own answer is acceptable;
	// "unknown resource" is not, and neither is a refusal.
	op := newAdminEnv(t, true)
	browserOp := newBrowser(t)
	signIn(t, browserOp, op.base)
	csrf := sessionCSRF(t, op.base, browserOp)
	reached := 0
	for _, pattern := range patterns {
		for method := range allowed[pattern] {
			resp := zzAdmSend(t, browserOp, op.base, method, fillPathParams(pattern), csrf)
			detail := zzAdmProblemDetail(t, resp)
			if resp.StatusCode == http.StatusNotFound && detail == "unknown resource" {
				t.Errorf("operator %s %s hit the gate: the handler's own check is missing",
					method, pattern)
				continue
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				t.Errorf("operator %s %s = %d: the allowlisted operator was refused",
					method, pattern, resp.StatusCode)
				continue
			}
			reached++
		}
	}
	if reached < len(patterns) {
		t.Fatalf("only %d/%d admin requests reached a handler", reached, len(patterns))
	}
}

// ---------------------------------------------------------------------------
// P3. Audit coverage of the security-relevant state changes in and around the
// operator plane. Each block is a question an incident responder has to be able
// to answer from the log.
// ---------------------------------------------------------------------------
func TestZZAdmSecurityRelevantActionsLeaveAnAuditEvent(t *testing.T) {
	env := newAdminEnv(t, true)

	// One logger for every writer this probe can reach: the operator service and
	// the HTTP layer's own audit log. The composition root passes the same object
	// to both; here they are the same object too.
	logger := audit.NewMemoryLogger()
	adminSvc, err := admin.New(admin.Config{
		Clients: env.clients, Tokens: env.store,
		Bindings: &revokingBindings{total: 2}, Audit: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.srv.adminSvc = adminSvc
	env.srv.auditLog = logger

	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	// (a) Operator mutation: the documented case, and the non-vacuous control for
	// everything below it.
	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", csrf, map[string]any{
		"name": "Audited", "type": "public",
		"redirect_uris": []string{"https://audited.example/cb"}, "scopes": []string{"openid"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d; the probe is not reaching the operator plane", resp.StatusCode)
	}
	zzAdmRequireAction(t, logger, "admin.client.register", "an operator registration")

	// (b) Identity unlink: the one write the HTTP layer records itself.
	env.srv.recordUnlinkAudit(context.Background(), string(env.adminID), "idn_probe")
	zzAdmRequireAction(t, logger, "auth.identity.unlink", "an identity unlink")

	// (c) Account export: a complete copy of one account's personal data leaves
	// the service. Nothing records that it did.
	before := len(logger.Events())
	resp = getURL(t, browser, env.base+"/v1/account/export")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if grew := zzAdmActionsSince(logger, before); !zzAdmContains(grew, "account.export") {
		t.Errorf("GET /v1/account/export left no audit event (actions added: %v): a full copy of "+
			"one account's personal data was produced and the log cannot answer who read it", grew)
	}

	// (d) Reading the audit log: the widest read of personal data the service
	// offers. docs/openapi.yaml calls it "the operator's window into who did
	// what"; nothing records that the window was opened.
	before = len(logger.Events())
	resp = getURL(t, browser, env.base+"/v1/admin/audit")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit read = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if grew := zzAdmActionsSince(logger, before); !zzAdmContains(grew, "admin.audit.read") {
		t.Errorf("GET /v1/admin/audit left no audit event (actions added: %v): an operator can read "+
			"every account's history with no trace of having done so", grew)
	}
}

func zzAdmRequireAction(t *testing.T, l *audit.MemoryLogger, action, what string) {
	t.Helper()
	for _, e := range l.Events() {
		if e.Action == action {
			return
		}
	}
	t.Errorf("no %q event in the log after %s; the log holds %v", action, what, zzAdmActions(l))
}

func zzAdmActions(l *audit.MemoryLogger) []string {
	var out []string
	for _, e := range l.Events() {
		out = append(out, e.Action)
	}
	return out
}

func zzAdmActionsSince(l *audit.MemoryLogger, n int) []string {
	all := zzAdmActions(l)
	if n > len(all) {
		return nil
	}
	return all[n:]
}

func zzAdmContains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// P4. Fail direction of an audit write in the OpenID Provider's store.
//
// The project picked a direction twice, on purpose: the operator plane logs and
// proceeds (docs/admin.md section 5), erasure and vault.Use fail closed (I3,
// architecture section 4.15). The OP store picked neither - its record helper
// drops the error on the floor (internal/store/memory/oidc.go:317,
// internal/store/postgres/oidc.go:126), so oidc.token (every access grant
// issued) and oidc.device.approve can go unrecorded with no error to the caller
// and no line in the log.
// ---------------------------------------------------------------------------
func TestZZAdmProviderAuditFailureIsNeitherReturnedNorLogged(t *testing.T) {
	failing := zzAdmFailingLogger{err: errors.New("probe: audit sink unreachable")}

	// Control: the logger really does fail, and vault fails closed on it (I3).
	// Without this the silent-drop assertion could pass for the wrong reason.
	wrapper, err := vault.NewLocalKeyWrapper("k", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewService(vault.NewMemoryRepo(), wrapper, failing)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Enroll(ctx, vault.Identity{Subject: "usr_x", Provider: "phigros.tape"}, []byte("s"), nil); err == nil {
		t.Fatal("control: vault.Enroll accepted a failing audit logger; the logger is not failing")
	}

	// The probe: an OP store whose audit sink is down.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  oauth.NewMemoryClientRegistry(),
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe", key),
		Audit:    failing,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreDeviceAuthorization(ctx, "cli", "probe-device-code", "WXYZ-1234",
		time.Now().Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	err = store.DecideDeviceAuthorization(ctx, "WXYZ-1234", "usr_victim", true, nil, nil)
	logged := buf.String()

	if err != nil {
		t.Logf("DecideDeviceAuthorization surfaced the audit failure: %v", err)
	}
	if err == nil && !strings.Contains(strings.ToLower(logged), "audit") {
		t.Errorf("a device approval (a whole access grant) was performed against a dead audit "+
			"sink: DecideDeviceAuthorization returned nil and nothing was logged (captured log %q). "+
			"The action proceeds, the record is lost, and no operator signal exists - neither "+
			"the fail-closed direction (vault.Use, lifecycle) nor the log-and-proceed one "+
			"(admin, auth) was taken", logged)
	}
}

// zzAdmFailingLogger is an audit logger that always fails.
type zzAdmFailingLogger struct{ err error }

func (f zzAdmFailingLogger) Record(context.Context, audit.Event) error { return f.err }

// ---------------------------------------------------------------------------
// P5. Erasing an operator's account does not end the operator capability its
// other sessions hold.
//
// The composition root states the session half itself ("sessions for a deleted
// account are only dropped on expiry", cmd/re0auth/main.go). What it does not
// state is the consequence for the allowlist: the gate is keyed on the session's
// usr_ value, never on the account row, so a deleted account keeps full operator
// power until its cookie expires.
// ---------------------------------------------------------------------------
func TestZZAdmErasedOperatorKeepsThePlaneThroughAnotherSession(t *testing.T) {
	env := newAdminEnv(t, true)

	// Memory-mode wiring: no session revoker, no flow purger, no pseudonym store.
	// The deleter has to be in place before the handler is built, because
	// specRoutes only mounts DELETE /v1/account when one is configured.
	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts: env.srv.accounts,
		Tokens:   env.store,
		Vault:    vault.NewMemoryRepo(),
		Audit:    audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.srv.deleter = deleter
	base := zzAdmRebuild(t, env.srv)

	first := newBrowser(t)
	signIn(t, first, base)
	second := newBrowser(t)
	signIn(t, second, base)

	csrf := sessionCSRF(t, base, first)
	for name, browser := range map[string]*http.Client{"first": first, "second": second} {
		resp := zzAdmSend(t, browser, base, http.MethodGet, "/v1/admin/clients", "")
		zzAdmProblemDetail(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s browser: GET /v1/admin/clients = %d, want 200 before erasure", name, resp.StatusCode)
		}
	}

	resp := adminJSON(t, first, http.MethodDelete, base+"/v1/account", csrf,
		map[string]any{"acknowledge": "deletes_my_account"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("erasure = %d: %s", resp.StatusCode, zzAdmProblemDetail(t, resp))
	}
	resp.Body.Close()

	resp = zzAdmSend(t, second, base, http.MethodGet, "/v1/admin/clients", "")
	detail := zzAdmProblemDetail(t, resp)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("an erased account's second session still calls the operator plane " +
			"(GET /v1/admin/clients = 200): erasure removed the account, not the operator " +
			"capability the allowlist keys on")
	} else if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second session after erasure = %d %q, want 404", resp.StatusCode, detail)
	}
}

// zzAdmRebuild serves the same Server again on a fresh port. The mux is built
// from specRoutes at Handler() time, so a route whose mount condition changed
// after the first build (DELETE /v1/account needs a deleter) only exists in a
// second build. The session cookie is port-agnostic, so a browser signed in
// here keeps working.
func zzAdmRebuild(t *testing.T, srv *Server) string {
	t.Helper()
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)
	return server.URL
}

// ---------------------------------------------------------------------------
// P6. The last step of an erasure can fail permanently, and the caller can no
// longer retry it.
//
// lifecycle.DeleteAccount revokes the account's sessions (step 4) and deletes
// the account row (step 7) *before* destroying the pseudonym key (step 8). When
// step 8 fails, the account is gone, every session is gone, and the audit
// history stays linkable - while the HTTP layer answers 500 "it is safe to try
// again", which is not true: the retry needs a session the erasure destroyed.
// The fake session revoker destroys the *calling* session, which is what a real
// subject-scoped revocation does to it (the caller's session is one of the
// subject's).
// ---------------------------------------------------------------------------
func TestZZAdmErasureWhoseLastStepFailsCannotBeRetried(t *testing.T) {
	env := newAdminEnv(t, true)

	flaky := &zzAdmFlakyDestroyer{failures: 1}
	sessions := &zzAdmDestroyingSessions{manager: env.srv.sessions}
	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts:   env.srv.accounts,
		Tokens:     env.store,
		Vault:      vault.NewMemoryRepo(),
		Sessions:   sessions,
		Pseudonyms: flaky,
		Audit:      audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.srv.deleter = deleter
	base := zzAdmRebuild(t, env.srv)

	browser := newBrowser(t)
	signIn(t, browser, base)
	csrf := sessionCSRF(t, base, browser)

	send := func() *http.Response {
		return adminJSON(t, browser, http.MethodDelete, base+"/v1/account", csrf,
			map[string]any{"acknowledge": "deletes_my_account"})
	}

	first := send()
	firstDetail := zzAdmProblemDetail(t, first)
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("first erasure = %d %q, want 500 from the failing last step", first.StatusCode, firstDetail)
	}
	if !sessions.called {
		t.Fatal("the erasure never reached the session step; the ordering claim is untested")
	}
	if !flaky.called {
		t.Fatal("the erasure never reached the pseudonym step")
	}

	// The finding was the response's promise, not the failure: it told the caller
	// "it is safe to try again", which is not true from the session step on. It
	// must not say that any more.
	for _, falsehood := range []string{"try again", "safe to"} {
		if strings.Contains(strings.ToLower(firstDetail), falsehood) {
			t.Errorf("the 500 still promises a retry (%q): %q — the erasure revokes the account's "+
				"sessions before the last step can fail, so trying again is not possible.",
				falsehood, firstDetail)
		}
	}

	// The retry is still refused, and that is inherent rather than fixed: the
	// erasure revoked the sessions at step 4 and deleted the account row at step 7.
	// Logged, not asserted, so a future change that makes it genuinely retryable is
	// noticed rather than silently breaking this probe.
	second := send()
	secondDetail := zzAdmProblemDetail(t, second)
	if second.StatusCode != http.StatusUnauthorized {
		t.Logf("the retry after the last step failed is now %d %q (sessions revoked: %v); "+
			"if the retry became reachable, the response's wording should be revisited",
			second.StatusCode, secondDetail, sessions.called)
	}
}

// zzAdmFlakyDestroyer fails its first N calls, then succeeds.
type zzAdmFlakyDestroyer struct {
	failures int
	calls    int
	called   bool
}

func (d *zzAdmFlakyDestroyer) Destroy(context.Context, string) error {
	d.calls++
	d.called = true
	if d.calls <= d.failures {
		return errors.New("probe: subject key store is unavailable")
	}
	return nil
}

// zzAdmDestroyingSessions is a subject-session revoker that really signs the
// caller out, because the caller's session is one of the subject's.
type zzAdmDestroyingSessions struct {
	manager interface {
		SignOut(context.Context) error
	}
	called bool
}

func (s *zzAdmDestroyingSessions) RevokeSubjectSessions(ctx context.Context, _ string) (int64, error) {
	s.called = true
	if err := s.manager.SignOut(ctx); err != nil {
		return 0, err
	}
	return 1, nil
}

// ---------------------------------------------------------------------------
// P7. Export containment: no other account's rows, and no caching. The
// credential half is already guarded by TestExportAccountOmitsCredentials; this
// is the cross-account half.
// ---------------------------------------------------------------------------
func TestZZAdmExportCarriesNoOtherAccountAndNoCache(t *testing.T) {
	base, browser, accounts, bindings, handler, store, v := newBindEnv(t)
	signIn(t, browser, base)
	ctx := context.Background()

	mine, err := accounts.FindByIdentity(ctx, idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := accounts.CreateWithIdentity(ctx, idp.Identity{Provider: idp.GitHub, Subject: "other-99"})
	if err != nil {
		t.Fatal(err)
	}

	myBinding := federation.Binding{User: mine, Game: "phigros", Source: "fake", TokenType: "Bearer"}
	otherBinding := federation.Binding{
		User: other.ID, Game: "zzothergame", Source: "zzothersource", TokenType: "Bearer",
	}
	for _, b := range []federation.Binding{myBinding, otherBinding} {
		if err := bindings.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		seedBindingSecret(t, v, b, "up-secret-"+b.Game)
	}
	// The other account also holds a live grant.
	mintToken(t, handler, store, "cli", string(other.ID), oauth.ScopePhigrosProfile)

	// Non-vacuity: the other account really does hold rows the export could leak.
	if n := zzAdmGrantCount(t, store, string(other.ID)); n == 0 {
		t.Fatal("the other account holds no grant; the leak assertion would prove nothing")
	}

	resp := getURL(t, browser, base+"/v1/account/export")
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("export Cache-Control = %q, want no-store", cc)
	}
	raw := rawBody(t, resp)
	if strings.Contains(raw, "zzothergame") || strings.Contains(raw, "zzothersource") ||
		strings.Contains(raw, string(other.ID)) {
		t.Errorf("the export mentions another account's data:\n%s", raw)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if n := len(doc["bindings"].([]any)); n != 1 {
		t.Errorf("export bindings = %d, want exactly the signed-in account's 1", n)
	}
	if n := len(doc["grants"].([]any)); n != 0 {
		t.Errorf("export grants = %d, want 0 (the grant belongs to the other account)", n)
	}
	if _, err := accounts.GetUser(ctx, other.ID); err != nil {
		t.Fatalf("the other account must still exist for this probe to mean anything: %v", err)
	}
}

func zzAdmGrantCount(t *testing.T, s *memory.OIDCStore, subject string) int {
	t.Helper()
	grants, err := s.Grants(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return len(grants)
}
