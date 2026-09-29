//go:build audit7

// Z20 consent-decision probes: what the audit log records about "which subject
// granted which client which scopes", and whether the device entrance honours the
// explicit-consent rule the catalogue carries.
package zzprobe_z20authzisolationmatrix

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ20SuccessfulCodeExchangeWritesASpuriousConsentDeny is the finding probe.
//
// The consent decision is audited on both exits (CHANGELOG AUD-3): approval in
// `CompleteLogin`, refusal in `DeleteAuthRequest`. But the OP library calls
// `DeleteAuthRequest` on the SUCCESS path too — `op.CreateTokenResponse` deletes
// the auth request after minting (zitadel/oidc pkg/op/token.go:50) — so every
// successful authorization-code exchange writes an `oidc.consent.deny` event.
// By that point `AuthRequestByCode` has already consumed the request
// (internal/store/memory/oidc.go:418-433), so the event carries an empty subject
// and an empty client id: the refusal stream gains one entry per successful
// login, with no way to tell it from a real refusal except that its fields are
// blank.
func TestZ20SuccessfulCodeExchangeWritesASpuriousConsentDeny(t *testing.T) {
	e := newZEnv(t, zOptions{})

	before := len(e.zEvents("oidc.consent.deny"))
	tok := e.mintToken(zSubject, "account.id", "phigros.profile.read")
	if tok == "" {
		t.Fatal("control failed: the code exchange issued no token")
	}

	// Control: the AUD-3 approval record is there, with its parties and scopes.
	approves := e.zEvents("oidc.consent.approve")
	if len(approves) != 1 {
		t.Fatalf("control: %d approve events, want 1: %+v", len(approves), approves)
	}
	if approves[0].Subject != zSubject || approves[0].Detail["client_id"] != zClientID {
		t.Errorf("control: the approval names the wrong parties: subject %q detail %v",
			approves[0].Subject, approves[0].Detail)
	}

	denies := e.zEvents("oidc.consent.deny")
	after := len(denies)
	if after != before {
		for _, d := range denies[before:] {
			t.Errorf("a SUCCESSFUL code exchange recorded %s: subject=%q outcome=%s detail=%v "+
				"(the library's post-mint DeleteAuthRequest reached the store's unconditional "+
				"refusal record)", d.Action, d.Subject, d.Outcome, d.Detail)
		}
	}
}

// TestZ20ARealRefusalStillRecordsTheEvent is the control for the fix: a refusal
// made through the real interaction API must keep its event, and that event must
// name the client.
func TestZ20ARealRefusalStillRecordsTheEvent(t *testing.T) {
	e := newZEnv(t, zOptions{})

	const verifier = "verifier-verifier-verifier-verifier-verifier"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {zClientID},
		"redirect_uri":          {zRedirect},
		"scope":                 {"account.id"},
		"state":                 {"st-z20-deny"},
		"code_challenge":        {zPKCE(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", loc)
	}
	// The route's own call: httpapi's decision handler invokes
	// Authorization.DenyAuthorization, which deletes the pending request.
	if _, err := e.op.DenyAuthorization(t.Context(), id); err != nil {
		t.Fatalf("deny: %v", err)
	}
	denies := e.zEvents("oidc.consent.deny")
	if len(denies) != 1 {
		t.Fatalf("a real refusal recorded %d deny events, want 1: %+v", len(denies), denies)
	}
	if got := denies[0].Detail["client_id"]; got != zClientID {
		t.Errorf("a real refusal recorded client %q, want %q", got, zClientID)
	}
}

// TestZ20DeviceApprovalAuditOmitsTheGrantedScopes is a finding probe for the
// device face of the same decision.
//
// AUD-3's contract is "which client, which scopes" (CHANGELOG, commit 636a074).
// The interactive face records the approved scope set
// (memory/oidc.go:1055-1060). The device face records only the client
// (memory/oidc.go:1104 `s.record(ctx, "oidc.device.approve", subject,
// d.clientID, ...)`), and the device decision is where narrowing happens
// (oidcstore.NarrowScopes), so the log cannot answer what was actually granted —
// the requested set and the granted set can differ.
func TestZ20DeviceApprovalAuditOmitsTheGrantedScopes(t *testing.T) {
	e := newZEnv(t, zOptions{})

	form := url.Values{
		"client_id": {zClientID},
		"scope":     {"phigros.profile.read phigros.score.read"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", rec.Code, rec.Body.String())
	}
	var dev struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dev); err != nil || dev.UserCode == "" {
		t.Fatalf("no user code: %s (err=%v)", rec.Body.String(), err)
	}

	// The decision the device route makes (httpapi/device_routes.go:114): the
	// user approves ONE of the two requested scopes.
	if err := e.store.DecideDeviceAuthorization(t.Context(), dev.UserCode, zSubject, true,
		[]oauth.Scope{oauth.ScopePhigrosProfile}, nil); err != nil {
		t.Fatalf("DecideDeviceAuthorization: %v", err)
	}

	events := e.zEvents("oidc.device.approve")
	if len(events) != 1 {
		t.Fatalf("control: %d device approval events, want 1 (actions seen: %v)",
			len(events), e.audit.Events())
	}
	if got := events[0].Detail["client_id"]; got != zClientID {
		t.Errorf("the device approval records the wrong client: %q", got)
	}
	if _, ok := events[0].Detail["scopes"]; !ok {
		t.Errorf("the device approval records no scopes: detail=%v. The narrowing decision "+
			"(profile approved, score withheld) is invisible in the log, while the "+
			"interactive face records its granted set", events[0].Detail)
	}
}

// TestZ20DeviceApprovalEnforcesExplicitConsent refutes `_audit/protocol.md` P-02
// ("设备流批准不检查 ExplicitConsent").
//
// P-02 says the mechanism exists everywhere but the device gate, and that
// `memory.OIDCStore.ApproveDevice` lacks it. `ApproveDevice` is not an entrance:
// the device route calls `DecideDeviceAuthorization`
// (httpapi/device_routes.go:114 → DeviceStore), and that method resolves the
// descriptors and calls `oidcstore.RequireExplicitConsent` before it writes
// (internal/store/memory/oidc.go:1397-1406; the postgres twin at
// internal/store/postgres/oidc.go:1217). With a catalogue that actually carries
// an ExplicitConsent descriptor, an approval that omits the tick is refused.
func TestZ20DeviceApprovalEnforcesExplicitConsent(t *testing.T) {
	e := newZEnv(t, zOptions{
		Registry:     zRegistryWithCritical(t),
		ClientScopes: []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile, zCriticalScope},
	})

	newCode := func(t *testing.T) string {
		t.Helper()
		form := url.Values{"client_id": {zClientID}, "scope": {zCriticalScope.String()}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("device_authorization = %d: %s", rec.Code, rec.Body.String())
		}
		var dev struct {
			UserCode string `json:"user_code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &dev); err != nil || dev.UserCode == "" {
			t.Fatalf("no user code: %s (err=%v)", rec.Body.String(), err)
		}
		return dev.UserCode
	}

	// Control: the same approval WITH the tick succeeds.
	ok := newCode(t)
	if err := e.store.DecideDeviceAuthorization(t.Context(), ok, zSubject, true, nil,
		[]oauth.Scope{zCriticalScope}); err != nil {
		t.Fatalf("control: an approval that ticked the critical scope was refused: %v", err)
	}

	// The attack P-02 predicted: approval without the tick.
	uc := newCode(t)
	err := e.store.DecideDeviceAuthorization(t.Context(), uc, zSubject, true, nil, nil)
	t.Logf("device approval without the explicit tick -> %v", err)
	if err == nil {
		t.Errorf("the device entrance approved an ExplicitConsent scope with no individual " +
			"tick: P-02 holds")
		return
	}
	var oe *oauth.Error
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Errorf("the device entrance refused for the wrong reason: %v (want access_denied)", err)
	}
}
