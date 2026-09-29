//go:build audit6

// Zone-01 finding: what the audit log records for a completed authorization.
package z01protocolauth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// 01-2 · Every successful authorization-code exchange writes a spurious
// `oidc.consent.deny` event. The mechanism: zitadel/oidc's CreateTokenResponse
// (pkg/op/token.go, "DeleteAuthRequest" call) asks the storage to delete the
// auth request after minting; both stores implement DeleteAuthRequest to
// record a deny event unconditionally — and by then AuthRequestByCode has
// already consumed the request, so the event carries an empty subject and an
// empty client. One "user denied" audit row per successful login makes the
// deny stream meaningless to an operator reading it.
//
// The postgres store has the same shape (internal/store/postgres/oidc.go,
// DeleteAuthRequest reads subject/client then records consent.deny; the
// AuthRequestByCode transaction has already deleted both rows).
func TestProbeASuccessfulCodeExchangeWritesAConsentDenyAuditEvent(t *testing.T) {
	e := newPlane(t, planeOptions{withAudit: true})

	tokens, _ := e.codeFlow(t, []string{"openid", "account.id"}, nil)
	if tokens["access_token"] == "" {
		t.Fatal("the control exchange did not issue a token")
	}

	var denies []audit.Event
	for _, ev := range e.audit.Events() {
		if ev.Action == "oidc.consent.deny" {
			denies = append(denies, ev)
		}
	}
	for _, ev := range e.audit.Events() {
		t.Logf("audit event: action=%s subject=%q provider=%s outcome=%s detail=%v",
			ev.Action, ev.Subject, ev.Provider, ev.Outcome, ev.Detail)
	}
	if len(denies) != 0 {
		for _, d := range denies {
			t.Errorf("a successful authorization-code exchange recorded oidc.consent.deny "+
				"(subject=%q client=%v): the library's post-mint DeleteAuthRequest hit the store's "+
				"unconditional deny record after AuthRequestByCode had already consumed the request",
				d.Subject, d.Detail)
		}
	}
}

// 01-2 control · A user's actual denial still records the event (with the
// client), so the fix has a real event to preserve — this probe is expected to
// stay green.
func TestProbeAnActualDenialStillRecordsTheEvent(t *testing.T) {
	e := newPlane(t, planeOptions{withAudit: true})

	// Start a request and deny it through the same interaction API the consent
	// route uses.
	verifier := "verifier-verifier-verifier-verifier-verifier"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"openid account.id"},
		"state":                 {"st-deny"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %s", resp.Header.Get("Location"))
	}
	if _, err := e.handler.DenyAuthorization(t.Context(), id); err != nil {
		t.Fatal(err)
	}

	var denies int
	for _, ev := range e.audit.Events() {
		if ev.Action == "oidc.consent.deny" {
			denies++
			if ev.Detail["client_id"] != e.webID {
				t.Errorf("a real denial recorded client %v, want %s", ev.Detail, e.webID)
			}
		}
	}
	if denies != 1 {
		t.Fatalf("a real denial recorded %d deny events, want 1", denies)
	}
}
