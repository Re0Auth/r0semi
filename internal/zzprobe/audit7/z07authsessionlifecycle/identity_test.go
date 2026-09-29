//go:build audit7

package z07authsessionlifecycle

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestZ07UnlinkAnotherAccountsIdentityIsNotFound.
//
// account.Store enforces I-3/isolation on the identity id: an identity that
// belongs to another account must be refused as "not found", never as
// "forbidden" — the latter would confirm the identity exists. Both backends
// compare the owner inside the store (memory/account.go:203-206,
// store/postgres/account.go:162-165), so the HTTP layer's 404 vs 403 split is
// decided by the store.
func TestZ07UnlinkAnotherAccountsIdentityIsNotFound(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})

	alice := env.newBrowser()
	env.setIdentity("alice")
	aliceUser := alice.signIn(probeProvider)

	bob := env.newBrowser()
	env.setIdentity("bob")
	bobUser := bob.signIn(probeProvider)
	if aliceUser == bobUser {
		t.Fatal("the two identities resolved to one account")
	}
	bobIDs := env.identityIDs(bobUser)
	if len(bobIDs) == 0 {
		t.Fatal("account B has no identity to attack")
	}

	csrf := alice.csrf()
	for _, id := range bobIDs {
		got := alice.status(http.MethodDelete, "/v1/identities/"+url.PathEscape(id), "", map[string]string{
			"X-CSRF-Token": csrf,
		})
		if got == http.StatusForbidden {
			t.Errorf("unlinking another account's identity %s answered 403, which confirms it exists", id)
			continue
		}
		if got != http.StatusNotFound {
			t.Errorf("unlinking another account's identity %s = %d, want 404", id, got)
			continue
		}
		t.Logf("another account's identity is 404, as designed")
	}

	// The victim's identity must still be there.
	if len(env.identityIDs(bobUser)) != len(bobIDs) {
		t.Errorf("account B lost an identity to account A")
	}
}

// TestZ07UnlinkingTheLastIdentityIsRefused is the I-2 guard at the HTTP layer: a
// 409, and the account is untouched.
func TestZ07UnlinkingTheLastIdentityIsRefused(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	user := b.signIn(probeProvider)
	csrf := b.csrf()

	ids := env.identityIDs(user)
	if len(ids) != 1 {
		t.Fatalf("the fixture gave the account %d identities, want 1", len(ids))
	}
	got := b.status(http.MethodDelete, "/v1/identities/"+url.PathEscape(ids[0]), "", map[string]string{
		"X-CSRF-Token": csrf,
	})
	if got != http.StatusConflict {
		t.Errorf("unlinking the last identity = %d, want 409", got)
	}
	if len(env.identityIDs(user)) != 1 {
		t.Errorf("the last identity was removed anyway")
	}
}

// deviceAuthorization starts a real RFC 8628 device flow as the public client and
// returns the user_code the human would type.
func deviceAuthorization(t *testing.T, b *browser) string {
	t.Helper()
	form := url.Values{
		"client_id": {probeClientID},
		"scope":     {"account.id"},
	}
	resp := b.do(http.MethodPost, "/oauth/device_authorization", form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d (%s)", resp.StatusCode, body)
	}
	var out struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.UserCode == "" {
		t.Fatalf("no user_code in %s", body)
	}
	return out.UserCode
}

// TestZ07DeviceDecisionIsRefusedForAHandleBoundToAnotherAccount is the ADR-0004
// device half at the real entry point: account A loads a user_code (which binds
// it to A), account B signs in on the same browser, and B's decision must be a
// 404 — while B's own load still works.
func TestZ07DeviceDecisionIsRefusedForAHandleBoundToAnotherAccount(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	env.setIdentity("dev-a")
	b.signIn(probeProvider)
	code := deviceAuthorization(t, b)

	// A loads the verification page: the handle is bound with owner A.
	resp := b.get("/v1/device/verification?user_code=" + url.QueryEscape(code))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"state":"pending"`) {
		t.Fatalf("A's verification load = %d (%s)", resp.StatusCode, body)
	}
	// The page hands back the normalised code; that is what the decision must use.
	var view struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	if view.UserCode == "" {
		view.UserCode = code
	}

	// Same browser, second account, no sign-out.
	env.setIdentity("dev-b")
	b.signIn(probeProvider)
	csrf := b.csrf()

	decision := func(userCode string) int {
		payload, _ := json.Marshal(map[string]string{"user_code": userCode, "decision": "approve"})
		return b.status(http.MethodPost, "/v1/device/decision", string(payload), map[string]string{
			"Content-Type": "application/json", "X-CSRF-Token": csrf,
		})
	}
	if got := decision(view.UserCode); got == http.StatusOK {
		t.Errorf("account B approved a user_code bound to account A's session: POST /v1/device/decision = 200")
	} else {
		t.Logf("B's decision on A's handle = %d", got)
	}

	// Positive control: B's own code works, so this is ownership, not a blanket
	// refusal.
	own := deviceAuthorization(t, b)
	load := b.get("/v1/device/verification?user_code=" + url.QueryEscape(own))
	loadBody := bodyOf(t, load)
	if load.StatusCode != http.StatusOK {
		t.Fatalf("B's own verification load = %d (%s)", load.StatusCode, loadBody)
	}
	var ownView struct {
		UserCode string `json:"user_code"`
	}
	_ = json.Unmarshal([]byte(loadBody), &ownView)
	if ownView.UserCode == "" {
		ownView.UserCode = own
	}
	if got := decision(ownView.UserCode); got != http.StatusOK {
		t.Errorf("B could not approve its own device code: %d", got)
	} else {
		t.Logf("B approved its own device code")
	}
}

// TestZ07LinkFlowConfirmsWhetherAnExternalIdentityAlreadyHasAnAccount.
//
// Starting a link flow (`?mode=link`) with an external identity that already
// belongs to another account redirects back with `?error=identity_taken`
// (internal/auth/auth.go:681-688). The code is a documented contract with the
// SPA, but it is also an existence oracle: anyone who controls one external IdP
// account at a configured provider and holds any Re0Auth account can ask "does
// this external identity have a Re0Auth account?" and get a yes/no. The login
// flow deliberately hides the same fact (both branches end with the same 303).
func TestZ07LinkFlowConfirmsWhetherAnExternalIdentityAlreadyHasAnAccount(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})

	// Account B exists, reachable as the external identity "victim".
	victim := env.newBrowser()
	env.setIdentity("victim")
	victimUser := victim.signIn(probeProvider)

	// Account A is a different person.
	attacker := env.newBrowser()
	env.setIdentity("attacker")
	attacker.signIn(probeProvider)

	// A asks: is "victim" already taken?
	env.setIdentity("victim")
	loc := attacker.signInOrFail(probeProvider, "link")
	t.Logf("link callback for an already-linked identity redirected to %q", loc)
	if strings.Contains(loc, "identity_taken") {
		t.Errorf("the link flow confirms that external identity %q already has an account (redirect %q); "+
			"the login flow does not disclose the same fact", "victim", loc)
	}

	// Control: an identity nobody holds links successfully, so the probe is not
	// satisfied by a flow that always reports the error.
	env.setIdentity("fresh-identity")
	loc2 := attacker.signInOrFail(probeProvider, "link")
	if strings.Contains(loc2, "error=") {
		t.Fatalf("linking a fresh identity reported an error: %q", loc2)
	}
	t.Logf("linking a fresh identity succeeded (redirect %q)", loc2)

	// And the victim's account is still the owner of "victim".
	if env.identityIDs(victimUser) == nil {
		t.Errorf("the victim account lost its identity")
	}
}

// TestZ07IdentityListIsSessionScoped: a bearer token must not be able to
// enumerate the account's login methods. The bearer request is made from a
// *fresh* browser so no session cookie accompanies it — otherwise the session
// would answer and the probe would prove nothing.
func TestZ07IdentityListIsSessionScoped(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()

	const verifier = "verifier-identities-scope-probe-000000000000000000"
	code := b.completeAuthorize("", csrf, verifier, "st-ident")
	tok := b.exchangeCode(code, verifier)
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", tok)
	}

	// Positive control for the token itself: a bearer-authenticated call that is
	// supposed to accept it does work from the same cookie-less browser.
	bare := env.newBrowser()
	bearer := map[string]string{"Authorization": "Bearer " + access}
	if got := bare.status(http.MethodGet, "/v1/me", "", bearer); got != http.StatusOK {
		t.Fatalf("GET /v1/me with the bearer token = %d, want 200 (the token is not being accepted at all)", got)
	}

	for _, target := range []string{"/v1/identities", "/v1/grants", "/v1/bindings", "/v1/sessions/current"} {
		got := bare.status(http.MethodGet, target, "", bearer)
		if got == http.StatusOK {
			body := ""
			if resp := bare.do(http.MethodGet, target, "", bearer); resp != nil {
				body = bodyOf(t, resp)
			}
			t.Errorf("GET %s with a client's bearer token and no session = 200; the view is supposed to be "+
				"session-scoped: %s", target, body)
			continue
		}
		t.Logf("GET %s with a bearer token = %d", target, got)
	}
}
