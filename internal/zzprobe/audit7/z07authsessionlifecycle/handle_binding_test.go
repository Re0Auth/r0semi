//go:build audit7

package z07authsessionlifecycle

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/auth"
)

// TestZ07DeviceVerificationBindsCallerControlledUserCodeBytesIntoTheSession.
//
// oauth.NormalizeUserCode removes every '-' before the device lookup
// (oauth/device.go:481-483), so one live user code has unboundedly many accepted
// spellings. The verification page then hands back the spelling the caller used —
// `DescribeDeviceAuthorization` returns `UserCode: userCode`, the *input*
// (internal/store/memory/oidc.go:1365-1368) — and `handleDeviceVerification`
// binds exactly that string into the browser session
// (internal/httpapi/device_routes.go:69). `auth.Manager.Bind` rejects only an id
// containing the unit separator and a cap on how many handles a kind may hold,
// never on their bytes (internal/auth/auth.go:304-330), and the session is
// re-committed whole on every request. So a signed-in browser that loads one URL
// carries a caller-chosen key of up to the request-line limit, for the life of
// the cookie, and up to 32 of them.
func TestZ07DeviceVerificationBindsCallerControlledUserCodeBytesIntoTheSession(t *testing.T) {
	store := newZ07Store()
	manager := auth.NewManager(auth.Options{Secure: false, Store: store})
	env := newProbeEnv(t, probeOptions{Manager: manager})
	b := env.newBrowser()
	b.signIn(probeProvider)

	_, _, base := store.counts()
	t.Logf("baseline session payload after sign-in: %d bytes", base)

	// A live user code the attacker can mint anonymously for any public client.
	canonical := deviceAuthorization(t, b)
	norm := strings.ReplaceAll(canonical, "-", "")

	const pad = 60000
	spellings := []string{
		norm[:1] + strings.Repeat("-", pad) + norm[1:],
		norm[:2] + strings.Repeat("-", pad) + norm[2:],
		norm[:3] + strings.Repeat("-", pad) + norm[3:],
	}
	accepted := 0
	for _, spelling := range spellings {
		resp := b.get("/v1/device/verification?user_code=" + url.QueryEscape(spelling))
		body := bodyOf(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the lookup refused a spelling whose normalisation is a live code: %d (%s)",
				resp.StatusCode, body)
		}
		var view struct {
			UserCode string `json:"user_code"`
		}
		if err := json.Unmarshal([]byte(body), &view); err != nil {
			t.Fatal(err)
		}
		if view.UserCode == spelling {
			accepted++
		}
	}

	// One more ordinary request, so the whole session is committed once more.
	resp := b.get("/v1/sessions/current")
	resp.Body.Close()

	_, _, after := store.counts()
	t.Logf("session payload after %d crafted verification loads: %d bytes (baseline %d)", len(spellings), after, base)

	if accepted == 0 {
		t.Fatalf("the page did not echo the caller's spelling, so nothing was bound")
	}
	if after < base+pad {
		t.Fatalf("the crafted handle did not reach the session store: %d -> %d bytes", base, after)
	}
	t.Errorf("%d crafted spellings of one user code — each %d bytes, %d bytes of padding apiece — were echoed "+
		"back and bound into the browser session as handle ids (%d bytes committed in one session, baseline %d); "+
		"Bind caps how many handles a kind holds (32) but never their bytes, and the session is rewritten whole on "+
		"every request, so one navigation carries the bloat for the life of the cookie and 32 spellings multiply it",
		accepted, pad+len(norm), pad, after, base)
}

// TestZ07UserCodeSpellingIsNormalisedForTheLookupButNotForTheHandle.
//
// The device flow is case- and separator-insensitive on the lookup path
// (oauth.NormalizeUserCode, oauth/device.go:479-490), and the verification page
// returns the canonical spelling (device_routes.go:69 binds auth.UserCode). The
// decision path, however, checks the session handle against the *client's* string
// verbatim (device_routes.go:108-112), so a caller that echoes the code the user
// actually typed — the shape RFC 8628 invites — is answered "unknown user code"
// even though the page had just rendered it as pending. Nothing is approved, so
// this fails closed; the defect is that two spellings of one code disagree about
// whether the handle exists.
func TestZ07UserCodeSpellingIsNormalisedForTheLookupButNotForTheHandle(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()

	canonical := deviceAuthorization(t, b) // e.g. "BCDF-GHJK"
	// oauth.NormalizeUserCode upper-cases, trims, and removes hyphens
	// (oauth/device.go:481-483), so a lower-case code with the hyphen kept is a
	// spelling the lookup accepts.
	typed := strings.ToLower(canonical)

	// What the lookup does *not* accept, despite the comment above it claiming to
	// be "separator-insensitive": anything but '-'.
	spaced := strings.ToLower(strings.ReplaceAll(canonical, "-", " "))
	spacedResp := b.get("/v1/device/verification?user_code=" + url.QueryEscape(spaced))
	spacedBody := bodyOf(t, spacedResp)
	if spacedResp.StatusCode == http.StatusNotFound {
		t.Logf("normalizeUserCode is hyphen-only, not 'separator-insensitive': %q = %d (%s)",
			spaced, spacedResp.StatusCode, spacedBody)
	}

	// The lookup accepts the typed spelling and normalises it.
	resp := b.get("/v1/device/verification?user_code=" + url.QueryEscape(typed))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"state":"pending"`) {
		t.Fatalf("the verification page refused the typed spelling %q: %d (%s)", typed, resp.StatusCode, body)
	}
	var view struct {
		State    string `json:"state"`
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	t.Logf("typed %q -> page shows state=%q user_code=%q", typed, view.State, view.UserCode)

	decide := func(userCode string) int {
		payload, _ := json.Marshal(map[string]string{"user_code": userCode, "decision": "approve"})
		return b.status(http.MethodPost, "/v1/device/decision", string(payload), map[string]string{
			"Content-Type": "application/json", "X-CSRF-Token": csrf,
		})
	}

	// The canonical spelling (what POST /oauth/device_authorization returned, and
	// what RFC 8628 prints on the device) must still be the one that works.
	canonicalCode := view.UserCode
	if canonicalCode == "" {
		canonicalCode = canonical
	}
	if got := decide(canonicalCode); got != http.StatusOK {
		t.Fatalf("approving with the page's own spelling %q = %d, want 200 (the handle is not usable at all)",
			canonicalCode, got)
	}

	// A second code, loaded with the spelling the user typed and decided with the
	// canonical `user_code` the device authorization returned — the spelling any
	// client that did not read the page's echo would use.
	second := deviceAuthorization(t, b)
	typed2 := strings.ToLower(second)
	load := b.get("/v1/device/verification?user_code=" + url.QueryEscape(typed2))
	loadBody := bodyOf(t, load)
	if load.StatusCode != http.StatusOK {
		t.Fatalf("second verification load with %q = %d (%s)", typed2, load.StatusCode, loadBody)
	}
	var secondView struct {
		UserCode string `json:"user_code"`
	}
	_ = json.Unmarshal([]byte(loadBody), &secondView)
	t.Logf("loaded with %q, the page echoed user_code=%q (the request's spelling, not the stored code %q)",
		typed2, secondView.UserCode, second)

	if got := decide(second); got == http.StatusNotFound {
		t.Errorf("the same device grant answered to two spellings: the page loaded %q as pending, but a "+
			"decision carrying the canonical user_code %q — the value the device authorization endpoint "+
			"returned and the one RFC 8628 prints — is 404; the handle key is the caller's spelling while the "+
			"lookup normalises", typed2, second)
	} else {
		t.Logf("deciding with the canonical spelling %q = %d", second, got)
	}
	if got := decide(secondView.UserCode); got != http.StatusOK {
		t.Logf("(the page's echoed spelling %q = %d)", secondView.UserCode, got)
	}
}

// TestZ07CSRFTokenIsNotBoundToTheAccount records the second half of the token's
// binding: SignIn rotates the session id but, since scs.RenewToken keeps the
// session's values, a token minted while account A was signed in still validates
// for account B on the same browser. The probe is a guard, not a finding: an
// attacker who learned A's token has no way to make B's browser send it
// (X-CSRF-Token is a custom header, and the protocol plane issues no CORS
// headers), and the session id A held is dead.
func TestZ07CSRFTokenIsNotBoundToTheAccount(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	env.setIdentity("csrf-a")
	b.signIn(probeProvider)
	tokenForA := b.csrf()

	env.setIdentity("csrf-b")
	b.signIn(probeProvider)

	if got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": tokenForA}); got == http.StatusNoContent {
		t.Logf("the token minted while account A was signed in still validates for account B on the same " +
			"browser: the token is session-bound, not account-bound (and the session id rotated, so A's " +
			"cookie is dead)")
	} else {
		t.Errorf("the token did not carry across the account switch: %d", got)
	}
}
