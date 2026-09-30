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

// TestZ07DeviceVerificationBindsCallerControlledUserCodeBytesIntoTheSession is
// the regression guard for Z07-3.
//
// oauth.NormalizeUserCode removes every '-' before the device lookup, so one live
// user code has unboundedly many accepted spellings. The verification page used
// to hand back the spelling the caller used, and Bind capped how many handles a
// kind holds (32) but never their bytes, so a signed-in browser that loaded one
// URL carried a caller-chosen session key of up to the request-line limit.
//
// It must now bind and return the normalised code: every accepted spelling has to
// answer 200 (the lookup stays insensitive — that is the control in the loop) yet
// come back as the same short value, and the session payload must not grow by the
// padding.
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
	var echoes []string
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
		echoes = append(echoes, view.UserCode)
	}

	// One more ordinary request, so the whole session is committed once more.
	resp := b.get("/v1/sessions/current")
	resp.Body.Close()

	_, _, after := store.counts()
	t.Logf("session payload after %d crafted verification loads: %d bytes (baseline %d)", len(spellings), after, base)

	// The lookup stays spelling-insensitive (every crafted spelling answered 200
	// above — the t.Fatalf in the loop is the control), but the handle must not
	// be: every accepted spelling has to normalise to the same bounded value, so
	// the caller cannot choose the bytes the session carries.
	if accepted != 0 {
		t.Errorf("%d crafted spellings were echoed back verbatim; the verification page must bind and return "+
			"the normalised code, not the caller's bytes (Z07-3)", accepted)
	}
	if len(echoes) == 0 || echoes[0] == "" {
		t.Fatalf("the page reported a live code but echoed no user_code at all")
	}
	for i := 1; i < len(echoes); i++ {
		if echoes[i] != echoes[0] {
			t.Errorf("one live code returned %q and %q for two accepted spellings: the handle is "+
				"spelling-dependent (Z07-3)", echoes[0], echoes[i])
		}
	}
	if len(echoes[0]) > 16 {
		t.Errorf("the bound user code is %d bytes: the handle's length must come from the code, not from the "+
			"request line (Z07-3)", len(echoes[0]))
	}
	if after >= base+pad {
		t.Errorf("the crafted spelling reached the session store: %d -> %d bytes; a %d-byte spelling must not "+
			"be bindable (Z07-3)", base, after, pad)
	}
	t.Logf("all %d crafted spellings echoed the same %d-byte code; session payload %d bytes (baseline %d)",
		len(echoes), len(echoes[0]), after, base)
}

// TestZ07UserCodeSpellingIsNormalisedForTheLookupButNotForTheHandle is the
// regression guard for the second half of Z07-3.
//
// The device flow is case- and separator-insensitive on the lookup path
// (oauth.NormalizeUserCode), and the verification page returns the normalised
// spelling. The decision path used to check the session handle against the
// *client's* string verbatim, so a caller echoing the code the user actually
// typed — the shape RFC 8628 invites — was answered "unknown user code" even
// though the page had just rendered it as pending. Both halves must now agree:
// whatever spelling loads the page, the same grant must be decidable with any
// accepted spelling, including the canonical one the device authorization
// endpoint returned.
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
	t.Logf("loaded with %q, the page echoed the normalised user_code=%q", typed2, secondView.UserCode)

	// Loaded with the typed spelling, the same grant must be decidable with the
	// canonical spelling the device authorization endpoint returned: the handle
	// is the normalised code, so every accepted spelling addresses it.
	if got := decide(second); got != http.StatusOK {
		t.Errorf("the same device grant answered to two spellings: the page loaded %q as pending, but a "+
			"decision carrying the canonical user_code %q — the value the device authorization endpoint "+
			"returned and the one RFC 8628 prints — is %d; the handle key must be the normalised code (Z07-3)",
			typed2, second, got)
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
