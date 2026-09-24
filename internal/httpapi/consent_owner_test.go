package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// consentView fetches the consent screen's data, reporting the CSRF token that a
// decision has to echo.
func consentView(t *testing.T, c *http.Client, base, handle string) (csrf string, status int) {
	t.Helper()
	resp := getURL(t, c, base+"/v1/authorization_requests/"+handle)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	csrf, _ = decodeResp(t, resp)["csrf_token"].(string)
	return csrf, resp.StatusCode
}

// decideConsent posts the frontend's approval and returns the status.
func decideConsent(t *testing.T, c *http.Client, base, handle, csrf string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"decision": "approve", "scopes": []string{"account.id"}})
	req, _ := http.NewRequest(http.MethodPost,
		base+"/v1/authorization_requests/"+handle+"/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

const consentVerifier = "verifier-verifier-verifier-verifier-verifier"

// The direction that has to keep working: the account that started the request is
// the one that approves it.
func TestConsentApprovedByTheAccountThatStartedIt(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	handle := authorize(t, browser, base, consentVerifier, "account.id", "st-same")
	csrf, status := consentView(t, browser, base, handle)
	if status != http.StatusOK {
		t.Fatalf("consent view = %d, want 200", status)
	}
	if csrf == "" {
		t.Fatal("no csrf token in the consent view")
	}
	if got := decideConsent(t, browser, base, handle, csrf); got != http.StatusOK {
		t.Fatalf("decision = %d, want 200", got)
	}
}

// The direction that must not work: a handle created by account A, then account B
// signing in on the same browser. Rotating the session id on sign-in preserves the
// session's values — deliberately, because the flow depends on a handle surviving
// the sign-in it triggers — so the handle has to carry the account it was created
// for, or it follows the browser instead of the account.
//
// Both the read and the decision are refused, and both as 404: a handle must not
// confirm its own existence to the wrong account. The test also proves B can still
// act on its *own* handle, so this is an ownership check rather than a lockout.
func TestConsentHandleCannotBeUsedByAnotherAccount(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)

	signInAs(t, browser, base, "a")
	handleA := authorize(t, browser, base, consentVerifier, "account.id", "st-a")

	// B signs in on the same browser, without A signing out.
	signInAs(t, browser, base, "b")

	if _, status := consentView(t, browser, base, handleA); status != http.StatusNotFound {
		t.Fatalf("A's consent view after B signed in = %d, want 404", status)
	}

	// B's own request works, which is what makes the refusal above an ownership
	// check and not a blanket one. It also supplies a CSRF token that B legitimately
	// holds.
	handleB := authorize(t, browser, base, consentVerifier, "account.id", "st-b")
	csrfB, status := consentView(t, browser, base, handleB)
	if status != http.StatusOK {
		t.Fatalf("B's own consent view = %d, want 200", status)
	}
	if csrfB == "" {
		t.Fatal("no csrf token for B's own request")
	}

	if got := decideConsent(t, browser, base, handleA, csrfB); got != http.StatusNotFound {
		t.Fatalf("B deciding A's handle = %d, want 404", got)
	}
	if got := decideConsent(t, browser, base, handleB, csrfB); got != http.StatusOK {
		t.Fatalf("B deciding B's own handle = %d, want 200", got)
	}
}
