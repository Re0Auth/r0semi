package auth

// Z07-8 probe: the /auth link callback must not answer "does this external
// identity already have a Re0Auth account?".
//
// Before the fix, linking an identity owned by another account redirected with
// `?error=identity_taken` while any other link failure redirected with
// `?error=link_failed`. The difference is an existence oracle: any signed-in
// user who can authenticate to a configured provider as some external subject
// could read the answer off the return URL. The login flow deliberately refuses
// to disclose the same fact (an unknown identity simply creates an account).
//
// The fix merges the two into one outward code and keeps the distinction in the
// server-side audit record. This probe fails on the old code and passes on the
// new one; it is the "red before, green after" artifact.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
)

// mislinkingStore is an account store whose LinkIdentity always fails with an
// unclassified error — the "linking failed for some other reason" arm the
// occupied-identity arm must be indistinguishable from on the wire.
type mislinkingStore struct {
	*account.MemoryStore
	err error
}

func (s mislinkingStore) LinkIdentity(context.Context, account.UserID, idp.Identity) (account.Identity, error) {
	return account.Identity{}, s.err
}

// linkCallback drives a full mode=link round trip and returns the callback's
// Location and body.
func (h *harness) linkCallback(t *testing.T, provider string) (string, string) {
	t.Helper()
	resp := h.get(t, h.server.URL+"/auth/"+provider+"/start?mode=link")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("link start status = %d, want 302", resp.StatusCode)
	}
	state := stateOf(t, resp)
	if provider == "google" {
		h.oidc.SetNonce(nonceOf(t, resp))
	}
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/"+provider+"/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther {
		body := readBody(t, resp)
		t.Fatalf("link callback status = %d body = %s, want 303", resp.StatusCode, body)
	}
	return resp.Header.Get("Location"), readBody(t, resp)
}

func errorCodeOf(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	return u.Query().Get("error")
}

func hasAuditCode(events []audit.Event, code string) bool {
	for _, e := range events {
		if e.Detail["code"] == code {
			return true
		}
	}
	return false
}

func TestZ07LinkCallbackCannotConfirmAnIdentityIsTaken(t *testing.T) {
	// Arm 1 — occupied: another account already owns discord/dc-555.
	taken := newHarness(t)
	if _, _, err := taken.accounts.CreateWithIdentity(context.Background(), idp.Identity{
		Provider: idp.Discord, Subject: "dc-555", DisplayName: "victim",
	}); err != nil {
		t.Fatal(err)
	}
	taken.login(t, "github")
	takenLoc, takenBody := taken.linkCallback(t, "discord")

	// Arm 2 — generic failure: the same callback path, but the store fails for a
	// reason that has nothing to do with ownership.
	broken := newHarnessWithStore(t, mislinkingStore{
		MemoryStore: account.NewMemoryStore(),
		err:         errors.New("probe: identity store unavailable"),
	})
	broken.login(t, "github")
	brokenLoc, brokenBody := broken.linkCallback(t, "discord")

	// The two facts must produce the same outward result. Any difference in the
	// return URL is the oracle.
	if takenLoc != brokenLoc {
		t.Errorf("the link callback distinguishes the two facts:\n occupied identity: %q\n storage failure:   %q",
			takenLoc, brokenLoc)
	}
	if code := errorCodeOf(t, takenLoc); code != codeLinkFailed {
		t.Errorf("an identity owned by another account redirects with error=%q, want the unified %q",
			code, codeLinkFailed)
	}

	// Neither the URL nor the response body may carry the distinction — not the
	// old code and not the underlying store error.
	for _, leak := range []string{codeIdentityTaken, "probe: identity store unavailable"} {
		for _, got := range []struct{ loc, body string }{
			{takenLoc, takenBody}, {brokenLoc, brokenBody},
		} {
			if strings.Contains(got.loc, leak) || strings.Contains(got.body, leak) {
				t.Errorf("the link callback leaked %q: location=%q body=%q", leak, got.loc, got.body)
			}
		}
	}

	// The distinction is not destroyed, only moved server-side: the audit record
	// still says why the link was refused.
	if !hasAuditCode(taken.audit.Events(), codeIdentityTaken) {
		t.Errorf("the audit log no longer records %q for the occupied identity: %v",
			codeIdentityTaken, taken.audit.Events())
	}
	if !hasAuditCode(broken.audit.Events(), codeLinkFailed) {
		t.Errorf("the audit log no longer records %q for the storage failure: %v",
			codeLinkFailed, broken.audit.Events())
	}

	// And a successful link is still a success: the probe is not satisfied by a
	// flow that always reports an error.
	fresh := newHarness(t)
	fresh.login(t, "github")
	freshLoc, _ := fresh.linkCallback(t, "discord")
	if code := errorCodeOf(t, freshLoc); code != "" {
		t.Fatalf("linking a fresh identity reported error=%q (location %q)", code, freshLoc)
	}
}
