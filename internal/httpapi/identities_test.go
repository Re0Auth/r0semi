package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
)

// identityList returns the ids in GET /v1/identities, in order.
func identityList(t *testing.T, client *http.Client, base string) []string {
	t.Helper()
	resp := getURL(t, client, base+"/v1/identities")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/identities = %d", resp.StatusCode)
	}
	view := decodeResp(t, resp)
	items, ok := view["data"].([]any)
	if !ok {
		t.Fatalf("identities body has no data array: %v", view)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("identity entry is not an object: %v", item)
		}
		id, _ := entry["id"].(string)
		out = append(out, id)
	}
	return out
}

func csrfToken(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	view := decodeResp(t, getURL(t, client, base+"/v1/sessions/current"))
	token, _ := view["csrf_token"].(string)
	if token == "" {
		t.Fatal("no CSRF token in the session")
	}
	return token
}

func unlinkIdentity(t *testing.T, client *http.Client, base, id, csrf string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, base+"/v1/identities/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return doReq(t, client, req)
}

// The identity list is session-scoped: a downstream client must not be able to
// enumerate the user's login methods.
func TestIdentitiesRequireASession(t *testing.T) {
	base, _ := newFlowEnv(t)
	resp := getURL(t, newBrowser(t), base+"/v1/identities")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /v1/identities = %d, want 401", resp.StatusCode)
	}
}

// Unlinking removes one way in while keeping the account usable, and the store
// refuses to remove the last one.
func TestUnlinkIdentityKeepsTheAccount(t *testing.T) {
	base, accounts := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)
	ctx := context.Background()

	uid, err := accounts.FindByIdentity(ctx, idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	first := identityList(t, browser, base)
	if len(first) != 1 {
		t.Fatalf("identities = %v, want the one from sign-in", first)
	}

	// Link a second identity, as the link flow would.
	second, err := accounts.LinkIdentity(ctx, uid, idp.Identity{
		Provider: idp.Google, Subject: "go-1", DisplayName: "Octo Google",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := identityList(t, browser, base); len(got) != 2 {
		t.Fatalf("identities after link = %v, want two", got)
	}

	csrf := csrfToken(t, browser, base)

	// Removing the first one is allowed and leaves the account signed in.
	resp := unlinkIdentity(t, browser, base, first[0], csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unlink = %d, want 204", resp.StatusCode)
	}
	remaining := identityList(t, browser, base)
	if len(remaining) != 1 || remaining[0] != string(second.ID) {
		t.Fatalf("identities after unlink = %v, want just the linked one", remaining)
	}

	// The last identity is the account; I-2 says it cannot be removed.
	resp = unlinkIdentity(t, browser, base, string(second.ID), csrf)
	view := decodeResp(t, resp)
	if resp.StatusCode != http.StatusConflict || view["code"] != "last_identity" {
		t.Fatalf("unlink last = %d %v, want 409 last_identity", resp.StatusCode, view)
	}
	if got := identityList(t, browser, base); len(got) != 1 {
		t.Fatalf("the last identity was removed anyway: %v", got)
	}
}

// A write needs the CSRF token, and an unknown id is a 404 rather than a 403.
func TestUnlinkIdentityChecksCSRFAndExistence(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	ids := identityList(t, browser, base)

	resp := unlinkIdentity(t, browser, base, ids[0], "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlink without CSRF = %d, want 403", resp.StatusCode)
	}

	// Unknown id, with a valid CSRF token: the store reports not found, and the
	// account is untouched.
	csrf := csrfToken(t, browser, base)
	resp = unlinkIdentity(t, browser, base, "idn_does_not_exist", csrf)
	view := decodeResp(t, resp)
	if resp.StatusCode != http.StatusNotFound || view["code"] != "not_found" {
		t.Fatalf("unknown identity = %d %v, want 404 not_found", resp.StatusCode, view)
	}
	if got := identityList(t, browser, base); len(got) != 1 {
		t.Fatalf("a failed unlink changed the identities: %v", got)
	}
}

// The JSON shape of the list is the same Identity schema the session endpoint
// uses, so a client can share one parser.
func TestIdentitiesAndSessionAgree(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	session := decodeResp(t, getURL(t, browser, base+"/v1/sessions/current"))
	list := decodeResp(t, getURL(t, browser, base+"/v1/identities"))

	sessionIDs, _ := session["identities"].([]any)
	listIDs, _ := list["data"].([]any)
	if len(sessionIDs) != len(listIDs) {
		t.Fatalf("session has %d identities, list has %d", len(sessionIDs), len(listIDs))
	}
	// And the shapes carry the fields the frontend actually renders.
	first, _ := listIDs[0].(map[string]any)
	for _, key := range []string{"id", "provider", "display_name", "linked_at"} {
		if _, ok := first[key]; !ok {
			t.Errorf("identity is missing %q: %v", key, first)
		}
	}
	encoded, _ := json.Marshal(first)
	if len(encoded) == 0 {
		t.Fatal("identity did not encode")
	}
}
