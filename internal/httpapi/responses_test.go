package httpapi

import (
	"net/http"
	"testing"
)

// Every business-plane response is authenticated and per-person, so none of them
// may be cached — not by a shared cache in front of the deployment, and not by the
// browser.
//
// The two that made this concrete: the session bootstrap and the admin client list
// hand out a CSRF token, and the account export is the whole of somebody's account.
// Before this, only the protocol plane set `no-store`; the business plane set no
// Cache-Control at all, and there is no Vary either, so an intermediary had no key
// that distinguishes one account's response from another's.
func TestBusinessPlaneResponsesAreNotCached(t *testing.T) {
	base, browser, _, _, _, _, _ := newBindEnv(t)
	signIn(t, browser, base)

	for _, path := range []string{
		"/v1/sessions/current",
		"/v1/account/export",
		"/v1/identities",
		"/v1/grants",
		"/v1/bindings",
		"/v1/sources",
		"/v1/idp/providers",
	} {
		t.Run(path, func(t *testing.T) {
			resp := getURL(t, browser, base+path)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the assertion below needs a body to protect)", resp.StatusCode)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}
