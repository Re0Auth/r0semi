package oidchttp

import (
	"net/http"
	"net/url"
	"testing"
)

// The OIDF Basic OP plan's refresh module finishes with this check, word for word:
// "Attempting to use refresh_token issued to client 2 with client 1" must answer
// 400 invalid_grant (RFC 6749 §5.2, OIDCC-3.1.3.4). The suite's static-client setup
// needs two registered clients to exercise it; the conformance spike seeds one, so
// this pins the behaviour on the protocol plane itself.
func TestRefreshTokenIsBoundToItsClient(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{"openid", "account.id", "offline_access"})
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("the code flow issued no refresh token: %v", tokens)
	}

	// narrow is a different confidential client: its secret authenticates, but the
	// refresh token was issued to web.
	out, status := postToken(t, f.server.URL, f.narrowID, "nsecret", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("a foreign client refreshed another client's token: %d %v", status, out)
	}

	// The refusal must not have consumed the token: its owner can still rotate it.
	if _, status := postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}); status != http.StatusOK {
		t.Fatalf("the owner's refresh after a foreign attempt = %d", status)
	}
}
