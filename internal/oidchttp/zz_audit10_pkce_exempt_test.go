package oidchttp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// This file pins the per-client PKCE exemption (allow_missing_pkce). The default is
// unchanged and pinned by TestAuthorizeRequiresPKCE / TestZZAudit_ConfidentialClientNeedsPKCE:
// a confidential client with no code_challenge is refused. These tests cover the one
// exception and prove it does not widen into anything else.

// An exempt client authorizes without a code_challenge, and the code it gets is
// redeemable with no code_verifier — the exemption has to work end to end, not just
// at the entrance.
func TestPKCEExemptClientAuthorizesWithoutPKCE(t *testing.T) {
	f := newFixture(t)

	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+url.Values{
		"response_type": {"code"},
		"client_id":     {f.exemptID},
		"redirect_uri":  {"https://client.example/cb"},
		"scope":         {"openid account.id"},
		"state":         {"pkce-exempt"},
		"nonce":         {"pkce-exempt-nonce"},
	}.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d, want a redirect to the login leg", resp.StatusCode)
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := login.Query().Get("error"); got != "" {
		t.Fatalf("exempt client was refused: error=%q (%s)", got, login)
	}
	handle := login.Query().Get("authRequestID")
	if handle == "" {
		t.Fatalf("exempt client did not reach the login leg: %s", login)
	}

	if err := f.store.CompleteLogin(t.Context(), handle, "usr_pkce_exempt", []string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = get(t, noRedirect, f.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(handle))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}

	// No code_verifier: the exemption exists precisely for clients that cannot send
	// one, so the exchange must not demand it.
	tokens, status := postToken(t, f.server.URL, f.exemptID, f.exemptSec, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://client.example/cb"},
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange without a verifier = %d %v", status, tokens)
	}
	if token, _ := tokens["access_token"].(string); token == "" {
		t.Fatalf("no access token: %v", tokens)
	}
}

// The exemption covers a missing code_challenge and nothing else: a challenge that
// is present still has to be S256 and well formed. Otherwise "allow missing PKCE"
// would quietly become "allow any PKCE".
func TestPKCEExemptClientStillNeedsS256(t *testing.T) {
	f := newFixture(t)
	cases := []url.Values{
		{"code_challenge_method": {"plain"}, "code_challenge": {strings.Repeat("c", 43)}},
		{"code_challenge_method": {"s256"}, "code_challenge": {strings.Repeat("c", 43)}},
		{"code_challenge_method": {"S256"}, "code_challenge": {"too-short"}},
	}
	for _, extra := range cases {
		q := url.Values{
			"response_type": {"code"},
			"client_id":     {f.exemptID},
			"redirect_uri":  {"https://client.example/cb"},
			"scope":         {"openid account.id"},
			"state":         {"pkce-exempt"},
		}
		for k, v := range extra {
			q[k] = v
		}
		resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+q.Encode())
		loc := resp.Header.Get("Location")
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("Location %q: %v", loc, err)
		}
		if resp.StatusCode != http.StatusFound || u.Query().Get("error") != "invalid_request" {
			t.Fatalf("a malformed PKCE challenge was accepted for an exempt client: %d %s", resp.StatusCode, loc)
		}
	}
}

// The exemption is a property of the registration, not of the request: the ordinary
// confidential client in the same deployment is still held to PKCE.
func TestPKCEExemptionIsPerClient(t *testing.T) {
	f := newFixture(t)
	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+url.Values{
		"response_type": {"code"},
		"client_id":     {f.webID},
		"redirect_uri":  {"https://client.example/cb"},
		"scope":         {"openid account.id"},
		"state":         {"pkce-required"},
	}.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("error_description"); !strings.Contains(got, "code_challenge") {
		t.Fatalf("a non-exempt client without PKCE was not refused for PKCE: %s", loc)
	}
}
