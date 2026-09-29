//go:build audit6

package z02protocoltoken

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Z02-13 (regression, P0-2 fix) — userinfo is a protected resource whose
// bearer must be a LIVE access token of this OP. Expired, revoked, and
// wrong-shaped bearers are all refused with 401 invalid_token, and the
// three-segment JWT shape (an id_token, the one this OP hands every RP) is
// refused on sight through every way a bearer can arrive.
func TestZ02UserinfoRequiresALiveAccessToken(t *testing.T) {
	clock := newTestClock()
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02", now: clock.Now})

	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatal("the fixture issued no access token / id_token")
	}

	// Control: the live token answers sub and nothing else.
	status, claims := e.userinfo(t, tokens.AccessToken)
	if status != http.StatusOK || claims["sub"] != "usr_z02" {
		t.Fatalf("control failed: %d %v", status, claims)
	}
	if len(claims) != 1 {
		t.Fatalf("userinfo leaked claims: %v", claims)
	}

	// The id_token as a bearer, through the Authorization header.
	status, _ = e.userinfo(t, tokens.IDToken)
	if status != http.StatusUnauthorized {
		t.Errorf("the id_token was accepted as a bearer: %d", status)
	}

	// The id_token through the access_token form parameter on a GET (the
	// query string folds into r.Form, the same set the boundary check reads).
	req, err := http.NewRequest(http.MethodGet,
		e.server.URL+"/oauth/userinfo?"+url.Values{"access_token": {tokens.IDToken}}.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		body := bodyOf(t, resp)
		t.Errorf("the id_token in the query string was accepted: %d %s", resp.StatusCode, body)
	}

	// The id_token through the access_token form parameter on a POST.
	resp, raw := e.postForm(t, "/oauth/userinfo", url.Values{"access_token": {tokens.IDToken}}, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the id_token in a POST body was accepted: %d %s", resp.StatusCode, raw)
	}

	// A five-segment garbage JWE and other shapes a caller can type.
	for _, bearer := range []string{
		"AAAA.BBBB.CCCC.DDDD.EEEE", // compact JWE shape, wrong content
		"one.two.three.four",       // four segments
		"a.b.c.d.e.f",
		"............................................",
		tokens.RefreshToken, // a refresh token is not an access token
		"",
	} {
		status, _ := e.userinfo(t, bearer)
		if status != http.StatusUnauthorized {
			t.Errorf("bearer %q was accepted: %d", truncate(bearer), status)
		}
	}

	// Expired: refused (the store's row is judged by the clock).
	clock.Advance(2 * time.Hour)
	status, _ = e.userinfo(t, tokens.AccessToken)
	if status != http.StatusUnauthorized {
		t.Errorf("an expired access token was accepted: %d", status)
	}
	clock.Advance(-2 * time.Hour)

	// Revoked: refused.
	fresh := asTokens(t, e.codeFlow(t, []string{"account.id"}))
	if _, raw := e.postForm(t, "/oauth/revoke", url.Values{"token": {fresh.AccessToken}}, e.webID, e.webSec); true {
		_ = raw
	}
	if status, _ := e.userinfo(t, fresh.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("a revoked access token was accepted: %d", status)
	}

	// An access token from a different deployment (another token key) —
	// refused, and the refusal shape carries the RFC 6750 challenge.
	var otherKey [32]byte
	copy(otherKey[:], []byte("other-0123456789abcdef0123456789a"))
	other := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	otherTokens := asTokens(t, other.codeFlow(t, []string{"account.id"}))
	req, err = http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+otherTokens.AccessToken)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a foreign deployment's token was accepted: %d", resp.StatusCode)
	}
	if !strings.HasPrefix(challenge, "Bearer") || !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("userinfo 401 challenge = %q", challenge)
	}
	_ = bodyOf(t, resp)
}

// Z02-14 guards — userinfo answers for a token that never asked for openid
// (the documented O-3 judgement), and only for sub; the scope field of the
// token does not gate the endpoint, but nothing beyond sub is ever returned.
func TestZ02UserinfoWithoutOpenIDReturnsOnlySub(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "phigros.score.read"}))
	if tokens.IDToken != "" {
		t.Fatalf("O-2 is broken before userinfo is reached: an id_token came back without openid")
	}
	status, claims := e.userinfo(t, tokens.AccessToken)
	if status != http.StatusOK || claims["sub"] != "usr_z02" {
		t.Fatalf("userinfo refused a non-openid token: %d %v", status, claims)
	}
	if len(claims) != 1 {
		t.Fatalf("userinfo leaked claims: %v", claims)
	}
}
