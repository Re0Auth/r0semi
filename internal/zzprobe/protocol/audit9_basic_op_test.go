//go:build audit5

package protocol

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// AUDIT9 / S02-1 (fixed) — the end-to-end Basic OP half of the fix.
//
// A `prompt=login` request is carried into storage as `max_age=0` (the library's
// normalization). Before the fix, completing the consent decision overwrote
// `auth_time` with the decision clock, so the id_token advertised an
// authentication that never happened. Now: a request that asks for a fresh
// authentication cannot complete without one, a real re-authentication is what
// makes it completable, and the id_token carries THAT time.
//
// This is the closest thing the repository has to a local "Basic OP" conformance
// flow: authorize -> (login) -> complete -> callback -> token, over the real
// handler, asserting the issued id_token.
func TestAudit9PromptLoginRefusesToFabricateAuthTime(t *testing.T) {
	clock := newTestClock()
	e := newEnv(t, envOptions{issuer: "https://issuer.probe", now: clock.Now})
	ctx := t.Context()

	authz := authValues(e, "https://client.example/cb", []string{"openid", "account.id"})
	authz.Set("prompt", "login")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("prompt=login did not reach the login plane: %q", resp.Header.Get("Location"))
	}

	ar, err := e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	concrete, ok := ar.(*oidcstore.AuthRequest)
	if !ok {
		t.Fatalf("auth request type = %T, want *oidcstore.AuthRequest", ar)
	}
	if concrete.MaxAge == nil || *concrete.MaxAge != 0 {
		t.Fatalf("prompt=login did not survive the storage boundary as max_age=0: %+v", concrete)
	}

	// 1. No authentication has happened: the decision cannot complete the request,
	//    and must not invent an auth_time.
	if err := e.store.CompleteLogin(ctx, id, "usr_probe", []string{"openid", "account.id"}); !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
		t.Fatalf("CompleteLogin without a re-authentication = %v, want ErrReauthenticationRequired", err)
	}
	if after, err := e.store.AuthRequestByID(ctx, id); err == nil && after.Done() {
		t.Fatal("the refused request was marked done")
	}

	// 2. A real re-authentication (the IdP callback's SignIn) stamps a time; the
	//    request now completes and the id_token must carry that time, not the
	//    decision clock.
	authenticatedAt := clock.Now().Add(-5 * time.Second)
	if err := e.store.SetAuthTime(ctx, id, authenticatedAt); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CompleteLogin(ctx, id, "usr_probe", []string{"openid", "account.id"}); err != nil {
		t.Fatalf("CompleteLogin after a real authentication: %v", err)
	}

	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}
	tokens, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {strings.Repeat("v", 64)},
	})
	if status != http.StatusOK {
		t.Fatalf("token = %d: %v", status, tokens)
	}
	claims := idTokenClaims(t, asTokens(t, tokens).IDToken)
	raw, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("id_token has no auth_time: %v", claims)
	}
	if got := int64(raw); got != authenticatedAt.Unix() {
		t.Errorf("auth_time = %d, want the real authentication %d (the decision clock is %d)",
			got, authenticatedAt.Unix(), clock.Now().Unix())
	}
}

// The same boundary for `max_age=N`: a session outside the window cannot complete
// the request, one inside it can.
func TestAudit9MaxAgeWindowIsEnforcedEndToEnd(t *testing.T) {
	clock := newTestClock()
	e := newEnv(t, envOptions{issuer: "https://issuer.probe", now: clock.Now})
	ctx := t.Context()

	authz := authValues(e, "https://client.example/cb", []string{"account.id"})
	authz.Set("max_age", "60")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("max_age did not reach the login plane: %q", resp.Header.Get("Location"))
	}

	// Ten minutes old is outside a 60-second window.
	if err := e.store.SetAuthTime(ctx, id, clock.Now().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CompleteLogin(ctx, id, "usr_probe", []string{"account.id"}); !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
		t.Fatalf("max_age=60 with a 10-minute-old authentication = %v, want ErrReauthenticationRequired", err)
	}

	// Thirty seconds old is inside it.
	if err := e.store.SetAuthTime(ctx, id, clock.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CompleteLogin(ctx, id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatalf("max_age=60 with a 30-second-old authentication: %v", err)
	}
}
