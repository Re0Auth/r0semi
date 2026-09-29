//go:build audit6

package z05memstore

// Falsification probes for finding 05-4 (cloneAuthRequest still shares the
// CodeChallenge pointer with the stored record). Two directions:
//
//   - REACHABILITY: drive the whole production authorization-code leg through
//     the real entrances (authorize -> consent write -> provider callback ->
//     token) and show that nothing on that leg writes through the shared
//     pointer: the stored challenge is byte-identical to what the entrance
//     accepted, PKCE is enforced, and the honest verifier redeems while a
//     wrong one is refused. This is the claim "no production writer exists"
//     made executable.
//   - THE MECHANISM AT ITS POINT OF IMPACT: a caller that DOES write through
//     the pointer the consent read path hands out steers which verifier the
//     token endpoint's PKCE check accepts — the crafted verifier mints and
//     the honest one is locked out, both through the real token endpoint.
//
// The probe itself acts as the hypothetical write-through caller (nothing in
// production does; that is what the reachability half shows). Both probes are
// red today and turn green when the clone becomes deep.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// rev4Authorize drives the production authorization-code leg up to the code:
// the real authorize entrance with an S256 PKCE challenge, the consent write
// (CompleteLogin — the storage call ApproveAuthorization makes), and the
// provider callback that mints the code. Returns the request id and the code.
func rev4Authorize(t *testing.T, e *env, verifier string) (id, code string) {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {"openid account.id offline_access"},
		"state":                 {"rev4-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := e.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), "")
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize entrance = %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?authRequestID=") {
		t.Fatalf("authorize redirected to %q, expected the login leg", loc)
	}
	id = strings.TrimPrefix(loc, "/login?authRequestID=")

	if err := e.store.CompleteLogin(context.Background(), id, "usr_probe",
		[]string{"openid", "account.id", "offline_access"}); err != nil {
		t.Fatalf("the consent write failed: %v", err)
	}

	rec = e.do(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), "")
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb := rec.Header().Get("Location")
	u, err := url.Parse(cb)
	if err != nil {
		t.Fatalf("callback redirect %q does not parse: %v", cb, err)
	}
	if code = u.Query().Get("code"); code == "" {
		t.Fatalf("callback redirect %q carries no code", cb)
	}
	return id, code
}

// rev4Redeem exchanges an authorization code at the real token endpoint.
func rev4Redeem(e *env, code, verifier string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {probeRedirect},
		"client_id":     {probeClientID},
		"code_verifier": {verifier},
	}.Encode()
	return e.do(http.MethodPost, "/oauth/token", form)
}

// TestRev4TheProductionChainNeverWritesThroughTheSharedChallenge is the
// reachability half: the full leg mints for the honest verifier, refuses a
// wrong one, and the stored challenge is still the entrance's value.
func TestRev4TheProductionChainNeverWritesThroughTheSharedChallenge(t *testing.T) {
	e := newEnv(t, nil)

	honest := strings.Repeat("v", 64)
	id, code := rev4Authorize(t, e, honest)

	// The stored challenge is still the entrance's value: the challenge the
	// consent read path hands out is byte-identical to the S256 of the
	// honest verifier, so no production step rewrote it through the pointer.
	clone, err := e.store.AuthRequestByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ch := clone.GetCodeChallenge()
	if ch == nil {
		t.Fatal("the clone carries no challenge; the reachability probe measured nothing")
	}
	sum := sha256.Sum256([]byte(honest))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); ch.Challenge != want || ch.Method != oidc.CodeChallengeMethodS256 {
		t.Fatalf("the stored challenge drifted from the entrance's value: %q (method %v)", ch.Challenge, ch.Method)
	}

	if rec := rev4Redeem(e, code, honest); rec.Code != http.StatusOK {
		t.Fatalf("the honest verifier was refused: %d %s (the leg does not work in this fixture)", rec.Code, rec.Body.String())
	}

	// PKCE is actually enforced at this endpoint: a wrong verifier with its
	// own code is refused — otherwise the alias probe below measures nothing.
	_, code2 := rev4Authorize(t, e, strings.Repeat("w", 64))
	if rec := rev4Redeem(e, code2, strings.Repeat("x", 64)); rec.Code == http.StatusOK {
		t.Fatal("a wrong code_verifier redeemed: PKCE is not enforced in this fixture")
	}
}

// TestRev4AWriteThroughTheSharedChallengeSteersPKCE is the impact half: a
// write through the pointer the consent read path (AuthRequestByID) hands out
// replaces the challenge the token endpoint's PKCE check judges.
func TestRev4AWriteThroughTheSharedChallengeSteersPKCE(t *testing.T) {
	const crafted = "rev4-rewritten-by-a-caller-0000000000000000000000"

	// The crafted verifier mints through the real entrance.
	e := newEnv(t, nil)
	id, code := rev4Authorize(t, e, strings.Repeat("v", 64))

	clone, err := e.store.AuthRequestByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ch := clone.GetCodeChallenge()
	if ch == nil {
		t.Fatal("the clone carries no challenge; the probe measured nothing")
	}
	ch.Challenge = crafted
	ch.Method = oidc.CodeChallengeMethodPlain

	if rec := rev4Redeem(e, code, crafted); rec.Code == http.StatusOK {
		t.Errorf("a write through the AuthRequestByID clone's CodeChallenge pointer steered the token endpoint's " +
			"PKCE check: the crafted verifier minted a token through the real entrance — the shared pointer is " +
			"exactly the value the code exchange judges (finding 05-4's mechanism, end to end)")
	}

	// The flip side, on its own chain (a failed exchange burns the code):
	// the honest verifier is locked out by the same rewrite.
	e2 := newEnv(t, nil)
	honest := strings.Repeat("y", 64)
	id2, code2 := rev4Authorize(t, e2, honest)

	clone2, err := e2.store.AuthRequestByID(context.Background(), id2)
	if err != nil {
		t.Fatal(err)
	}
	ch2 := clone2.GetCodeChallenge()
	if ch2 == nil {
		t.Fatal("the clone carries no challenge; the flip-side probe measured nothing")
	}
	ch2.Challenge = crafted
	ch2.Method = oidc.CodeChallengeMethodPlain

	if rec := rev4Redeem(e2, code2, honest); rec.Code != http.StatusOK {
		t.Errorf("the honest verifier was locked out by a write through the shared challenge pointer: %d — the "+
			"rewrite of the aliased value is what PKCE judged, not the entrance's challenge", rec.Code)
	}
}
