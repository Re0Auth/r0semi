//go:build audit6

package z02protocoltoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// Z02-2 (FINDING) — RFC 7009 semantics at /oauth/revoke. An unknown token is
// 200 (idempotent success, required by §2.1), and an unauthenticated caller is
// 401. But a token that IS live and belongs to ANOTHER client answers 401
// invalid_client, which distinguishes it from the unknown-token 200: the
// endpoint is a liveness oracle for foreign tokens, reachable by any caller
// that can name a public client id (which the revocation endpoint accepts
// with no secret at all). oauth/as.go's Revoke comment claims the opposite of
// what both engines do ("answering 'that is not yours' would turn this
// endpoint into an oracle for whether a stolen string is a live token" —
// and invalid_client is exactly that answer).
func TestZ02RevocationDistinguishesForeignLiveTokensFromUnknownOnes(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	victim := asTokens(t, e.codeFlow(t, []string{"account.id"}))

	// Control 1: an unknown token is 200 (RFC 7009 §2.1 idempotence).
	resp, raw := e.postForm(t, "/oauth/revoke", form("token", "not-a-token-at-all"), e.narrowID, e.narrowSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an unknown token was not a 200: %d %s", resp.StatusCode, raw)
	}

	// Control 2: the owner revokes its own token — 200, and it works.
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", victim.AccessToken), e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's own revocation answered %d: %s", resp.StatusCode, raw)
	}
	// (The victim's token is now dead; mint a fresh one for the probe below.)
	victim = asTokens(t, e.codeFlow(t, []string{"account.id"}))

	// The finding: the narrow client presents the (live) web token.
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", victim.AccessToken), e.narrowID, e.narrowSec)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a foreign client's revocation of a live token was treated as success — the finding does not hold: %s", raw)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the foreign-live-token case answered %d, which the mechanism does not predict: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "invalid_client") {
		t.Errorf("the refusal is not invalid_client: %s", raw)
	}
	// And the token was NOT revoked by the refusal (the owner can still use it).
	if status, _ := e.userinfo(t, victim.AccessToken); status != http.StatusOK {
		t.Errorf("the refused revocation still killed the token: %d", status)
	}

	// The oracle needs no secret: a public client id, form-only, no Basic.
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token":     {victim.AccessToken},
		"client_id": {e.deviceID},
	}, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a public client's probe of a foreign live token answered %d, want the 401 that distinguishes it: %s",
			resp.StatusCode, raw)
	}
	// And the same shape with an unknown token is a 200, so the pair is a
	// binary oracle.
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token":     {"not-a-token-at-all"},
		"client_id": {e.deviceID},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a public client's probe of an unknown token answered %d, want the 200 that completes the oracle: %s",
			resp.StatusCode, raw)
	}
	t.Errorf("CONFIRMED: /oauth/revoke answers 401 invalid_client for a live foreign token and 200 for an unknown one, " +
		"so an anonymous caller that can name a public client id can test whether an arbitrary string is a live token " +
		"(of another client) — the liveness oracle oauth/as.go's comment says this endpoint must not be")

	// A wrong Basic secret is a 401 for a different reason (client auth), which
	// is indistinguishable from the oracle's answer — the shape is the same,
	// but at least it requires claiming a confidential id.
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", victim.AccessToken), e.webID, "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong secret was not refused: %d %s", resp.StatusCode, raw)
	}
}

// Z02-15 guards — RFC 7009 auth semantics: no credentials at all for a
// confidential-only revocation, unknown client ids, and the none/basic/post
// matrix the discovery advertises.
func TestZ02RevocationAuthMatrix(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	ctx := context.Background()
	tokens := asTokens(t, e.codeFlow(t, []string{"account.id"}))

	// No identity at all: refused.
	resp, raw := e.postForm(t, "/oauth/revoke", form("token", tokens.AccessToken), "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revocation with no identity answered %d: %s", resp.StatusCode, raw)
	}

	// Unknown client id: refused.
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", tokens.AccessToken), "no-such-client", "x")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revocation from an unknown client answered %d: %s", resp.StatusCode, raw)
	}

	// client_secret_basic and client_secret_post (both advertised) work; the
	// public none shape works with the form client_id.
	fresh := asTokens(t, e.codeFlow(t, []string{"account.id"}))
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", fresh.AccessToken), e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_basic revocation answered %d: %s", resp.StatusCode, raw)
	}
	fresh = asTokens(t, e.codeFlow(t, []string{"account.id"}))
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token": {fresh.AccessToken}, "client_id": {e.webID}, "client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_post revocation answered %d: %s", resp.StatusCode, raw)
	}
	if status, _ := e.userinfo(t, fresh.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("the posted-secret revocation did not take effect: %d", status)
	}
	fresh = asTokens(t, e.codeFlow(t, []string{"account.id"}))
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token": {fresh.AccessToken}, "client_id": {e.deviceID},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("none (public client) revocation answered %d: %s", resp.StatusCode, raw)
	}
	if status, _ := e.userinfo(t, fresh.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("the public client's revocation did not take effect: %d", status)
	}

	// A suspended client cannot revoke anything (client resolution fails).
	fresh = asTokens(t, e.codeFlow(t, []string{"account.id"}))
	if err := e.clients.SetStatus(ctx, e.webID, oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	resp, raw = e.postForm(t, "/oauth/revoke", form("token", fresh.AccessToken), e.webID, e.webSec)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a suspended client's revocation answered %d: %s", resp.StatusCode, raw)
	}
}

// Z02-16 guards — the AS engine's Revoke keeps the same ownership rule
// (b5f01da's sibling), and its refusal is the invalid_client protocol error
// rather than a bare 500.
func TestZ02ASEngineRevokeOwnership(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})
	svc := e.asEngine(t)
	ctx := context.Background()

	issued := asEngineToken(t, svc, e)
	if err := svc.Revoke(ctx, oauth.RevokeRequest{ClientID: e.narrowID, ClientSecret: e.narrowSec, Token: issued.AccessToken}); err == nil {
		t.Errorf("a client revoked another client's token through the AS engine")
	} else if oe, ok := err.(*oauth.Error); !ok || oe.Code != "invalid_client" {
		t.Errorf("the refusal is not invalid_client: %v", err)
	}
	if err := svc.Revoke(ctx, oauth.RevokeRequest{ClientID: "unknown-client", Token: issued.AccessToken}); err == nil {
		t.Errorf("an unknown client revoked a token through the AS engine")
	}
	if err := svc.Revoke(ctx, oauth.RevokeRequest{ClientID: e.webID, ClientSecret: e.webSec, Token: "not-a-token"}); err != nil {
		t.Errorf("an unknown token was not idempotent success: %v", err)
	}
	if err := svc.Revoke(ctx, oauth.RevokeRequest{ClientID: e.webID, ClientSecret: e.webSec, Token: issued.AccessToken}); err != nil {
		t.Fatalf("the owner's revocation failed: %v", err)
	}
	if info, err := svc.Introspect(ctx, issued.AccessToken); err != nil || info.Active {
		t.Errorf("the revoked token is still active: %+v", info)
	}
}

// asEngineToken drives the AS engine's own authorize+exchange for the web
// client and returns the token response.
func asEngineToken(t *testing.T, svc oauth.Service, e zoneEnv) oauth.TokenResponse {
	t.Helper()
	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authz, err := svc.Authorize(t.Context(), oauth.AuthorizationRequest{
		ClientID: e.webID, RedirectURI: "https://client.example/cb", Subject: "usr_z02",
		Scopes:              []oauth.Scope{oauth.ScopeAccountID},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.Exchange(t.Context(), oauth.CodeExchangeRequest{
		ClientID: e.webID, ClientSecret: e.webSec, Code: authz.Code,
		RedirectURI: "https://client.example/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
