//go:build audit5

package oauth

import (
	"context"
	"testing"
	"time"
)

func TestZZProbeDeviceCodeRepeatMint(t *testing.T) {
	svc, clients, store, _, clock := newTestAS(t)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_1", true, nil, nil); err != nil {
		t.Fatal(err)
	}

	clock.advance(6 * time.Second)
	tok1, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	clock.advance(6 * time.Second)
	tok2, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	t.Logf("second exchange: err=%v token=%q first=%q", err, tok2.AccessToken, tok1.AccessToken)

	clock.advance(6 * time.Second)
	removed, err := store.RevokeTokens(ctx, TokenFilter{})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(6 * time.Second)
	tok3, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
	t.Logf("after RevokeTokens removed=%d: err=%v token=%q", removed, err, tok3.AccessToken)
	info, ierr := svc.Introspect(ctx, tok3.AccessToken)
	t.Logf("introspect post-revocation: err=%v active=%v subject=%s", ierr, info.Active, info.Subject)
}

// A wrong client's refresh attempt must be refused WITHOUT spending the owner's
// token, and the owner's own refresh must still succeed afterwards.
//
// The finding's shape was the same as KIT-4: ConsumeRefresh ran before the client
// binding was judged, so merely presenting somebody else's refresh token ended
// their session — the DoS was the refusal's side effect. The ownership pre-check
// (service.Refresh calls TokenOwner before ConsumeRefresh) is what makes this a
// guard rather than a log line; it is asserted here, not merely printed.
func TestZZProbeRefreshNotBurnedByWrongClient(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "a", ClientConfidential, "sa", []Scope{ScopeAccountID})
	registerClient(t, clients, "b", ClientConfidential, "sb", []Scope{ScopeAccountID})
	ctx := context.Background()
	at, err := svc.Authorize(ctx, AuthorizationRequest{ClientID: "a", RedirectURI: "https://app.example/cb", Subject: "usr_1", Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge("v1-verifier-v1-verifier-v1-verifier"), CodeChallengeMethod: "S256"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{ClientID: "a", ClientSecret: "sa", Code: at.Code, RedirectURI: "https://app.example/cb", CodeVerifier: "v1-verifier-v1-verifier-v1-verifier"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "b", ClientSecret: "sb", RefreshToken: tok.RefreshToken})
	if err == nil {
		t.Fatal("a client refreshed a token issued to another client")
	}
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("cross-client refresh code = %q, want invalid_grant", got)
	}

	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "a", ClientSecret: "sa", RefreshToken: tok.RefreshToken}); err != nil {
		t.Fatalf("the wrong client's attempt burned the owner's refresh token: %v", err)
	}
}
