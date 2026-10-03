//go:build audit5

package oauth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// R10-19: a grant revocation and an issuance are not serialized.
//
// RevokeGrant deletes by (subject, client) in its own call; issue writes the new
// access then the new refresh as two independent writes. A rotation that has
// already consumed its presented refresh token has nothing left for the
// revocation to delete, so a RevokeGrant landing between the claim and the mint
// reports success and then a live pair appears behind it. The same window exists
// for a code exchange and an approved device poll.
//
// gatedSaveStore parks the first armed SaveAccess, i.e. after ConsumeRefresh has
// retired the value and before either record of the new pair is written, so the
// window is entered by a handshake rather than by racing goroutines.

type gatedSaveStore struct {
	*MemoryStore

	arm     atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *gatedSaveStore) SaveAccess(ctx context.Context, value string, t AccessToken) error {
	if s.arm.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	return s.MemoryStore.SaveAccess(ctx, value, t)
}

func TestR1019RevokeGrantCannotLoseToAnInFlightRotation(t *testing.T) {
	svc, clients, store, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	ctx := context.Background()
	const (
		redirect = "https://app.example/cb"
		verifier = "r10-19-verifier-r10-19-verifier-x"
	)

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", ClientSecret: "s3cret", Code: auth.Code,
		RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	racing := &gatedSaveStore{
		MemoryStore: store,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	impl, ok := svc.(*service)
	if !ok {
		t.Fatalf("service is %T, want *service", svc)
	}
	impl.tokens = racing
	racing.arm.Store(true)

	type outcome struct {
		tok TokenResponse
		err error
	}
	rotating := make(chan outcome, 1)
	go func() {
		tok, err := svc.Refresh(ctx, RefreshRequest{
			ClientID: "app", ClientSecret: "s3cret", RefreshToken: first.RefreshToken,
		})
		rotating <- outcome{tok, err}
	}()

	select {
	case <-racing.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the rotation never reached its mint")
	}

	// The revocation runs while the rotation is between its claim and its mint.
	if err := svc.RevokeGrant(ctx, "usr_1", "app"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	close(racing.release)

	got := <-rotating
	if got.err != nil {
		// The fix: the issuance noticed the revocation and rolled its pair back.
		if info, ierr := svc.Introspect(ctx, got.tok.AccessToken); ierr == nil && info.Active {
			t.Fatalf("R10-19: issuance failed but left an active access token (%v)", got.err)
		}
		return
	}

	// No error: the issuance must not have left a live pair behind a revocation
	// that already reported success.
	if info, err := svc.Introspect(ctx, got.tok.AccessToken); err != nil || info.Active {
		if err == nil && info.Active {
			t.Fatalf("R10-19: RevokeGrant returned success, then the in-flight rotation minted an "+
				"access token that Introspect still reports Active (subject %q)", info.Subject)
		}
	}
	if _, err := store.ConsumeRefresh(ctx, got.tok.RefreshToken); err == nil {
		t.Fatal("R10-19: RevokeGrant returned success, then the in-flight rotation minted a refresh " +
			"token that is still redeemable")
	}
}
