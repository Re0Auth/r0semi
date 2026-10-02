package oauth

import (
	"context"
	"testing"
	"time"
)

// S01-3 (P2): MemoryStore.ConsumeRefresh ignored a tombstone's own ExpiresAt.
//
// The tombstone contract (see refreshTombstone and the Store interface) says a
// spent refresh value's family stays reachable for at least the spent token's own
// lifetime — "at least", not "forever". After that deadline a replay could not
// have produced a usable token anyway, so presenting the value is an ordinary
// unknown token (ErrTokenNotFound / invalid_grant), NOT the theft signal that
// revokes the whole family. The PG store already filters on
// `expires_at > clock()`; the memory store never read the field, so a replay of a
// long-dead token revoked a family that had long since rotated past it.
//
// This drives the real service path, so it also proves the clock is injected: the
// store learns "now" only because NewService hands it the configured clock.
func TestReplayAfterTombstoneDeadlineDoesNotRevokeTheFamily(t *testing.T) {
	svc, clients, store, _, clock := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	const (
		redirect = "https://app.example/cb"
		verifier = "tombstone-verifier-tombstone-verifier-x"
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
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	// One rotation: `first` is spent and leaves a tombstone carrying its own
	// deadline (newTestAS uses RefreshTokenTTL = 24h).
	rotated, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}

	// Move past that deadline. The tombstone is now expired residue.
	clock.advance(24*time.Hour + time.Second)

	// The replay is still refused with the ordinary invalid_grant, but it must be
	// the unknown-value path, not the reuse-detection path.
	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken}); protocolCode(t, err) != "invalid_grant" {
		t.Fatalf("the stale replay answered %v, want invalid_grant", err)
	}

	// The decisive assertion: a dead tombstone must not revoke the live family.
	// At HEAD ConsumeRefresh returned the *RefreshReuseError unconditionally, the
	// service revoked the family, and this consume found the rotated generation
	// already deleted.
	if _, err := store.ConsumeRefresh(ctx, rotated.RefreshToken); err != nil {
		t.Fatalf("a replay past the tombstone deadline revoked the live family: %v", err)
	}
}
