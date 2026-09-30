package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// RFC 9700 §4.14.2: a refresh token presented after it was already rotated is
// itself the theft signal, so the AS revokes the whole token family rather than
// only refusing the value that was presented. Without the family rule the thief's
// already-rotated generation keeps minting access tokens for the rest of the
// 30-day refresh TTL, and the replay that detected the theft changes nothing.
func TestRefreshReplayRevokesTheWholeFamily(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	firstAccess, first, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	held, err := store.TokenRequestByRefreshToken(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	secondAccess, second, _, err := store.CreateAccessAndRefreshTokens(ctx, held, first)
	if err != nil {
		t.Fatalf("rotation was refused: %v", err)
	}

	// An unrelated family, so a pass cannot come from a store that refuses
	// everything: the revocation below must be scoped to the replayed family.
	_, other, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), "")
	if err != nil {
		t.Fatal(err)
	}

	// Precondition: the rotated replacement is live before any replay.
	if _, err := store.TokenRequestByRefreshToken(ctx, second); err != nil {
		t.Fatalf("the replacement refresh token was rejected before the replay: %v", err)
	}

	// The replay. It is refused, and the family — including the generation the
	// thief already rotated to — is revoked with it.
	if _, err := store.TokenRequestByRefreshToken(ctx, first); !errors.Is(err, ErrRefreshTokenSpent) {
		t.Fatalf("replay error = %v, want ErrRefreshTokenSpent", err)
	}
	if _, err := store.TokenRequestByRefreshToken(ctx, second); err == nil {
		t.Fatal("the replacement survived a detected replay: the token family was not revoked")
	}
	for _, id := range []string{firstAccess, secondAccess} {
		var introspect oidc.IntrospectionResponse
		if err := store.SetIntrospectionFromToken(ctx, &introspect, id, "usr_1", "cli"); err == nil {
			t.Errorf("access token %q survived the family revocation", id)
		}
	}

	// The other family is untouched.
	if _, err := store.TokenRequestByRefreshToken(ctx, other); err != nil {
		t.Fatalf("an unrelated family was revoked with the replayed one: %v", err)
	}
	// The family's tombstone went with it, because the family it named is gone.
	if c := store.Counts(); c.RefreshTokens != 1 || c.Tombstones != 0 {
		t.Fatalf("counts after the family revocation = %+v, want one live refresh token and no tombstones", c)
	}
}

// The tombstone rotation leaves is not immortal: it is swept on the spent token's
// own deadline, past which the value it stands for could not have been spent at
// all. This is what keeps a long-lived deployment from accumulating one residue
// record per rotation forever.
func TestRefreshTombstonesAreSweptOnTheSpentTokensDeadline(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	_, first, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	held, err := store.TokenRequestByRefreshToken(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, held, first); err != nil {
		t.Fatalf("rotation was refused: %v", err)
	}
	if c := store.Counts(); c.Tombstones != 1 || c.RefreshTokens != 1 {
		t.Fatalf("counts after a clean rotation = %+v, want one live refresh token and one tombstone", c)
	}

	// Two hours on: the access tokens are gone but the spent token's deadline
	// (and therefore the tombstone's) has not passed.
	clock.Advance(2 * time.Hour)
	store.SweepExpired()
	if c := store.Counts(); c.Tombstones != 1 || c.RefreshTokens != 1 {
		t.Fatalf("counts before the refresh deadline = %+v, want the tombstone and the replacement kept", c)
	}

	// Past the 30-day refresh TTL both are expired; the sweep reclaims the whole
	// family's residue.
	clock.Advance(31 * 24 * time.Hour)
	store.SweepExpired()
	if c := store.Counts(); c != (Counts{}) {
		t.Fatalf("counts after the sweep = %+v, want an empty store", c)
	}
}
