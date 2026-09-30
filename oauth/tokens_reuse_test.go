package oauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// These are the MemoryStore half of the RFC 9700 §4.14.2 contract: rotation has to
// leave a family trace, a replay has to be distinguishable from a value that was
// never issued, and the family revocation has to remove every generation.

// tombstoneCount reads the tombstone map under the store's lock, so a test never
// races the store's own discipline.
func tombstoneCount(s *MemoryStore) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tombstones)
}

// consumeAndReplay is the core shape: a live token is consumed once (rotation
// retires it), and presenting the same value again is a reuse, not an unknown.
func TestMemoryStoreReplayReportsReuseNotUnknown(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	expiry := time.Unix(1_700_000_000, 0).Add(time.Hour)

	if err := store.SaveRefresh(ctx, "rt", RefreshToken{
		ClientID: "cli", Subject: "usr_1", FamilyID: "fam-1", ExpiresAt: expiry,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := store.ConsumeRefresh(ctx, "rt")
	if err != nil {
		t.Fatal(err)
	}
	if got.FamilyID != "fam-1" {
		t.Fatalf("consumed record lost its family: %+v", got)
	}

	_, err = store.ConsumeRefresh(ctx, "rt")
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("replay = %v, want ErrRefreshTokenReused", err)
	}
	var reuse *RefreshReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("replay = %T, want *RefreshReuseError", err)
	}
	if reuse.FamilyID != "fam-1" {
		t.Fatalf("reuse carries family %q, want fam-1", reuse.FamilyID)
	}
	// The sentinel must not be what "never issued" reports, or the caller cannot
	// tell a theft from a typo.
	if _, err := store.ConsumeRefresh(ctx, "never-issued"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("unknown value = %v, want ErrTokenNotFound", err)
	}
	if errors.Is(ErrTokenNotFound, ErrRefreshTokenReused) {
		t.Fatal("the two sentinels are not distinct")
	}
}

// RevokeRefreshFamily has to remove every generation of the chain: the live
// refresh record, the access record it was minted with, and the tombstone of the
// generation that was already spent. It must also leave every other family alone.
func TestMemoryStoreRevokeRefreshFamilyKillsEveryGeneration(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	expiry := time.Unix(1_700_000_000, 0).Add(time.Hour)

	save := func(value, family string) {
		t.Helper()
		if err := store.SaveRefresh(ctx, value, RefreshToken{
			ClientID: "cli", Subject: "usr_1", FamilyID: family, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveAccess(ctx, "at-"+value, AccessToken{
			ClientID: "cli", Subject: "usr_1", FamilyID: family, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The first generation is spent, leaving a tombstone.
	save("gen1", "fam-1")
	if _, err := store.ConsumeRefresh(ctx, "gen1"); err != nil {
		t.Fatal(err)
	}
	// The thief's replacement, same family.
	save("gen2", "fam-1")
	// An unrelated grant, same client and subject, different family.
	save("other", "fam-2")

	removed, err := store.RevokeRefreshFamily(ctx, "fam-1")
	if err != nil {
		t.Fatal(err)
	}
	// gen2's refresh + access and gen1's access: the tombstone is residue, not a
	// token record, so it does not inflate the count.
	if removed != 3 {
		t.Fatalf("revoked %d records, want 3 (two refresh generations' access and gen2's refresh)", removed)
	}
	if _, err := store.ConsumeRefresh(ctx, "gen2"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("the thief's generation survived: %v", err)
	}
	for _, value := range []string{"at-gen1", "at-gen2"} {
		if _, err := store.GetAccess(ctx, value); !errors.Is(err, ErrTokenNotFound) {
			t.Errorf("%s survived the family revocation: %v", value, err)
		}
	}
	if tombstoneCount(store) != 0 {
		t.Errorf("the family's tombstone survived: %d left", tombstoneCount(store))
	}

	// No over-revocation: the neighbouring family is intact.
	if _, err := store.ConsumeRefresh(ctx, "other"); err != nil {
		t.Fatalf("an unrelated family was revoked: %v", err)
	}
	if _, err := store.GetAccess(ctx, "at-other"); err != nil {
		t.Fatalf("an unrelated family's access token was revoked: %v", err)
	}

	// Idempotent, and a second call removes nothing.
	if again, err := store.RevokeRefreshFamily(ctx, "fam-1"); err != nil || again != 0 {
		t.Fatalf("second revocation = %d, %v; want 0, nil", again, err)
	}
}

// An empty family id is what a caller has when the tombstone was malformed or the
// record predates the family column. It must never be read as "all".
func TestMemoryStoreRevokeEmptyFamilyRevokesNothing(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	expiry := time.Unix(1_700_000_000, 0).Add(time.Hour)
	for _, family := range []string{"", "fam-1"} {
		value := "rt-" + family
		if err := store.SaveRefresh(ctx, value, RefreshToken{
			ClientID: "cli", Subject: "usr_1", FamilyID: family, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveAccess(ctx, "at-"+value, AccessToken{
			ClientID: "cli", Subject: "usr_1", FamilyID: family, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.RevokeRefreshFamily(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("an empty family revoked %d records; it must revoke nothing", removed)
	}
	for _, family := range []string{"", "fam-1"} {
		if _, err := store.ConsumeRefresh(ctx, "rt-"+family); err != nil {
			t.Fatalf("family %q was revoked by an empty-id call: %v", family, err)
		}
	}
}

// The tombstone map is the only unbounded growth this rule adds, so the sweep has
// to reclaim it on the spent token's own deadline — and only then.
func TestMemoryStoreSweepReclaimsExpiredTombstones(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	if err := store.SaveRefresh(ctx, "rt", RefreshToken{
		ClientID: "cli", Subject: "usr_1", FamilyID: "fam-1", ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, "rt"); err != nil {
		t.Fatal(err)
	}
	if tombstoneCount(store) != 1 {
		t.Fatal("rotation left no tombstone to sweep")
	}

	// Before the deadline the tombstone survives, so a replay is still detected.
	if removed := store.SweepExpired(now); removed != 0 {
		t.Fatalf("the sweep removed %d records before their deadline", removed)
	}
	if _, err := store.ConsumeRefresh(ctx, "rt"); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("the live-window replay = %v, want ErrRefreshTokenReused", err)
	}

	// Past it the tombstone goes, and with it the now-pointless replay signal.
	if removed := store.SweepExpired(now.Add(2 * time.Minute)); removed != 1 {
		t.Fatalf("the sweep removed %d records, want the expired tombstone", removed)
	}
	if tombstoneCount(store) != 0 {
		t.Fatal("an expired tombstone survived the sweep")
	}
	if _, err := store.ConsumeRefresh(ctx, "rt"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("after the tombstone's deadline = %v, want ErrTokenNotFound", err)
	}
}

// The lifecycle paths revoke by owner, so the tombstones they match have to carry
// the owner fields and go with the live rows.
func TestMemoryStoreLifecycleClearsMatchingTombstones(t *testing.T) {
	ctx := context.Background()
	expiry := time.Unix(1_700_000_000, 0).Add(time.Hour)

	spend := func(t *testing.T, store *MemoryStore, value, client, subject string) {
		t.Helper()
		if err := store.SaveRefresh(ctx, value, RefreshToken{
			ClientID: client, Subject: subject, FamilyID: "fam-" + value, ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConsumeRefresh(ctx, value); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("DeleteBySubjectClient", func(t *testing.T) {
		store := NewMemoryStore()
		spend(t, store, "mine", "cli_a", "usr_1")
		spend(t, store, "theirs", "cli_b", "usr_1")
		spend(t, store, "elsewhere", "cli_a", "usr_2")

		if err := store.DeleteBySubjectClient(ctx, "usr_1", "cli_a"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConsumeRefresh(ctx, "mine"); !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("the revoked grant's tombstone survived: %v", err)
		}
		for _, value := range []string{"theirs", "elsewhere"} {
			if _, err := store.ConsumeRefresh(ctx, value); !errors.Is(err, ErrRefreshTokenReused) {
				t.Fatalf("%s's tombstone was removed by an unrelated revocation: %v", value, err)
			}
		}
	})

	t.Run("RevokeTokens", func(t *testing.T) {
		store := NewMemoryStore()
		spend(t, store, "mine", "cli_a", "usr_1")
		spend(t, store, "theirs", "cli_b", "usr_1")
		spend(t, store, "elsewhere", "cli_a", "usr_2")

		if _, err := store.RevokeTokens(ctx, TokenFilter{Subject: "usr_1"}); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"mine", "theirs"} {
			if _, err := store.ConsumeRefresh(ctx, value); !errors.Is(err, ErrTokenNotFound) {
				t.Fatalf("the subject's revoked tombstone %s survived: %v", value, err)
			}
		}
		if _, err := store.ConsumeRefresh(ctx, "elsewhere"); !errors.Is(err, ErrRefreshTokenReused) {
			t.Fatalf("another subject's tombstone was removed by the Kill Switch: %v", err)
		}
	})
}

// Deleting a spent value explicitly (RFC 7009 on a token already rotated) says the
// replay signal is no longer wanted; the tombstone goes with the row.
func TestMemoryStoreDeleteRefreshClearsItsTombstone(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.SaveRefresh(ctx, "rt", RefreshToken{
		ClientID: "cli", Subject: "usr_1", FamilyID: "fam-1",
		ExpiresAt: time.Unix(1_700_000_000, 0).Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, "rt"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRefresh(ctx, "rt"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, "rt"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("after DeleteRefresh = %v, want ErrTokenNotFound", err)
	}
}
