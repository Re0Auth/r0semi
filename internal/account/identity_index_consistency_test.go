package account

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
)

// assertIndexConsistent is a white-box invariant check: byUser must mirror the
// identities table exactly, for every user, with no duplicates, no dangling
// pointers and no empty keys.
func assertIndexConsistent(t *testing.T, s *MemoryStore) {
	t.Helper()

	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[IdentityID]UserID)
	for user, indexed := range s.byUser {
		if len(indexed) == 0 {
			t.Fatalf("byUser[%s] is an empty slice; the key should be absent", user)
		}
		for _, id := range indexed {
			if prev, dup := seen[id]; dup {
				t.Fatalf("identity %s indexed twice (users %s and %s)", id, prev, user)
			}
			seen[id] = user
			got, ok := s.identities[id]
			if !ok {
				t.Fatalf("byUser[%s] points at identity %s, which is not in the identities table", user, id)
			}
			if got.User != user {
				t.Fatalf("byUser[%s] points at identity %s owned by %s", user, id, got.User)
			}
		}
	}
	for id, got := range s.identities {
		user, ok := seen[id]
		if !ok {
			t.Fatalf("identity %s (user %s) is missing from byUser", id, got.User)
		}
		if user != got.User {
			t.Fatalf("identity %s indexed under %s, owned by %s", id, user, got.User)
		}
	}
}

func identIDs(list []Identity) []IdentityID {
	out := make([]IdentityID, len(list))
	for i, it := range list {
		out[i] = it.ID
	}
	return out
}

// forceLinkedAt pins an identity's LinkedAt so ordering assertions are
// deterministic rather than dependent on wall-clock resolution.
func forceLinkedAt(t *testing.T, s *MemoryStore, id IdentityID, at time.Time) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.identities[id]
	if !ok {
		t.Fatalf("forceLinkedAt: unknown identity %s", id)
	}
	it.LinkedAt = at
	s.identities[id] = it
}

// TestIdentitiesBehaviorEquivalence pins the observable behaviour across
// create/link/unlink/delete for several users at once: the returned set, the
// (LinkedAt, ID) ordering, and the untouched neighbours.
func TestIdentitiesBehaviorEquivalence(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	alice, a1, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-alice"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Google, "go-alice"))
	if err != nil {
		t.Fatal(err)
	}
	a3, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Discord, "gl-alice"))
	if err != nil {
		t.Fatal(err)
	}
	bob, b1, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-bob"))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := s.LinkIdentity(ctx, bob.ID, ident(idp.Google, "go-bob"))
	if err != nil {
		t.Fatal(err)
	}

	// a2 and a3 share a timestamp: the ID tiebreak must decide.
	forceLinkedAt(t, s, a1.ID, base)
	forceLinkedAt(t, s, a2.ID, base.Add(time.Minute))
	forceLinkedAt(t, s, a3.ID, base.Add(time.Minute))
	forceLinkedAt(t, s, b1.ID, base)
	forceLinkedAt(t, s, b2.ID, base.Add(time.Minute))

	wantAlice := []IdentityID{a1.ID, a2.ID, a3.ID}
	if a2.ID > a3.ID {
		wantAlice = []IdentityID{a1.ID, a3.ID, a2.ID}
	}
	list, err := s.Identities(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(identIDs(list)) != fmt.Sprint(wantAlice) {
		t.Fatalf("alice identities = %v, want %v", ids(list), wantAlice)
	}

	// Unlinking the middle identity keeps the remaining order and leaves bob alone.
	if err := s.UnlinkIdentity(ctx, alice.ID, a2.ID); err != nil {
		t.Fatal(err)
	}
	if list, err = s.Identities(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	wantAfter := []IdentityID{a1.ID, a3.ID}
	if fmt.Sprint(identIDs(list)) != fmt.Sprint(wantAfter) {
		t.Fatalf("alice identities after unlink = %v, want %v", ids(list), wantAfter)
	}
	if list, err = s.Identities(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != b1.ID || list[1].ID != b2.ID {
		t.Fatalf("bob identities = %v, want [%s %s]", ids(list), b1.ID, b2.ID)
	}
	assertIndexConsistent(t, s)

	// Deleting bob removes his identities and their lookup keys.
	if err := s.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Identities(ctx, bob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Identities on a deleted user = %v, want ErrNotFound", err)
	}
	if _, err := s.FindByIdentity(ctx, idp.Google, "go-bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted bob's identity is still resolvable: %v", err)
	}
	if recreated, _, err := s.CreateWithIdentity(ctx, ident(idp.Google, "go-bob")); err != nil || recreated.ID == bob.ID {
		t.Fatalf("recreating bob's identity = %+v, %v", recreated, err)
	}
	assertIndexConsistent(t, s)

	// Deleting an absent user stays idempotent.
	if err := s.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatalf("DeleteUser(absent) = %v, want nil", err)
	}
	assertIndexConsistent(t, s)

	// Alice is untouched by all of that.
	if list, err = s.Identities(ctx, alice.ID); err != nil || len(list) != 2 {
		t.Fatalf("alice identities = %v, %v", ids(list), err)
	}
	assertIndexConsistent(t, s)
}

// TestByUserIndexConsistency walks every mutation point and asserts the index
// mirrors the identities table: no leftovers, no gaps, no duplicates.
func TestByUserIndexConsistency(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	assertIndexConsistent(t, s)

	alice, a1, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-alice"))
	if err != nil {
		t.Fatal(err)
	}
	assertIndexConsistent(t, s)
	if got := len(s.byUser[alice.ID]); got != 1 {
		t.Fatalf("after CreateWithIdentity byUser[%s] has %d ids, want 1", alice.ID, got)
	}

	a2, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Google, "go-alice"))
	if err != nil {
		t.Fatal(err)
	}
	assertIndexConsistent(t, s)

	// Idempotent re-link must not duplicate the index entry.
	if _, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Google, "go-alice")); err != nil {
		t.Fatal(err)
	}
	assertIndexConsistent(t, s)
	if got := len(s.byUser[alice.ID]); got != 2 {
		t.Fatalf("idempotent re-link duplicated the index: byUser[%s] = %d ids", alice.ID, got)
	}

	// Errored mutations must leave the index untouched.
	if _, err := s.LinkIdentity(ctx, "usr_missing", ident(idp.Discord, "gl-x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link to unknown user = %v, want ErrNotFound", err)
	}
	assertIndexConsistent(t, s)

	// Adding a third identity, then unlinking it, must remove exactly one entry.
	a3, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Discord, "gl-alice"))
	if err != nil {
		t.Fatal(err)
	}
	assertIndexConsistent(t, s)
	if err := s.UnlinkIdentity(ctx, alice.ID, a3.ID); err != nil {
		t.Fatal(err)
	}
	assertIndexConsistent(t, s)
	for _, id := range s.byUser[alice.ID] {
		if id == a3.ID {
			t.Fatalf("byUser[%s] still lists unlinked identity %s", alice.ID, a3.ID)
		}
	}
	if got := len(s.byUser[alice.ID]); got != 2 {
		t.Fatalf("byUser[%s] has %d ids after unlink, want 2", alice.ID, got)
	}

	// Unlinking a foreign or unknown identity fails and must not touch the index.
	if err := s.UnlinkIdentity(ctx, alice.ID, "idn_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlink unknown identity = %v, want ErrNotFound", err)
	}
	assertIndexConsistent(t, s)

	// Unlinking down to the last identity reports ErrLastIdentity and leaves the
	// index intact.
	if err := s.UnlinkIdentity(ctx, alice.ID, a2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlinkIdentity(ctx, alice.ID, a1.ID); !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("unlink last identity = %v, want ErrLastIdentity", err)
	}
	assertIndexConsistent(t, s)
	if got := len(s.byUser[alice.ID]); got != 1 {
		t.Fatalf("byUser[%s] has %d ids after the ErrLastIdentity guard, want 1", alice.ID, got)
	}

	if err := s.DeleteUser(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.byUser[alice.ID]; ok {
		t.Fatalf("byUser[%s] survived DeleteUser", alice.ID)
	}
	assertIndexConsistent(t, s)
}

// TestConcurrentLinkUnlinkIndexRace mixes link/unlink writers with Identities
// readers. Under -race it must not panic or deadlock, and the index must still
// mirror the identities table afterwards.
func TestConcurrentLinkUnlinkIndexRace(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	user, root, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-root"))
	if err != nil {
		t.Fatal(err)
	}
	// root is a permanent identity, so unlink never trips I-2.

	const writers = 8
	const readers = 4
	const rounds = 25

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			provider := idp.Provider(fmt.Sprintf("prov-%d", w))
			for r := 0; r < rounds; r++ {
				linked, err := s.LinkIdentity(ctx, user.ID, ident(provider, fmt.Sprintf("sub-%d-%d", w, r)))
				if err != nil {
					t.Errorf("writer %d: LinkIdentity: %v", w, err)
					return
				}
				if err := s.UnlinkIdentity(ctx, user.ID, linked.ID); err != nil {
					t.Errorf("writer %d: UnlinkIdentity: %v", w, err)
					return
				}
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				list, err := s.Identities(ctx, user.ID)
				if err != nil {
					t.Errorf("reader %d: Identities: %v", r, err)
					return
				}
				found := false
				for _, it := range list {
					if it.ID == root.ID {
						found = true
					}
					if it.User != user.ID {
						t.Errorf("reader %d: foreign identity %s in result", r, it.ID)
						return
					}
				}
				if !found {
					t.Errorf("reader %d: root identity missing from Identities", r)
					return
				}
			}
		}(r)
	}
	wg.Wait()

	assertIndexConsistent(t, s)
	list, err := s.Identities(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != root.ID {
		t.Fatalf("after the race Identities = %v, want only %s", ids(list), root.ID)
	}
	if got := len(s.byUser[user.ID]); got != 1 {
		t.Fatalf("byUser[%s] has %d entries after the race, want 1", user.ID, got)
	}
}
