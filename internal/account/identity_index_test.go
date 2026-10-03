package account

import (
	"context"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
)

// TestIdentitiesReadsOnlyTheUserIndex is the direct probe for the user→identity
// index (S03-7=A). It plants identities in the identities table that a
// legitimate index would not contain, and requires Identities to ignore them.
//
// A full-table scan (the old implementation) returns the planted identity; an
// index-only read cannot. The planted identity is deliberately the earliest one
// so a scanning implementation also reorders the result.
func TestIdentitiesReadsOnlyTheUserIndex(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	alice, first, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-alice"))
	if err != nil {
		t.Fatal(err)
	}

	ghost := Identity{
		ID:       "idn_ghost_of_alice",
		User:     alice.ID,
		Provider: idp.Google,
		Subject:  "go-ghost-alice",
		LinkedAt: first.LinkedAt.Add(-time.Hour), // earliest: would sort first
	}
	s.mu.Lock()
	s.identities[ghost.ID] = ghost
	s.mu.Unlock()

	list, err := s.Identities(ctx, alice.ID)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("Identities returned %d identities, want 1: %v", len(list), ids(list))
	}
	if list[0].ID == ghost.ID {
		t.Fatalf("Identities returned %q, which is absent from the user index: it scanned the whole table", ghost.ID)
	}

	// A ghost owned by a different user must not leak into this user's list.
	bob, _, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-bob"))
	if err != nil {
		t.Fatal(err)
	}
	otherGhost := Identity{
		ID:       "idn_ghost_of_bob",
		User:     bob.ID,
		Provider: idp.Google,
		Subject:  "go-ghost-bob",
		LinkedAt: first.LinkedAt.Add(-2 * time.Hour),
	}
	s.mu.Lock()
	s.identities[otherGhost.ID] = otherGhost
	s.mu.Unlock()

	list, err = s.Identities(ctx, alice.ID)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(list) != 1 || list[0].ID != first.ID {
		t.Fatalf("Identities = %v, want just %q", ids(list), first.ID)
	}
}

func ids(list []Identity) []IdentityID {
	out := make([]IdentityID, len(list))
	for i, it := range list {
		out[i] = it.ID
	}
	return out
}
