package oauth

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// A memory store with no database behind it holds every token it ever issued
// until something removes the expired ones. Expiry on read makes them unusable;
// only the sweep makes them gone.
func TestMemoryStoreSweepExpired(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	if err := store.SaveCode(ctx, "live-code", AuthorizationCode{ClientID: "cli", Subject: "usr_1", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCode(ctx, "dead-code", AuthorizationCode{ClientID: "cli", Subject: "usr_1", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccess(ctx, "live-at", AccessToken{ClientID: "cli", Subject: "usr_1", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccess(ctx, "dead-at", AccessToken{ClientID: "cli", Subject: "usr_1", ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefresh(ctx, "dead-rt", RefreshToken{ClientID: "cli", Subject: "usr_1", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	if removed := store.SweepExpired(now); removed != 3 {
		t.Fatalf("swept %d records, want the three expired ones", removed)
	}
	// A live record survives: the sweep must never remove something a lookup would
	// still accept.
	if _, err := store.GetAccess(ctx, "live-at"); err != nil {
		t.Fatalf("the sweep removed a live access token: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, "live-code"); err != nil {
		t.Fatalf("the sweep removed a live code: %v", err)
	}
	if removed := store.SweepExpired(now); removed != 0 {
		t.Fatalf("a second sweep removed %d more", removed)
	}
}

// The sweep is the only thing bounding the maps, so it has to keep up with the
// pattern that grows them: issue, expire, issue again.
func TestMemoryStoreSweepKeepsTheMapsBounded(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 100; i++ {
		issued := now.Add(time.Duration(i) * time.Second)
		if err := store.SaveAccess(ctx, "at-"+strconv.Itoa(i), AccessToken{
			ClientID: "cli", Subject: "usr_1",
			IssuedAt: issued, ExpiresAt: issued.Add(time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		store.SweepExpired(issued.Add(2 * time.Second))
	}
	store.mu.Lock()
	held := len(store.access)
	store.mu.Unlock()
	if held > 1 {
		t.Fatalf("the store holds %d access tokens, want at most the live one", held)
	}
}
