package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// audit9StoreWithCap builds a store whose tombstone map is bounded by cap.
func audit9StoreWithCap(t *testing.T, cap int) *OIDCStore {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:              clients,
		Registry:             oauth.DefaultRegistry(),
		Signer:               oidcstore.NewSigner("test", key),
		MaxRefreshTombstones: cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// AUDIT9 / S13-5 (fixed) — refresh-token tombstones are bounded.
//
// Every rotation writes one tombstone that lives until the SPENT token's expiry —
// 30 days by default — and rotation is the ordinary token-endpoint path, so the
// map used to grow without limit and every 5-minute sweep walked all of it under
// the store's single mutex. The map now holds at most MaxRefreshTombstones:
// replay detection stays exact for recent rotations and best-effort for the
// oldest, which is the documented trade.
func TestAudit9RefreshTombstonesAreBounded(t *testing.T) {
	const cap = 50
	store := audit9StoreWithCap(t, cap)
	ctx := context.Background()

	_, refresh, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), "")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	const rotations = cap * 3
	for i := 0; i < rotations; i++ {
		if _, refresh, _, err = store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), refresh); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}

	if got := store.Counts().Tombstones; got != cap {
		t.Errorf("tombstones after %d rotations = %d, want the %d-entry bound", rotations, got, cap)
	}
	// Inside the refresh TTL nothing is due, so the sweep must reclaim nothing.
	if removed := store.SweepExpired(); removed != 0 {
		t.Errorf("SweepExpired removed %d tombstones, want 0 inside the refresh TTL", removed)
	}
	// The bound survives the sweep.
	if got := store.Counts().Tombstones; got != cap {
		t.Errorf("tombstones after the sweep = %d, want %d", got, cap)
	}
}
