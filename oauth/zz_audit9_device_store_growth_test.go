package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// AUDIT9 / S01-2 — MemoryDeviceStore never prunes, so device authorizations grow
// for the process lifetime.
//
// SaveDevice writes byDev and byUser and nothing in the package ever deletes from
// either map: there is no delete method, no expiry sweep, and no SweepExpired
// counterpart to MemoryStore.SweepExpired. Expiry is enforced only on READ, so an
// expired record stays resident forever. The store is what a no-database
// deployment uses for its device flow, so this is an unbounded growth path, not
// just a test fixture.
//
// Guard: pins the unbounded map. It fails once SaveDevice (or a sweep) reclaims
// expired rows, or once a deletion path exists that the test would have to model.
func TestAudit9MemoryDeviceStoreNeverReclaimsExpiredRecords(t *testing.T) {
	store := NewMemoryDeviceStore()
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)

	const records = 500
	for i := 0; i < records; i++ {
		code := fmt.Sprintf("device-code-%03d", i)
		rec := DeviceAuthorizationRecord{
			UserCode:  fmt.Sprintf("AAAA-%04d", i),
			ClientID:  "cli",
			Status:    DevicePending,
			ExpiresAt: expired,
		}
		if err := store.SaveDevice(ctx, code, rec); err != nil {
			t.Fatalf("SaveDevice %d: %v", i, err)
		}
	}

	// An expired record is still readable — the store does not treat expiry as a
	// reason to forget.
	rec, err := store.GetDevice(ctx, "device-code-000")
	if err != nil {
		t.Fatalf("an expired device record was reclaimed: %v", err)
	}
	if !rec.ExpiresAt.Before(time.Now()) {
		t.Fatal("the planted record is not expired; the setup is wrong")
	}

	store.mu.Lock()
	held := len(store.byDev)
	userIndexed := len(store.byUser)
	store.mu.Unlock()
	if held != records {
		t.Errorf("byDev holds %d of %d planted expired records, want all of them "+
			"(a prune/sweep would reclaim them)", held, records)
	}
	if userIndexed != records {
		t.Errorf("byUser holds %d of %d entries, want all of them", userIndexed, records)
	}
}
