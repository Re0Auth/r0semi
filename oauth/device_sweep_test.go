package oauth

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// S01-2 — MemoryDeviceStore has a reclaim path again.
//
// SaveDevice only ever inserts, so without a sweep the two maps hold every
// request the process ever started. SweepExpired is the same contract as
// MemoryStore.SweepExpired: it is called by the deployment's own loop, it drops
// expired records from both maps, and it reports how many it removed.
func TestS01_2SweepExpiredReclaimsExpiredDeviceRecords(t *testing.T) {
	store := NewMemoryDeviceStore()
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	const expiredRecords = 500
	for i := 0; i < expiredRecords; i++ {
		if err := store.SaveDevice(ctx, fmt.Sprintf("device-code-%03d", i), DeviceAuthorizationRecord{
			UserCode:  fmt.Sprintf("AAAA-%04d", i),
			ClientID:  "cli",
			Status:    DevicePending,
			ExpiresAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SaveDevice %d: %v", i, err)
		}
	}

	removed := store.SweepExpired(now)
	if removed != expiredRecords {
		t.Errorf("SweepExpired removed %d records, want %d", removed, expiredRecords)
	}

	store.mu.Lock()
	held := len(store.byDev)
	userIndexed := len(store.byUser)
	store.mu.Unlock()
	if held != 0 {
		t.Errorf("byDev holds %d expired records after the sweep, want 0", held)
	}
	if userIndexed != 0 {
		t.Errorf("byUser holds %d expired entries after the sweep, want 0", userIndexed)
	}

	// Positive control: a live record is untouched — it stays readable through
	// the public path and its user-code index survives, so the sweep is not
	// simply clearing the maps.
	const liveCode = "live-device-code"
	const liveUserCode = "ZZZZ-9999"
	if err := store.SaveDevice(ctx, liveCode, DeviceAuthorizationRecord{
		UserCode:  liveUserCode,
		ClientID:  "cli",
		Status:    DevicePending,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveDevice live: %v", err)
	}

	if removed := store.SweepExpired(now); removed != 0 {
		t.Errorf("SweepExpired removed %d live records, want 0", removed)
	}
	if _, err := store.GetDevice(ctx, liveCode); err != nil {
		t.Fatalf("a live device record was reclaimed by the sweep: %v", err)
	}
	if _, err := store.GetDeviceByUserCode(ctx, liveUserCode); err != nil {
		t.Fatalf("the live record's user-code index was dropped by the sweep: %v", err)
	}
	store.mu.Lock()
	held = len(store.byDev)
	userIndexed = len(store.byUser)
	store.mu.Unlock()
	if held != 1 || userIndexed != 1 {
		t.Errorf("after the live record, byDev=%d byUser=%d, want 1 and 1", held, userIndexed)
	}
}
