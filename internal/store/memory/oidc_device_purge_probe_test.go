package memory

// S13-2 probe: StoreDeviceAuthorization is reachable from the public
// POST /oauth/device_authorization, and it used to call
// purgeExpiredDevicesLocked unconditionally while holding the store's single
// global mutex. That made every public device-authorization request scan the
// whole devices map, so N requests inside the ten-minute window cost O(N²)
// locked work and stalled every other store call behind them.
//
// The fix drops the unconditional purge from that path and keeps only a targeted
// reclaim of the one record that would otherwise answer the request: a colliding,
// expired user_code. The full sweep stays with the janitor, SweepExpired. These
// tests pin both halves of that contract.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestStoreDeviceAuthorizationDoesNotSweepUnrelatedExpiredDevices(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	// A expires in ten minutes. B is long-lived: it has nothing to do with A's
	// deadline and must not be touched by an unrelated request.
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13a-device", "AAAA-0001",
		clock.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13b-device", "BBBB-0002",
		clock.Now().Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	clock.Advance(11 * time.Minute) // A is past its deadline; B is not.

	// A brand-new user_code arrives. On the old code this call ran the
	// unconditional purge and swept A as a side effect of an unrelated request.
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13c-device", "CCCC-0003",
		clock.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Counts().Devices; got != 3 {
		t.Fatalf("StoreDeviceAuthorization swept unrelated expired devices: Devices = %d, want 3 "+
			"(A is expired but must survive until the janitor runs)", got)
	}

	// The janitor is still what reclaims by deadline, and it removes exactly the
	// record whose deadline passed.
	if removed := store.SweepExpired(); removed != 1 {
		t.Fatalf("SweepExpired removed %d records, want 1 (only A)", removed)
	}
	if got := store.Counts().Devices; got != 2 {
		t.Fatalf("after SweepExpired Devices = %d, want 2", got)
	}
}

func TestExpiredUserCodeIsReusableOnCollision(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	expires := clock.Now().Add(10 * time.Minute)
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13d-device", "DDDD-0004",
		expires, []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	// While the record is live its user_code is taken, and the collision must be
	// reported rather than silently overwritten.
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13e-device", "DDDD-0004",
		expires, nil); !errors.Is(err, op.ErrDuplicateUserCode) {
		t.Fatalf("live collision = %v, want op.ErrDuplicateUserCode", err)
	}

	clock.Advance(11 * time.Minute)

	// Past the deadline the code is reusable: the colliding expired record and
	// its user_code entry are dropped, and the new device is stored. That is the
	// property the removed unconditional purge used to supply as a side effect.
	if err := store.StoreDeviceAuthorization(ctx, "cli", "s13f-device", "DDDD-0004",
		clock.Now().Add(10*time.Minute), nil); err != nil {
		t.Fatalf("expired user_code was not reusable: %v", err)
	}
	if got := store.Counts().Devices; got != 1 {
		t.Fatalf("Devices = %d, want 1 (the stale colliding record must have been dropped)", got)
	}
}
