package memory

// A device decision is a state transition, not an assignment. The caller (the OP
// library and the verification page) reads the state before writing, but the read
// and the write are separate steps, so the write carries its own conditions —
// still pending, not denied, not expired. Round 3 recorded the unconditional
// write as C3-3 (docs/security-audit-3.md); these tests pin the predicate.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/oauth"
)

func pendingDevice(t *testing.T, store *OIDCStore, code string, ttl time.Duration) {
	t.Helper()
	if err := store.StoreDeviceAuthorization(context.Background(), "cli", "dc-"+code, code,
		time.Now().Add(ttl), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
}

func TestApproveDeviceRefusesASpentCode(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	pendingDevice(t, store, "SPNT-0001", 5*time.Minute)

	if err := store.ApproveDevice(ctx, "SPNT-0001", "usr_1", nil); err != nil {
		t.Fatalf("the first approval was refused: %v", err)
	}
	if err := store.ApproveDevice(ctx, "SPNT-0001", "usr_2", nil); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("second approval = %v, want ErrDeviceNotFound", err)
	}
	// The first approver is still the one recorded: a refused second write must
	// not have moved the subject.
	st, err := store.DeviceByUserCode(ctx, "SPNT-0001")
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject != "usr_1" {
		t.Fatalf("subject = %q, want the first approver", st.Subject)
	}
}

func TestApproveDeviceRefusesADeniedCode(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	pendingDevice(t, store, "DENY-0001", 5*time.Minute)

	if err := store.DenyDevice(ctx, "DENY-0001"); err != nil {
		t.Fatalf("deny was refused: %v", err)
	}
	if err := store.ApproveDevice(ctx, "DENY-0001", "usr_1", nil); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("approving a denied code = %v, want ErrDeviceNotFound", err)
	}
}

func TestApproveDeviceRefusesAnExpiredCode(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	pendingDevice(t, store, "EXPR-0001", -time.Minute)

	if err := store.ApproveDevice(ctx, "EXPR-0001", "usr_1", nil); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("approving an expired code = %v, want ErrDeviceNotFound", err)
	}
}

func TestDenyDeviceRefusesASecondDenial(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	pendingDevice(t, store, "TWIC-0001", 5*time.Minute)

	if err := store.DenyDevice(ctx, "TWIC-0001"); err != nil {
		t.Fatalf("the first denial was refused: %v", err)
	}
	if err := store.DenyDevice(ctx, "TWIC-0001"); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("second denial = %v, want ErrDeviceNotFound", err)
	}
}

// A denial still outranks an approval whichever write lands second: the deny
// predicate deliberately does not require the code to be undecided.
func TestDenyDeviceOverridesAnApproval(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	pendingDevice(t, store, "OVER-0001", 5*time.Minute)

	if err := store.ApproveDevice(ctx, "OVER-0001", "usr_1", nil); err != nil {
		t.Fatalf("approve was refused: %v", err)
	}
	if err := store.DenyDevice(ctx, "OVER-0001"); err != nil {
		t.Fatalf("deny after approve was refused: %v", err)
	}
	st, err := store.DeviceByUserCode(ctx, "OVER-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Denied {
		t.Fatal("the denial did not take effect")
	}
}

func TestApproveDeviceRefusesAnUnknownCode(t *testing.T) {
	store, _ := testStore(t)
	if err := store.ApproveDevice(context.Background(), "NOPE-0001", "usr_1", nil); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("approving an unknown code = %v, want ErrDeviceNotFound", err)
	}
}
