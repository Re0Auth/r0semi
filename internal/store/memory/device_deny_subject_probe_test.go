package memory

// device_deny_subject_probe_test.go is the probe for Z20V-1=A.
//
// Z20V-1: the device denial path recorded `subject: ""`, so `oidc.device.deny`
// could not answer "who refused". The store already holds the denying account —
// the route hands it to DecideDeviceAuthorization — but DenyDevice's signature
// dropped it. The fix adds the subject to DenyDevice and records it.

import (
	"context"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

func deviceDenialEvent(t *testing.T, logger *audit.MemoryLogger) *audit.Event {
	t.Helper()
	for i := range logger.Events() {
		if logger.Events()[i].Action == "oidc.device.deny" {
			return &logger.Events()[i]
		}
	}
	return nil
}

// TestDenyDeviceAuditNamesTheDenyingSubject pins the direct store method.
func TestDenyDeviceAuditNamesTheDenyingSubject(t *testing.T) {
	logger := audit.NewMemoryLogger()
	store := deviceStore(t, oauth.DefaultRegistry(), logger, oauth.ScopeAccountID)
	ctx := context.Background()

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-deny", "DENY-0001",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DenyDevice(ctx, "DENY-0001", "usr_denier"); err != nil {
		t.Fatalf("DenyDevice: %v", err)
	}

	event := deviceDenialEvent(t, logger)
	if event == nil {
		t.Fatal("the device denial recorded no audit event")
	}
	if event.Subject != "usr_denier" {
		t.Errorf("the denial event does not name who refused: subject=%q, want %q (Z20V-1)",
			event.Subject, "usr_denier")
	}
	if event.Detail["client_id"] != "cli" {
		t.Errorf("the denial event lost the client: detail=%v", event.Detail)
	}
}

// TestDeviceDenialThroughTheEntranceKeepsTheSubject pins the call point the route
// actually uses: DecideDeviceAuthorization forwards the authenticated subject into
// the denial, exactly as it does for an approval.
func TestDeviceDenialThroughTheEntranceKeepsTheSubject(t *testing.T) {
	logger := audit.NewMemoryLogger()
	store := deviceStore(t, oauth.DefaultRegistry(), logger, oauth.ScopeAccountID)
	ctx := context.Background()

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-entrance", "DENY-0002",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideDeviceAuthorization(ctx, "DENY-0002", "usr_via_entrance", false, nil, nil); err != nil {
		t.Fatalf("DecideDeviceAuthorization(deny): %v", err)
	}

	event := deviceDenialEvent(t, logger)
	if event == nil {
		t.Fatal("the device denial recorded no audit event")
	}
	if event.Subject != "usr_via_entrance" {
		t.Errorf("DecideDeviceAuthorization's denial dropped the subject: subject=%q, want %q (Z20V-1)",
			event.Subject, "usr_via_entrance")
	}
}
