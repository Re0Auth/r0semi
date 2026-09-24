package memory

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// requestAuthCode starts a consent request for subject and mints a code from it,
// as the OP does between authorize and callback. It returns the request id.
func requestAuthCode(t *testing.T, store *OIDCStore, subject string) string {
	t.Helper()
	req, err := store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID: "cli", RedirectURI: "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, subject)
	if err != nil {
		t.Fatal(err)
	}
	id := req.GetID()
	if err := store.SaveAuthCode(context.Background(), id, "code-"+id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestPurgeSubjectRemovesRequestsCodesAndDevices mirrors the Postgres store's
// erasure behavior: an account's pending consent requests, the codes minted from
// them, and its device authorizations all go — and another account's do not.
func TestPurgeSubjectRemovesRequestsCodesAndDevices(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	const subject, other = "usr_target", "usr_other"

	requestAuthCode(t, store, subject)
	requestAuthCode(t, store, other)

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dev-secret", "ABCD-EFGH",
		time.Now().Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveDevice(ctx, "ABCD-EFGH", subject, []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	// Non-vacuous: both accounts really have state before the purge.
	if c := store.Counts(); c.AuthRequests != 2 || c.Codes != 2 || c.Devices != 1 {
		t.Fatalf("setup counts = %+v, want 2 requests, 2 codes, 1 device", c)
	}

	if _, err := store.PurgeSubject(ctx, subject); err != nil {
		t.Fatal(err)
	}

	c := store.Counts()
	if c.AuthRequests != 1 || c.Codes != 1 {
		t.Errorf("after purge: requests=%d codes=%d, want 1 and 1 (the other account's)", c.AuthRequests, c.Codes)
	}
	if c.Devices != 0 {
		t.Errorf("after purge: devices=%d, want 0", c.Devices)
	}

	// The other account's request must still resolve.
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, req := range store.authRequests {
		if req.Subject != other {
			t.Errorf("request %s belongs to %q, not the surviving account", id, req.Subject)
		}
	}
}

func TestPurgeSubjectRejectsAnEmptySubject(t *testing.T) {
	store, _ := testStore(t)
	if _, err := store.PurgeSubject(context.Background(), ""); err == nil {
		t.Fatal("an empty subject should be rejected")
	}
}

// TestPurgeSubjectIsIdempotent: erasure can be retried, so a second purge of the
// same subject is a no-op rather than an error.
func TestPurgeSubjectIsIdempotent(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	requestAuthCode(t, store, "usr_target")

	if _, err := store.PurgeSubject(ctx, "usr_target"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PurgeSubject(ctx, "usr_target"); err != nil {
		t.Fatalf("second purge: %v", err)
	}
}

// TestPurgeSubjectLeavesOtherAccountsAlone is the isolation check: erasing one
// account must not touch another's state (invariant I-3's spirit, at erasure).
func TestPurgeSubjectLeavesOtherAccountsAlone(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	requestAuthCode(t, store, "usr_keep")

	if _, err := store.PurgeSubject(ctx, "usr_gone"); err != nil {
		t.Fatal(err)
	}
	if c := store.Counts(); c.AuthRequests != 1 || c.Codes != 1 {
		t.Errorf("purging a subject with no state disturbed another's: %+v", c)
	}
}
