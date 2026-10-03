package memory

// R10-107: the pending consent handles and pending device authorizations are
// written before any credential is checked, so an anonymous caller sets the
// store's memory floor unless admission is bounded. These are the shipped guards
// for that bound: the constants, the OIDCOptions override, and the fail-closed
// behaviour (an error, nothing stored, and admission recovers after the sweep).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestPendingAdmissionDefaultBounds(t *testing.T) {
	if defaultMaxPendingAuthRequests != 1<<17 {
		t.Fatalf("defaultMaxPendingAuthRequests = %d, want %d", defaultMaxPendingAuthRequests, 1<<17)
	}
	if defaultMaxPendingDeviceAuthorizations != 1<<15 {
		t.Fatalf("defaultMaxPendingDeviceAuthorizations = %d, want %d",
			defaultMaxPendingDeviceAuthorizations, 1<<15)
	}
}

func TestPendingAdmissionBoundsAreHonouredFromOptions(t *testing.T) {
	base, _ := testStore(t)
	store, err := NewOIDCStore(OIDCOptions{
		Clients:                        base.clients,
		Registry:                       base.registry,
		Signer:                         base.signer,
		MaxPendingAuthRequests:         3,
		MaxPendingDeviceAuthorizations: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.maxPendingAuthRequests != 3 {
		t.Fatalf("maxPendingAuthRequests = %d, want 3", store.maxPendingAuthRequests)
	}
	if store.maxPendingDeviceAuthorizations != 4 {
		t.Fatalf("maxPendingDeviceAuthorizations = %d, want 4", store.maxPendingDeviceAuthorizations)
	}
}

func authRequest() *oidc.AuthRequest {
	return &oidc.AuthRequest{
		ClientID:     "cli",
		RedirectURI:  "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       []string{"account.id"},
	}
}

func TestPendingAuthRequestAdmissionIsBoundedAndFailsClosed(t *testing.T) {
	store, _ := testStore(t)
	store.maxPendingAuthRequests = 2
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := store.CreateAuthRequest(ctx, authRequest(), ""); err != nil {
			t.Fatalf("CreateAuthRequest %d: %v", i, err)
		}
	}
	_, err := store.CreateAuthRequest(ctx, authRequest(), "")
	if !errors.Is(err, ErrPendingAuthRequestsFull) {
		t.Fatalf("past the bound: got %v, want ErrPendingAuthRequestsFull", err)
	}
	if got := store.Counts().AuthRequests; got != 2 {
		t.Fatalf("a refused request was stored: population %d", got)
	}
	checkIndexes(t, store)

	// The bound must not be permanent: once the 30-minute TTL sweeps them, the
	// store admits again.
	store.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	store.SweepExpired()
	if got := store.Counts().AuthRequests; got != 0 {
		t.Fatalf("the expired pending requests were not swept: %d remain", got)
	}
	if _, err := store.CreateAuthRequest(ctx, authRequest(), ""); err != nil {
		t.Fatalf("admission did not recover after the sweep: %v", err)
	}
}

func TestDeviceAuthorizationAdmissionIsBoundedAndFailsClosed(t *testing.T) {
	store, _ := testStore(t)
	store.maxPendingDeviceAuthorizations = 2
	ctx := context.Background()
	expires := time.Now().Add(10 * time.Minute)

	for i := 0; i < 2; i++ {
		if err := store.StoreDeviceAuthorization(ctx, "cli",
			string(rune('a'+i)), "CODE-"+string(rune('a'+i)), expires, []string{"account.id"}); err != nil {
			t.Fatalf("StoreDeviceAuthorization %d: %v", i, err)
		}
	}
	err := store.StoreDeviceAuthorization(ctx, "cli", "c", "CODE-c", expires, []string{"account.id"})
	if !errors.Is(err, ErrPendingDeviceAuthorizationsFull) {
		t.Fatalf("past the bound: got %v, want ErrPendingDeviceAuthorizationsFull", err)
	}
	if got := store.Counts().Devices; got != 2 {
		t.Fatalf("a refused device authorization was stored: population %d", got)
	}

	// A re-used device code overwrites rather than adds, so it is admitted even at
	// the bound (a fresh user code keeps it from tripping the duplicate-user-code
	// refusal, which is a different rule).
	if err := store.StoreDeviceAuthorization(ctx, "cli", "a", "CODE-z", expires, []string{"account.id"}); err != nil {
		t.Fatalf("an overwrite must not be refused at the bound: %v", err)
	}
}
