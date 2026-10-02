package oauth

// Probes for S04-5=A: user-code uniqueness belongs to the store's canonical
// unique constraint (surfaced as ErrUserCodeConflict), and freeUserCode must only
// treat a collision as a redraw while every other store error propagates.
//
// Pre-fix: SaveDevice returned no conflict at all, oauth never retried on one, and
// MemoryDeviceStore silently overwrote a duplicate user code — so both the retry
// assertion and the duplicate-refusal assertion fail.
//
// They run in the default build: `go test ./oauth/ -count=1`.

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// s045ConflictStore reports a conflict for its first n saves, then delegates. It
// models the PG unique-constraint violation on the INSERT.
type s045ConflictStore struct {
	*MemoryDeviceStore
	conflicts int
	saves     int
}

func (s *s045ConflictStore) SaveDevice(ctx context.Context, deviceCode string, d DeviceAuthorizationRecord) error {
	s.saves++
	if s.conflicts > 0 {
		s.conflicts--
		return fmt.Errorf("%w: forced by probe", ErrUserCodeConflict)
	}
	return s.MemoryDeviceStore.SaveDevice(ctx, deviceCode, d)
}

// s045FailureStore fails every save with a non-conflict error.
type s045FailureStore struct {
	*MemoryDeviceStore
	err error
}

func (s *s045FailureStore) SaveDevice(context.Context, string, DeviceAuthorizationRecord) error {
	return s.err
}

// S04-5: a canonical user-code conflict is a redraw, not a failure. Pre-fix the
// conflict error was returned to the caller and BeginDeviceAuthorization failed.
func TestS045UserCodeConflictRedrawsInsteadOfFailing(t *testing.T) {
	store := &s045ConflictStore{MemoryDeviceStore: NewMemoryDeviceStore(), conflicts: 2}
	svc, clients, _, _ := newP3Service(t, nil, store, 0)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

	resp, err := svc.BeginDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID},
	})
	if err != nil {
		t.Fatalf("a user-code conflict was not retried: %v", err)
	}
	if store.saves < 3 {
		t.Fatalf("SaveDevice was called %d times after 2 conflicts, want at least 3 (one per draw)",
			store.saves)
	}
	if resp.UserCode == "" || resp.DeviceCode == "" {
		t.Fatalf("the retried request has no codes: %+v", resp)
	}
	// The retry must persist the code it actually returned.
	if _, err := store.GetDeviceByUserCode(context.Background(), resp.UserCode); err != nil {
		t.Fatalf("the returned user code is not the stored one: %v", err)
	}
}

// S04-5: only a conflict is a collision. Any other save failure is the request's
// answer and must not be folded into "could not allocate a unique user code".
func TestS045NonConflictSaveErrorPropagates(t *testing.T) {
	boom := errors.New("device store down")
	store := &s045FailureStore{MemoryDeviceStore: NewMemoryDeviceStore(), err: boom}
	svc, clients, _, _ := newP3Service(t, nil, store, 0)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

	_, err := svc.BeginDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("the save failure was reported as %v, want the store error", err)
	}
	if errors.Is(err, ErrUserCodeConflict) {
		t.Fatal("a generic save failure was reported as a user-code conflict")
	}
}

// S04-5: the in-package DeviceStore enforces the same canonical uniqueness the PG
// unique index does. Pre-fix SaveDevice overwrote the earlier record silently.
func TestS045MemoryDeviceStoreRefusesDuplicateCanonicalUserCode(t *testing.T) {
	store := NewMemoryDeviceStore()
	ctx := context.Background()

	first := DeviceAuthorizationRecord{UserCode: "bcdf-ghjk", ClientID: "cli", Status: DevicePending}
	if err := store.SaveDevice(ctx, "device-1", first); err != nil {
		t.Fatal(err)
	}
	// Same code, different case/separator: the canonical key is what must collide.
	second := DeviceAuthorizationRecord{UserCode: "BCDFGHJK", ClientID: "cli", Status: DevicePending}
	err := store.SaveDevice(ctx, "device-2", second)
	if !errors.Is(err, ErrUserCodeConflict) {
		t.Fatalf("a duplicate canonical user code was stored as %v, want ErrUserCodeConflict", err)
	}
	if err := store.SaveDevice(ctx, "device-2", DeviceAuthorizationRecord{
		UserCode: "ZZZZ-9999", ClientID: "cli", Status: DevicePending,
	}); err != nil {
		t.Fatalf("a free user code was refused: %v", err)
	}

	// The refused write did not touch the first record.
	rec, err := store.GetDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UserCode != "bcdf-ghjk" {
		t.Fatalf("the first record was overwritten: user_code = %q", rec.UserCode)
	}
	if _, err := store.GetDevice(ctx, "device-2"); err != nil {
		// device-2 landed under its own (free) code; both records must coexist.
		t.Fatalf("the retried record is missing: %v", err)
	}
}
