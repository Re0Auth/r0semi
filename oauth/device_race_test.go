package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// interleavingDeviceStore lands a competing write inside the window between the
// service's read and its write.
//
// The window is real — a client polls every few seconds while the user is looking
// at the verification page — and far too small to hit by chance, so it is entered
// deliberately: the hooks run after the underlying read has produced its record,
// which is exactly the stale state the service is holding. Reproducing it this way
// keeps the test deterministic; a goroutine race would fail on a loaded machine
// rather than on the bug.
type interleavingDeviceStore struct {
	DeviceStore
	afterGetDevice           func()
	afterGetDeviceByUserCode func()
}

func (s *interleavingDeviceStore) GetDevice(ctx context.Context, deviceCode string) (DeviceAuthorizationRecord, error) {
	rec, err := s.DeviceStore.GetDevice(ctx, deviceCode)
	if hook := s.afterGetDevice; hook != nil {
		s.afterGetDevice = nil // fire once
		hook()
	}
	return rec, err
}

func (s *interleavingDeviceStore) GetDeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorizationRecord, error) {
	rec, err := s.DeviceStore.GetDeviceByUserCode(ctx, userCode)
	if hook := s.afterGetDeviceByUserCode; hook != nil {
		s.afterGetDeviceByUserCode = nil
		hook()
	}
	return rec, err
}

// newRacingAS is newTestAS with the device store replaced, so a test can drive the
// interleaving through the service rather than through the store directly.
func newRacingAS(t *testing.T, devices DeviceStore) (Service, *MemoryClientRegistry, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	clients := NewMemoryClientRegistry()
	svc, err := NewService(clients, NewMemoryStore(), audit.NewMemoryLogger(), Config{
		Issuer:          "https://auth.test",
		Scopes:          testRegistry(t),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		CodeTTL:         time.Minute,
		Now:             clock.now,
		Devices:         devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clients, clock
}

// TestAdversarialDevicePollDoesNotEraseADecision: a poll reads the record, and a
// decision that lands before the poll writes must survive it.
//
// Under the old whole-record write the poll put its stale copy back and the denial
// vanished — the request returned to pending, so a later approval went through as
// if the user had never said no.
func TestAdversarialDevicePollDoesNotEraseADecision(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryDeviceStore()
	racing := &interleavingDeviceStore{DeviceStore: base}
	svc, clients, clock := newRacingAS(t, racing)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

	start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(6 * time.Second)

	var denied bool
	racing.afterGetDevice = func() {
		applied, err := base.RecordDecision(ctx, TokenHash(start.DeviceCode), DeviceDecision{Status: DeviceDenied})
		if err != nil {
			t.Errorf("interleaved denial: %v", err)
		}
		denied = applied
	}

	// The poll read before the denial, so this answer is the stale one; what the
	// test is about is what the poll left behind.
	if _, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{
		ClientID: "cli", DeviceCode: start.DeviceCode,
	}); err == nil {
		t.Fatal("a poll on a pending request issued tokens")
	} else if got := protocolCode(t, err); got != "authorization_pending" {
		t.Fatalf("poll = %q, want authorization_pending (the stale read)", got)
	}
	if !denied {
		t.Fatal("the interleaved denial never applied; the test would prove nothing")
	}
	stored, err := base.GetDevice(ctx, start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != DeviceDenied {
		t.Fatalf("the poll erased the decision: status = %q, want %q", stored.Status, DeviceDenied)
	}

	// And the denial still decides the flow: the next poll refuses outright.
	clock.advance(6 * time.Second)
	if _, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{
		ClientID: "cli", DeviceCode: start.DeviceCode,
	}); err == nil {
		t.Fatal("a request the user denied handed out tokens")
	} else if got := protocolCode(t, err); got != "access_denied" {
		t.Fatalf("poll after denial = %q, want access_denied", got)
	}
}

// TestAdversarialDeviceFirstDecisionWinsInBothDirections: whichever decision lands
// first is the one that sticks. A second decision — approval overwriting a denial,
// or a denial overwriting an approval — is refused, and the caller is told exactly
// what a sequential second decision is told ("already decided").
func TestAdversarialDeviceFirstDecisionWinsInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		first    DeviceStatus
		approved bool
	}{
		{"denial first, later approval refused", DeviceDenied, true},
		{"approval first, later denial refused", DeviceApproved, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base := NewMemoryDeviceStore()
			racing := &interleavingDeviceStore{DeviceStore: base}
			svc, clients, _ := newRacingAS(t, racing)
			registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

			start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
				ClientID: "cli", Scopes: []Scope{ScopeAccountID},
			})
			if err != nil {
				t.Fatal(err)
			}

			var landed bool
			racing.afterGetDeviceByUserCode = func() {
				decision := DeviceDecision{Status: tc.first, Subject: "usr_first"}
				applied, err := base.RecordDecision(ctx, TokenHash(start.DeviceCode), decision)
				if err != nil {
					t.Errorf("interleaved decision: %v", err)
				}
				landed = applied
			}

			err = svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_second", tc.approved, nil, nil)
			if err == nil {
				t.Fatalf("a second decision overwrote the first (%s)", tc.first)
			}
			if got := protocolCode(t, err); got != "invalid_request" {
				t.Fatalf("second decision = %q, want invalid_request", got)
			}
			if !landed {
				t.Fatal("the interleaved decision never applied; the test would prove nothing")
			}
			stored, err := base.GetDevice(ctx, start.DeviceCode)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Status != tc.first || stored.Subject != "usr_first" {
				t.Fatalf("the first decision did not stand: %+v", stored)
			}
		})
	}
}
