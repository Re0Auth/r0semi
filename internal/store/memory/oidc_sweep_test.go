package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// testClock is a settable clock, so a test can age records past their deadline
// instead of sleeping through it.
//
// Atomic rather than mutex-guarded, and that is not a micro-optimisation: the
// clock is read on every store call, so a mutex here serialises the parallel
// benchmarks on the fixture. BenchmarkIntrospect then measures the fixture's lock
// instead of the store's, which is the one quantity it exists to report.
type testClock struct {
	now atomic.Int64 // UnixNano
}

func newTestClock() *testClock {
	c := new(testClock)
	c.now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *testClock) Now() time.Time { return time.Unix(0, c.now.Load()).UTC() }

func (c *testClock) Advance(d time.Duration) { c.now.Add(int64(d)) }

var (
	sharedSignerOnce sync.Once
	sharedSignerKey  *oidcstore.Signer
)

// signerForTests shares one RSA key across stores: generating a 2048-bit key per
// store would dominate a test's runtime for no benefit, since the key is only
// held, never used, on these paths.
func signerForTests(tb testing.TB) *oidcstore.Signer {
	tb.Helper()
	sharedSignerOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("memory test: generate RSA key: " + err.Error())
		}
		sharedSignerKey = oidcstore.NewSigner("test", key)
	})
	return sharedSignerKey
}

// clockedStore is a store whose sense of "now" the test controls.
func clockedStore(tb testing.TB, clock *testClock) *OIDCStore {
	tb.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		tb.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		tb.Fatal(err)
	}
	store, err := NewOIDCStore(OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   signerForTests(tb),
		Now:      clock.Now,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return store
}

func tokenRequest() *oidcstore.AuthRequest {
	return &oidcstore.AuthRequest{ClientID: "cli", Subject: "usr_1", Scopes: []string{"account.id"}}
}

// The sweep removes exactly what has expired, keyed on the same deadline the
// lookups use, and leaves everything else in place.
func TestSweepExpiredRemovesOnlyExpiredRecords(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "cli",
		RedirectURI:  "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, ar.GetID(), "the-code"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenRequest(), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreDeviceAuthorization(ctx, "cli", "device-code", "BCDF-GHJK",
		clock.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	want := Counts{AuthRequests: 1, Codes: 1, AccessTokens: 1, RefreshTokens: 1, Devices: 1}
	if got := store.Counts(); got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}

	// Two hours on: the 30-minute request TTL, the one-hour access-token TTL and
	// the ten-minute device window have all passed. The 30-day refresh token has
	// not.
	clock.Advance(2 * time.Hour)
	if removed := store.SweepExpired(); removed != 4 {
		t.Fatalf("removed = %d, want 4 (request, code, access token, device)", removed)
	}
	if got := store.Counts(); got != (Counts{RefreshTokens: 1}) {
		t.Fatalf("counts = %+v, want only the live refresh token", got)
	}

	clock.Advance(31 * 24 * time.Hour)
	if removed := store.SweepExpired(); removed != 1 {
		t.Fatalf("removed = %d, want the refresh token", removed)
	}
	if got := store.Counts(); got != (Counts{}) {
		t.Fatalf("counts = %+v, want an empty store", got)
	}
}

// The sweep is about memory, not access: an expired record is already refused by
// a lookup, and a live one is never touched by the sweep.
func TestSweepNeverRemovesLiveRecords(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	accessID, _, err := store.CreateAccessToken(ctx, tokenRequest())
	if err != nil {
		t.Fatal(err)
	}

	if removed := store.SweepExpired(); removed != 0 {
		t.Fatalf("removed = %d from a store holding only live records", removed)
	}
	if err := store.SetIntrospectionFromToken(ctx, new(oidc.IntrospectionResponse), accessID, "usr_1", ""); err != nil {
		t.Fatalf("a live token stopped working after a sweep: %v", err)
	}

	// Past the deadline the lookup refuses it, with or without a sweep.
	clock.Advance(2 * time.Hour)
	if err := store.SetIntrospectionFromToken(ctx, new(oidc.IntrospectionResponse), accessID, "usr_1", ""); err == nil {
		t.Fatal("an expired token was still accepted")
	}
}

// The property the janitor exists for: repeated batches of records do not
// accrete. This is the 1000 QPS shape — mint, expire, sweep, repeat — and the
// population returns to zero every round instead of growing for the life of the
// process.
func TestSweepExpiredKeepsMapsBounded(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()
	req := tokenRequest()

	const batch = 500
	for round := 0; round < 5; round++ {
		for i := 0; i < batch; i++ {
			if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil {
				t.Fatal(err)
			}
		}
		if got := store.Counts().AccessTokens; got != batch {
			t.Fatalf("round %d: %d access tokens, want %d", round, got, batch)
		}
		clock.Advance(31 * 24 * time.Hour)
		if removed := store.SweepExpired(); removed != 2*batch {
			t.Fatalf("round %d: removed %d, want %d (access + refresh)", round, removed, 2*batch)
		}
	}
	if got := store.Counts().Records(); got != 0 {
		t.Fatalf("records = %d after five swept rounds, want 0", got)
	}
}

// TestEverySweptReadPathRefusesExpiredBeforeTheSweep is the N-01 guard for the
// memory backend, the twin of the Postgres guard
// (internal/store/postgres/sweep_test.go
// TestEverySweptReadPathAdjudicatesItsDeadline).
//
// The sweep's safety argument is "an expired record is one a lookup already
// refuses", so nothing it removes can have been reachable. That argument is only
// worth something if the read path is actually checked; this drives each record
// class past its deadline on the fake clock and asserts the READ refuses it while
// the record is still in the maps — before SweepExpired has run.
//
// One class cannot be asserted here at all. It is skipped by name rather than
// quietly omitted, and the skip is the signal: the device class is exempt for a
// reason that outlives G-7 — its expiry is adjudicated by the library, which also
// has to tell expired_token from access_denied, so the read is deliberately not
// where the refusal happens. G-7's own half (an approved code past its deadline
// must stop reporting Done) is asserted by
// TestApprovedDeviceCodePastExpiryIsNotDone.
func TestEverySweptReadPathRefusesExpiredBeforeTheSweep(t *testing.T) {
	// Past every deadline in the table — including the 30-day refresh token and
	// the tombstone it leaves — so one advance covers every class.
	const pastAll = 31 * 24 * time.Hour

	plantAuthRequest := func(t *testing.T, s *OIDCStore) string {
		t.Helper()
		ar, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
			ClientID:     "cli",
			RedirectURI:  "https://app.example/cb",
			ResponseType: oidc.ResponseTypeCode,
			Scopes:       oidc.SpaceDelimitedArray{"account.id"},
		}, "usr_1")
		if err != nil {
			t.Fatal(err)
		}
		return ar.GetID()
	}

	cases := []struct {
		name string
		// exempt names why this class cannot be asserted at all — the refusal
		// lives outside this read — so the skip outlives the finding that
		// prompted it.
		exempt string
		// plant stores one live record and returns the value its read path uses.
		plant func(t *testing.T, s *OIDCStore) string
		read  func(t *testing.T, s *OIDCStore, key string) error
		// notFound requires the refusal to be oauth.ErrTokenNotFound, not merely
		// an error: the replay path also errors with ErrRefreshTokenSpent while
		// the tombstone is live, which is not a deadline refusal.
		notFound bool
	}{
		{
			name:  "auth request by id",
			plant: plantAuthRequest,
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				_, err := s.AuthRequestByID(context.Background(), key)
				return err
			},
		},
		{
			name: "authorization code",
			plant: func(t *testing.T, s *OIDCStore) string {
				t.Helper()
				id := plantAuthRequest(t, s)
				if err := s.SaveAuthCode(context.Background(), id, "the-code"); err != nil {
					t.Fatal(err)
				}
				return "the-code"
			},
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				_, err := s.AuthRequestByCode(context.Background(), key)
				return err
			},
		},
		{
			name: "access token",
			plant: func(t *testing.T, s *OIDCStore) string {
				t.Helper()
				id, _, err := s.CreateAccessToken(context.Background(), tokenRequest())
				if err != nil {
					t.Fatal(err)
				}
				return id
			},
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				return s.SetIntrospectionFromToken(context.Background(), new(oidc.IntrospectionResponse), key, "usr_1", "")
			},
		},
		{
			name:     "refresh token",
			notFound: true,
			plant: func(t *testing.T, s *OIDCStore) string {
				t.Helper()
				_, rt, _, err := s.CreateAccessAndRefreshTokens(context.Background(), tokenRequest(), "")
				if err != nil {
					t.Fatal(err)
				}
				return rt
			},
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				_, err := s.TokenRequestByRefreshToken(context.Background(), key)
				return err
			},
		},
		{
			name:     "refresh token tombstone",
			notFound: true,
			plant: func(t *testing.T, s *OIDCStore) string {
				t.Helper()
				_, spent, _, err := s.CreateAccessAndRefreshTokens(context.Background(), tokenRequest(), "")
				if err != nil {
					t.Fatal(err)
				}
				// Rotate once: the spent value now has a live tombstone, so the
				// read below is the replay path and its deadline is the
				// tombstone's, not the (also expired) live row's.
				if _, _, _, err := s.CreateAccessAndRefreshTokens(context.Background(), tokenRequest(), spent); err != nil {
					t.Fatalf("rotation: %v", err)
				}
				return spent
			},
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				_, err := s.TokenRequestByRefreshToken(context.Background(), key)
				return err
			},
		},
		{
			name: "device authorization",
			exempt: "a pending device's deadline is adjudicated by the library " +
				"(CheckDeviceAuthorizationState), which must also distinguish expired_token from " +
				"access_denied, so this read is deliberately not where the refusal happens; the " +
				"approved-but-expired half G-7 closed is asserted by TestApprovedDeviceCodePastExpiryIsNotDone",
			plant: func(t *testing.T, s *OIDCStore) string {
				t.Helper()
				if err := s.StoreDeviceAuthorization(context.Background(), "cli", "device-code", "BCDF-GHJK",
					s.now().Add(10*time.Minute), []string{"account.id"}); err != nil {
					t.Fatal(err)
				}
				return "device-code"
			},
			read: func(_ *testing.T, s *OIDCStore, key string) error {
				_, err := s.GetDeviceAuthorizatonState(context.Background(), "cli", key)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.exempt != "" {
				t.Skipf("N-01: %s", tc.exempt)
			}
			clock := newTestClock()
			store := clockedStore(t, clock)
			key := tc.plant(t, store)

			// Past every deadline, but BEFORE the sweep: the read must refuse on
			// its own, or the sweep's "already refused" claim is false.
			clock.Advance(pastAll)
			err := tc.read(t, store, key)
			if err == nil {
				t.Fatalf("%s: the read path accepted a record %s past its deadline; the sweep cannot claim to "+
					"remove only already-refused records (N-01)", tc.name, pastAll)
			}
			if tc.notFound && !errors.Is(err, oauth.ErrTokenNotFound) {
				t.Errorf("%s: expired read = %v, want oauth.ErrTokenNotFound — an expired record must not look "+
					"like a replay (N-01)", tc.name, err)
			}
			// Control: the record is still in the maps, so it was the read that
			// refused it, not the sweep.
			if got := store.Counts().Records(); got == 0 {
				t.Errorf("%s: the store is empty before the sweep; the read refused a record that is not there",
					tc.name)
			}
		})
	}
}
