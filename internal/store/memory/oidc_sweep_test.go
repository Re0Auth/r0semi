package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/oauth"
)

// testClock is a settable clock, so a test can age records past their deadline
// instead of sleeping through it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

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
