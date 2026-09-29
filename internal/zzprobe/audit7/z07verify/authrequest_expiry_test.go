//go:build audit7

// Zone Z07 adversarial-verification probe.
//
// It re-derives the memory backend half of Z07-1 from scratch, with its own
// clock and its own client registry — it shares no fixture with the report's
// probes. The claim under test is that a pending consent handle past its
// deadline is still returned by AuthRequestByID (the read the consent screen
// performs), while the sibling code lookup refuses an expired record.
//
// The probe is expected to FAIL today. Its positive controls are in the same
// function: the record is readable inside its lifetime, and SweepExpired
// proves it really was past its deadline.
package z07verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

type verifyClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *verifyClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *verifyClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newVerifyStore(t *testing.T, ttl time.Duration) (*memory.OIDCStore, *verifyClock) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("verify-cli", "VERIFY", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	clock := &verifyClock{now: time.Now().UTC()}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:    clients,
		Registry:   oauth.DefaultRegistry(),
		Signer:     oidcstore.NewSigner("verify", key),
		RequestTTL: ttl,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, clock
}

// TestZ07VerifyExpiredAuthRequestIsStillReadableByID pins the backend-level
// mechanism Z07-1 asserts, independently of the httpapi/oidchttp fixture the
// report used.
func TestZ07VerifyExpiredAuthRequestIsStillReadableByID(t *testing.T) {
	const ttl = 30 * time.Minute
	store, clock := newVerifyStore(t, ttl)
	ctx := context.Background()

	req, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:    "verify-cli",
		RedirectURI: "https://app.example/cb",
		Scopes:      []string{oauth.ScopeAccountID.String()},
		State:       "verify-state",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	id := req.GetID()

	// Control 1: inside the lifetime the by-ID read works, so a store that
	// refused everything would not satisfy the probe.
	if _, err := store.AuthRequestByID(ctx, id); err != nil {
		t.Fatalf("AuthRequestByID inside the TTL failed: %v", err)
	}

	// A code hanging off the request, to exercise the sibling lookup too.
	if err := store.SaveAuthCode(ctx, id, "verify-code"); err != nil {
		t.Fatal(err)
	}

	clock.Advance(ttl + time.Minute)

	// Control 2: the code lookup refuses the expired record...
	if _, err := store.AuthRequestByCode(ctx, "verify-code"); err == nil {
		t.Errorf("AuthRequestByCode accepted an authorization code %v past its deadline", ttl+time.Minute)
	} else {
		t.Logf("AuthRequestByCode refuses the expired code: %v", err)
	}

	// ...and the record really is expired, so the by-ID silence is not an
	// artefact of the probe's clock.
	// (SweepExpired is called last because it removes the record.)
	// The finding:
	if _, err := store.AuthRequestByID(ctx, id); err == nil {
		t.Errorf("AuthRequestByID returned a pending consent handle %v past its %v deadline: "+
			"the by-ID read carries no expiry predicate, so only the periodic sweep ends it",
			ttl+time.Minute, ttl)
	} else {
		t.Logf("AuthRequestByID refuses the expired handle: %v", err)
	}

	if removed := store.SweepExpired(); removed == 0 {
		t.Fatalf("the sweep removed nothing, so the record was not past its deadline after all")
	}
	if _, err := store.AuthRequestByID(ctx, id); err == nil {
		t.Errorf("even after the sweep removed the record, AuthRequestByID still returns it")
	}
}
