//go:build audit5

package concurrency

import (
	"context"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// --- Finding CM-4: the in-memory OP store has no population cap ---
//
// Nothing in internal/store/memory caps authRequests, codes, accessTokens,
// refreshTokens or devices. The only remover is the janitor (SweepExpired, run by
// cmd/re0auth every opJanitorInterval = 5 minutes) and the records it removes are
// those past their TTL (requestTTL defaults to 30 minutes; the OP's device
// authorization lifetime is 10 minutes). Between the rate limiter (default 50/s
// per client address, burst 100) and the in-flight cap (default 512) nothing
// bounds the population, and the entries an attacker creates are created *before*
// any credential is presented: an authorization request exists the moment
// /oauth/authorize is answered, and a device authorization the moment
// /oauth/device_authorization is.
//
// The probe below drives the real HTTP surface with no credential at all, and the
// second measures what one entry costs so the growth rate is a number rather than
// an adjective.

func authorizeQuery() string {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {"account.id"},
		"state":                 {"st"},
		"nonce":                 {"nnn"},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
	}.Encode()
}

// An unauthenticated caller grows the pending-authorization map at one entry per
// request. There is no session cookie, no bearer token, and no client secret in
// any of these requests: the only thing presented is a public client_id.
func TestUnauthenticatedAuthorizeGrowsTheStoreWithoutBound(t *testing.T) {
	env := newProbeEnv(t)

	const n = 200
	for i := 0; i < n; i++ {
		rec := env.do(http.MethodGet, "/oauth/authorize?"+authorizeQuery(), "")
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize #%d = %d: %s", i, rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "authRequestID=") {
			t.Fatalf("authorize #%d did not mint a handle: %s", i, loc)
		}
	}
	// Anti-vacuity: the requests really did reach the OP and leave state behind.
	if got := env.store.Counts().AuthRequests; got != n {
		t.Errorf("pending authorization requests = %d after %d unauthenticated requests, want %d",
			got, n, n)
	}

	// And the same for device authorizations, which also need no credential.
	const d = 100
	for i := 0; i < d; i++ {
		form := url.Values{"client_id": {probeClientID}, "scope": {"account.id"}}.Encode()
		rec := env.do(http.MethodPost, "/oauth/device_authorization", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("device_authorization #%d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if got := env.store.Counts().Devices; got != d {
		t.Errorf("device authorizations = %d after %d unauthenticated requests, want %d", got, d, d)
	}
}

// One entry's retained cost, and what the janitor costs when it finally runs.
//
// The numbers are printed rather than asserted: they are the input to the capacity
// arithmetic (an attacker holding one address at the default 50 req/s for the
// 30-minute request TTL is ~90,000 pending requests), and a hard assertion on a
// byte count would be a test that breaks on a Go release rather than on a defect.
func TestPendingRequestsCostMemoryAndTheSweepHoldsTheLock(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()
	req := &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
		State: "st", Nonce: "nnn",
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	const n = 100_000
	for i := 0; i < n; i++ {
		if _, err := st.CreateAuthRequest(ctx, req, ""); err != nil {
			t.Fatal(err)
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	perEntry := int64(after.HeapAlloc-before.HeapAlloc) / n
	if got := st.Counts().AuthRequests; got != n {
		t.Fatalf("auth requests = %d, want %d", got, n)
	}

	start := time.Now()
	removed := st.SweepExpired()
	sweep := time.Since(start)
	t.Logf("%d pending requests retain ~%d bytes each (~%d MiB total); SweepExpired() over them took %s and removed %d",
		n, perEntry, int64(after.HeapAlloc-before.HeapAlloc)/(1<<20), sweep, removed)

	// The janitor sweeps on a ticker while holding the store's single lock for the
	// whole scan (memory/oidc.go SweepExpired: `s.mu.Lock(); defer s.mu.Unlock()`
	// around every loop). At the default 50 req/s and a 30-minute TTL a single
	// address can hold ~90,000 live pending requests, so that scan is the figure
	// above multiplied by about one — under load, once every five minutes, the
	// whole OP store stops for that long.
	if sweep > 0 && perEntry == 0 {
		t.Fatal("the probe measured no retained memory; the numbers above are meaningless")
	}
}

// The sweep really is the only remover: an unexpired record survives it, so the
// map's ceiling is set by arrivals multiplied by the TTL, not by the janitor.
func TestTheJanitorOnlyRemovesExpiredRecords(t *testing.T) {
	now := time.Now()
	st, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  newProbeClients(t),
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(t),
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, ""); err != nil {
		t.Fatal(err)
	}
	if removed := st.SweepExpired(); removed != 0 {
		t.Fatalf("the janitor removed %d unexpired records", removed)
	}
	if got := st.Counts().AuthRequests; got != 1 {
		t.Fatalf("auth requests = %d, want the unexpired one", got)
	}
	now = now.Add(31 * time.Minute) // past the 30-minute request TTL
	if removed := st.SweepExpired(); removed != 1 {
		t.Errorf("the janitor removed %d records past the TTL, want 1", removed)
	}
}
