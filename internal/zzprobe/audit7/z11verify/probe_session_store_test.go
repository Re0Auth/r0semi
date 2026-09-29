//go:build audit7

// Z11-V NEW FINDING: the probe exemption skips the limiter and the in-flight cap,
// but the session middleware still runs for /healthz and /readyz. A caller that
// sends any session cookie therefore drives one store lookup per probe request —
// in the shipped Postgres deployment, a pooled SELECT — with no rate limit and no
// concurrency cap at all. The readinessCache that closed CS-1/P1-4 bounds the
// readiness dependency check, not this second per-request round trip on the same
// exempt path.
//
// Evidence here: a counting scs.Store mounted through the REAL auth.Manager and
// the REAL httpapi chain.
package zzprobe_z11verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// countStore is an scs.Store that counts lookups. It behaves like the Postgres
// store: an unknown token is simply not found.
type countStore struct {
	find   int64
	commit int64
}

func (s *countStore) Find(string) ([]byte, bool, error) {
	atomic.AddInt64(&s.find, 1)
	return nil, false, nil
}

func (s *countStore) Commit(string, []byte, time.Time) error {
	atomic.AddInt64(&s.commit, 1)
	return nil
}

func (s *countStore) Delete(string) error { return nil }

// TestZ11VProbePathStillHitsTheSessionStore is red (t.Errorf) if a session cookie
// on a probe request reaches the store while the probe is exempt from both
// admission controls.
func TestZ11VProbePathStillHitsTheSessionStore(t *testing.T) {
	store := &countStore{}
	sessions := auth.NewManager(auth.Options{Store: store})
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              stubOIDC,
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		Sessions:          sessions,
		Accounts:          account.NewMemoryStore(),
		// Both admission controls are at their tightest: burst 1 and one slot.
		Limiter:     ratelimit.New(1e-6, 1),
		MaxInFlight: 1,
		Ready:       httpapi.ReadinessProbe(func(ctx context.Context) error { return nil }),
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	cookie := &http.Cookie{Name: "r0semi_session", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	// Control 1: a probe with NO cookie must not touch the store (this pins the
	// counter to the cookie path rather than to "the counter is broken").
	before := atomic.LoadInt64(&store.find)
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/readyz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	noCookie := atomic.LoadInt64(&store.find) - before
	t.Logf("control: 5 cookie-less /readyz requests caused %d store lookups (want 0)", noCookie)

	// Control 2: the same cookie on a NON-probe path must touch the store, so the
	// counting instrument is proven to work.
	before = atomic.LoadInt64(&store.find)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/me", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	nonProbe := atomic.LoadInt64(&store.find) - before
	t.Logf("control: one /v1/me with the cookie caused %d store lookups (want 1)", nonProbe)
	if nonProbe != 1 {
		t.Fatalf("the counting store is not on the path: %d lookups for a browser request", nonProbe)
	}

	// The finding: 20 probe requests with the cookie, no rate limit, no cap.
	before = atomic.LoadInt64(&store.find)
	const n = 20
	codes := map[int]int{}
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/readyz", nil)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		codes[resp.StatusCode]++
	}
	lookups := atomic.LoadInt64(&store.find) - before
	t.Logf("finding: %d cookie-bearing /readyz requests (limiter burst 1, max_in_flight 1) = statuses %v, "+
		"%d session-store lookups", n, codes, lookups)

	if codes[http.StatusTooManyRequests] > 0 || codes[http.StatusServiceUnavailable] > 0 {
		t.Fatalf("the probe was admitted fewer than %d times (%v): the exemption is not in force, so this probe "+
			"cannot show the amplification", n, codes)
	}
	if lookups < n {
		t.Errorf("only %d lookups for %d cookie-bearing probe requests: re-derive", lookups, n)
		return
	}
	t.Errorf("NEW: %d anonymous /readyz requests carrying one arbitrary cookie each caused %d session-store "+
		"lookups (in the shipped Postgres deployment: a pooled SELECT from the sessions table, taking a connection "+
		"per request) while the limiter with a single token and a single in-flight slot admitted every one of them. "+
		"The readinessCache that answered CS-1/P1-4 bounds the readiness dependency check, not this per-request "+
		"round trip on the same exempt path.", n, lookups)
}
