//go:build audit7

// Z11-V regression guard: the probe exemption must also SKIP the session
// middleware.
//
// /healthz and /readyz are exempt from the limiter and the in-flight cap, so if
// they were still wrapped by sessions.LoadAndSave a caller that sends any session
// cookie could drive one session-store lookup per probe request — in the shipped
// Postgres deployment, a pooled SELECT — with no rate limit and no concurrency cap
// at all. server.go routes both probes around LoadAndSave; everything else still
// loads the session.
//
// This guard mounts a counting scs.Store through the REAL auth.Manager and the REAL
// httpapi chain: 20 cookie-bearing /readyz and 20 cookie-bearing /healthz requests
// must cause 0 lookups and answer 200. The controls prove the instrument works and
// is pinned to the cookie path: cookie-less /readyz causes 0 lookups, and /v1/me
// with the same cookie causes exactly 1. It was formerly
// TestZ11VProbePathStillHitsTheSessionStore, a finding-confirmation oracle.
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

// TestZ11VProbePathSkipsTheSessionStore is green only while /healthz and /readyz
// are routed around the session middleware: cookie-bearing probes must cause no
// store lookups.
func TestZ11VProbePathSkipsTheSessionStore(t *testing.T) {
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
	if noCookie != 0 {
		t.Fatalf("control: cookie-less /readyz caused %d store lookups, want 0", noCookie)
	}

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

	// The subject: 20 cookie-bearing /readyz AND 20 cookie-bearing /healthz, with
	// the limiter at burst 1 and max_in_flight 1. Every probe must be admitted (200)
	// and none may reach the session store.
	before = atomic.LoadInt64(&store.find)
	const n = 20
	codes := map[int]int{}
	for _, p := range []string{"/readyz", "/healthz"} {
		for i := 0; i < n; i++ {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+p, nil)
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			codes[resp.StatusCode]++
		}
	}
	lookups := atomic.LoadInt64(&store.find) - before
	t.Logf("%d cookie-bearing probe requests (20 /readyz + 20 /healthz, limiter burst 1, max_in_flight 1) = "+
		"statuses %v, %d session-store lookups", 2*n, codes, lookups)

	if codes[http.StatusOK] != 2*n {
		t.Errorf("cookie-bearing probe statuses %v: every probe must be admitted with 200", codes)
	}
	if lookups != 0 {
		t.Errorf("%d session-store lookups for %d cookie-bearing probe requests: /healthz and /readyz are wrapped "+
			"by sessions.LoadAndSave again, so an anonymous cookie drives a pooled SELECT per exempt probe with "+
			"no limiter and no concurrency cap", lookups, 2*n)
	}
}
