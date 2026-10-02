package idp

// Audit probe for S06-3: (*Client).oidcProvider used to hold providerMu across
// the network discovery call, so concurrent logins against an issuer whose
// discovery was slow (or failing) were serialized behind it. The lock is now
// held only around the cache read and the write-back; the round trip runs
// outside it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestAuditS063DiscoveryFailureDoesNotSerializeConcurrentLogins runs four
// concurrent logins against a discovery endpoint that takes 250ms and then
// answers 503. Held under one lock, the four failures cost about 1.0s of wall
// clock; with the round trip outside the lock they overlap and cost about one
// 250ms delay. The in-flight peak is logged so the concurrency is observed, not
// just implied by the duration.
func TestAuditS063DiscoveryFailureDoesNotSerializeConcurrentLogins(t *testing.T) {
	var inFlight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// srv.Client() is injected rather than the hardened default: the fake issuer
	// is on loopback, which the default outbound client refuses by design.
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   srv.Client(),
		Credentials: []Credentials{{
			Provider: "audits063", ClientID: "cid", ClientSecret: "sec",
			Issuer: srv.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("audits063")
	if !ok {
		t.Fatal("provider not registered")
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, srv.Client())

	const callers = 4
	errs := make([]error, callers)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.AuthCodeURL(ctx, "state", c.NewVerifier(), "nonce")
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	peakSeen := peak.Load()
	t.Logf("%d concurrent logins against a 250ms-then-503 discovery took %s; discovery in-flight peak = %d",
		callers, elapsed.Round(time.Millisecond), peakSeen)

	for i, err := range errs {
		if err == nil {
			t.Errorf("caller %d: a failing discovery was not reported", i)
		}
	}
	// The peak is recorded, not asserted: the wall clock below is the property
	// under test, and a scheduler that happened not to overlap the goroutines
	// would otherwise fail the probe for the wrong reason.
	if peakSeen < 2 {
		t.Logf("note: discovery in-flight peak = %d; the callers did not overlap in this run", peakSeen)
	}
	if elapsed >= 600*time.Millisecond {
		t.Fatalf("concurrent logins serialized on the discovery network call: %s for %d x 250ms",
			elapsed.Round(time.Millisecond), callers)
	}
}
