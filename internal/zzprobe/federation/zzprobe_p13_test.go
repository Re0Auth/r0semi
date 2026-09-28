//go:build audit5

package zzprobe_federation

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// The dedicated guard for P1-3: one data-plane request must be bounded in TIME,
// and a source that only ever answers 401 must be shed rather than paid for on
// every request.
//
// The finding had two halves:
//
//   - the candidate loop runs several outbound calls in series (source, token
//     refresh, the fetch again after a 401, then the next candidate), each with a
//     20s deadline, and nothing bounded the total. The worst case was far past the
//     server's 60s write timeout, so the client got a dropped connection and no
//     error body — the one answer it cannot interpret;
//   - a 401 is a 4xx, and httpclient's breaker counted only 5xx and transport
//     errors, so a source whose tokens could never be refreshed cost two round
//     trips on every request, forever, and never tripped anything.
func TestZZProbeDataPlaneIsBoundedInTimeAndShedsA401Source(t *testing.T) {
	t.Run("A one request cannot outlive the total deadline", func(t *testing.T) {
		// An upstream that accepts the connection and never answers: the case where
		// only the deadline ends the request.
		blocked := newBlockingDoer()
		svc := budgetServiceWithTimeout(t, blocked, 300*time.Millisecond)

		start := time.Now()
		_, err := svc.Raw(context.Background(), federation.RawRequest{
			User: "usr_1", Game: "phigros", Source: "src", Path: "records",
		})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("the read succeeded against an upstream that never answered")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the read failed with %v, want the total deadline (context.DeadlineExceeded)", err)
		}
		// The bound is the deadline, not the outbound client's own 20s: a test that
		// allowed 20s would pass with no total bound at all.
		if elapsed > 3*time.Second {
			t.Errorf("the read took %v against a %v deadline: the total bound is not applied", elapsed, 300*time.Millisecond)
		}
		t.Logf("a stalled upstream ended the request after %v (deadline 300ms)", elapsed)
	})

	t.Run("B the deadline bounds the whole candidate loop, not one call", func(t *testing.T) {
		// Two candidates, both stalling. Without a total deadline this is at least
		// two outbound timeouts (2 x 20s by default); with it, one number.
		blocked := newBlockingDoer()
		svc := budgetServiceWithTimeout(t, blocked, 400*time.Millisecond)
		start := time.Now()
		_, err := svc.Fetch(context.Background(), federation.FetchRequest{
			User: "usr_1", Game: "phigros", Resource: "profile",
		})
		if err == nil {
			t.Fatal("the fetch succeeded against an upstream that never answered")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("the fetch took %v against a 400ms deadline", elapsed)
		} else {
			t.Logf("two stalling candidates ended after %v (deadline 400ms)", elapsed)
		}
	})

	t.Run("C a permanently-401 source trips the breaker", func(t *testing.T) {
		// The breaker is the real decorator, not a stub: a per-host circuit breaker
		// over a transport that always answers 401.
		var calls int64
		base := &stubRoundTripper{fn: func(*http.Request) (*http.Response, error) {
			atomic.AddInt64(&calls, 1)
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       http.NoBody,
				Request:    nil,
			}, nil
		}}
		breaker := httpclient.CircuitBreaker(base, httpclient.BreakerOptions{
			FailureThreshold:  3,
			Cooldown:          time.Minute,
			HalfOpenSuccesses: 2,
		})
		client := &http.Client{Transport: breaker, Timeout: 5 * time.Second}

		open := false
		for i := 0; i < 10; i++ {
			req, err := http.NewRequest(http.MethodGet, "https://upstream.example/v1/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if errors.Is(err, httpclient.ErrCircuitOpen) {
				open = true
				break
			}
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_ = resp.Body.Close()
		}
		if !open {
			t.Errorf("ten consecutive 401s did not open the breaker (transport calls: %d): "+
				"a source whose tokens cannot be refreshed is charged on every request forever",
				atomic.LoadInt64(&calls))
		}
		t.Logf("the breaker opened after %d upstream calls", atomic.LoadInt64(&calls))
	})

	t.Run("D control: a 401 followed by a success never opens it", func(t *testing.T) {
		// The refresh dance is a 401 and then a 200 on the same host. The breaker
		// must not punish a healthy source for it: WithFailureThreshold(n) is a ratio
		// over the last n attempts, so the success keeps it closed.
		var n int64
		base := &stubRoundTripper{fn: func(*http.Request) (*http.Response, error) {
			status := http.StatusUnauthorized
			if atomic.AddInt64(&n, 1)%2 == 0 {
				status = http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       http.NoBody,
			}, nil
		}}
		breaker := httpclient.CircuitBreaker(base, httpclient.BreakerOptions{FailureThreshold: 3, Cooldown: time.Minute})
		client := &http.Client{Transport: breaker, Timeout: 5 * time.Second}
		for i := 0; i < 12; i++ {
			req, err := http.NewRequest(http.MethodGet, "https://upstream.example/v1/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if errors.Is(err, httpclient.ErrCircuitOpen) {
				t.Fatalf("the breaker opened on a source that answers a 401 and a 200 in turn (after %d calls)", i)
			}
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_ = resp.Body.Close()
		}
	})
}

// blockingDoer never produces a response until the caller gives up: an upstream
// that accepted the connection and went quiet, so only a deadline ends the read.
type blockingDoer struct{ calls int64 }

func newBlockingDoer() *blockingDoer { return &blockingDoer{} }

func (d *blockingDoer) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(&d.calls, 1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// budgetServiceWithTimeout is budgetService with the data plane's total timeout
// set, so the probe can use a deadline short enough to observe.
func budgetServiceWithTimeout(t *testing.T, doer *blockingDoer, total time.Duration) federation.Service {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", DisplayName: "Src", Issuer: "https://upstream.example",
		TokenClass: "revocable",
		RawBase:    "https://upstream.example/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
			{Name: "records", Schema: "re0auth.phigros.records/1", Scope: "phigros.score.read"},
		},
	}, federation.Source{
		Game: "phigros", Name: "second", DisplayName: "Second", Issuer: "https://second.example",
		TokenClass: "revocable",
		RawBase:    "https://second.example/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	for _, name := range []string{"src", "second"} {
		b := federation.Binding{User: "usr_1", Game: "phigros", Source: name, Version: 1}
		if err := bindings.Put(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if err := v.Enroll(context.Background(), federation.BindingIdentity(b),
			mustPair(t, "upstream-token", ""), nil); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: doer, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		TotalTimeout: total,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// stubRoundTripper is the smallest http.RoundTripper that answers exactly what a
// probe tells it to.
type stubRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return s.fn(req) }
