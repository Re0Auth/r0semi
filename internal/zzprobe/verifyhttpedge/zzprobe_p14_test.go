//go:build audit5

package verifyhttpedge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// The dedicated guard for P1-4: the probe exemption must not be an amplification
// vector, and a probe must never be shed because the service is busy.
//
// The finding: `isProbe` is checked before both the rate limiter and the in-flight
// cap, and /readyz ran its dependency check on every request — one pooled database
// round trip each. Measured: with `max_in_flight = 1` saturated, 32 concurrent
// /readyz calls all entered the probe, so an anonymous caller could exhaust the
// connection pool on the one endpoint whose job is to report on it.
//
// The two requirements pull against each other, and both must hold:
//
//   - the exemption cannot be removed (a 429 on a liveness probe restarts a healthy
//     process; a 429 on readiness pulls a serving instance out of rotation), so
//   - the exempted work must be bounded: one check per readinessTTL, shared, with
//     everyone else answered from the last result instead of queueing or shedding.
func TestZZProbeReadyzIsBoundedAndNeverShed(t *testing.T) {
	// The observable is the number of dependency checks: it is what costs a pool
	// connection, and no status code can show it.
	counted := func(t *testing.T) (*httpapi.Server, *int64) {
		t.Helper()
		var checks int64
		srv, err := httpapi.New(httpapi.Config{
			Issuer:            "https://op.verify.test",
			OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			TokenIntrospector: stubIntrospector{},
			GrantStore:        stubGrants{},
			DeviceStore:       stubDevices{},
			// A saturated bucket and a full in-flight cap: the state the exemption
			// exists for, and the state the amplification was measured in.
			Limiter:     ratelimit.New(0.001, 1),
			MaxInFlight: 1,
			Ready: func(context.Context) error {
				atomic.AddInt64(&checks, 1)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("httpapi.New: %v", err)
		}
		return srv, &checks
	}

	t.Run("A a flood costs one dependency check", func(t *testing.T) {
		srv, checks := counted(t)
		handler := srv.Handler()

		// Spend the limiter's single token, so the bucket is genuinely empty and the
		// probes below are really on the exempt path.
		first := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/v1/me")
		second := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/v1/me")
		if first.Code != http.StatusUnauthorized || second.Code != http.StatusTooManyRequests {
			t.Fatalf("the limiter is not engaged: %d then %d", first.Code, second.Code)
		}

		const callers = 64
		var wg sync.WaitGroup
		codes := make([]int, callers)
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
				req.RemoteAddr = "203.0.113.9:1234" // the throttled address
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				codes[i] = rec.Code
			}(i)
		}
		wg.Wait()

		for i, code := range codes {
			if code != http.StatusOK {
				t.Fatalf("concurrent /readyz call %d = %d, want 200: a probe was shed because the service was busy", i, code)
			}
		}
		if got := atomic.LoadInt64(checks); got != 1 {
			t.Errorf("%d concurrent probes ran %d dependency checks, want 1: each one is a pooled database round trip, "+
				"so the endpoint that reports on the pool is the one that exhausts it", callers, got)
		}
		t.Logf("%d concurrent probes from a throttled address: all 200, %d dependency checks",
			callers, atomic.LoadInt64(checks))
	})

	t.Run("B the result is refreshed once the TTL passes", func(t *testing.T) {
		srv, checks := counted(t)
		if rec := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
			t.Fatalf("/readyz = %d", rec.Code)
		}
		// A cached result is not a frozen one: past the TTL the check runs again, so
		// an instance that lost its database stops being reported ready.
		time.Sleep(1200 * time.Millisecond)
		if rec := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
			t.Fatalf("/readyz = %d after the TTL", rec.Code)
		}
		if got := atomic.LoadInt64(checks); got != 2 {
			t.Errorf("dependency checks = %d, want 2: the cached result outlived its TTL", got)
		}
	})

	t.Run("C a failing dependency is still reported", func(t *testing.T) {
		var failing atomic.Bool
		srv, err := httpapi.New(httpapi.Config{
			Issuer:            "https://op.verify.test",
			OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			TokenIntrospector: stubIntrospector{},
			GrantStore:        stubGrants{},
			DeviceStore:       stubDevices{},
			Ready: func(context.Context) error {
				if failing.Load() {
					return context.DeadlineExceeded
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("httpapi.New: %v", err)
		}
		if rec := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
			t.Fatalf("/readyz = %d while healthy", rec.Code)
		}
		failing.Store(true)
		time.Sleep(1200 * time.Millisecond)
		if rec := zzCall(t, srv, "203.0.113.9:1234", http.MethodGet, "/readyz"); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("/readyz = %d while the dependency is down, want 503", rec.Code)
		}
	})
}
