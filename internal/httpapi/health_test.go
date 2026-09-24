package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// healthServer builds the full surface with the readiness probe and limiter under
// test, so the probes are exercised through the same middleware stack a
// deployment runs rather than a bare handler.
func healthServer(t *testing.T, ready ReadinessProbe, limiter *ratelimit.Limiter) *Server {
	t.Helper()
	cfg := newFullConfig(t)
	cfg.Ready = ready
	cfg.Limiter = limiter
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func probe(t *testing.T, h http.Handler, path, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Liveness must not depend on a dependency being up. A liveness probe that fails
// when the database is down turns one outage into a restart loop: the orchestrator
// kills a process that was never the problem, and the restart cannot fix a
// database.
func TestHealthzIsLivenessOnly(t *testing.T) {
	srv := healthServer(t, func(context.Context) error {
		return errors.New("database is on fire")
	}, nil)

	rec := probe(t, srv.Handler(), "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d with a failing dependency, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "ok\n" {
		t.Fatalf("/healthz body = %q, want %q", body, "ok\n")
	}
}

// Without a probe there is nothing to reach — the in-memory deployment — so
// readiness is honestly always true.
func TestReadyzWithoutProbeIsReady(t *testing.T) {
	srv := healthServer(t, nil, nil)
	rec := probe(t, srv.Handler(), "/readyz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d without a probe, want 200", rec.Code)
	}
}

// Readiness tracks the probe: 200 when the dependency answers, 503 when it does
// not, so an orchestrator stops routing to an instance that cannot serve.
func TestReadyzTracksTheProbe(t *testing.T) {
	var err error
	srv := healthServer(t, func(context.Context) error { return err }, nil)
	handler := srv.Handler()

	if rec := probe(t, handler, "/readyz", ""); rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d with a healthy probe, want 200", rec.Code)
	}

	err = errors.New("connection refused")
	rec := probe(t, handler, "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d with a failing probe, want 503", rec.Code)
	}
	if body := rec.Body.String(); body != "not ready\n" {
		t.Fatalf("/readyz body = %q, want %q", body, "not ready\n")
	}
}

// The readiness endpoint is reachable without credentials, so the dependency's
// error must not reach the caller: it can name an internal host or topology an
// anonymous probe has no business learning. The reason belongs in the log.
func TestReadyzDoesNotLeakTheProbeError(t *testing.T) {
	secret := "dial tcp 10.0.0.7:5432: connection refused"
	srv := healthServer(t, func(context.Context) error { return errors.New(secret) }, nil)

	rec := probe(t, srv.Handler(), "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.7") || strings.Contains(rec.Body.String(), "dial tcp") {
		t.Fatalf("/readyz leaked the dependency error: %q", rec.Body.String())
	}
}

// Probes are exempt from the limiter. Under the load that fills a bucket, a
// throttled liveness probe would have a healthy process restarted and a throttled
// readiness probe would pull a serving instance out of rotation — the opposite of
// what is wanted at exactly that moment.
func TestProbesAreExemptFromTheLimiter(t *testing.T) {
	srv := healthServer(t, nil, ratelimit.New(0.001, 1)) // one token, effectively no refill
	handler := srv.Handler()
	const remote = "203.0.113.9:1234"

	// Spend the single token on a business-plane request, then confirm the bucket
	// is actually empty: without this the exemption test could pass vacuously.
	if rec := probe(t, handler, "/v1/me", remote); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first /v1/me = %d, want 401", rec.Code)
	}
	if rec := probe(t, handler, "/v1/me", remote); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /v1/me = %d, want 429 — the limiter is not engaged", rec.Code)
	}

	for i := 0; i < 5; i++ {
		for _, path := range []string{"/healthz", "/readyz"} {
			if rec := probe(t, handler, path, remote); rec.Code != http.StatusOK {
				t.Fatalf("%s = %d on attempt %d from a throttled address, want 200", path, rec.Code, i)
			}
		}
	}
}

// A probe is still an HTTP response from this service, so it carries the same
// defensive headers and request id as everything else. A cached readiness result
// is worse than none, so it is explicitly not storable.
func TestProbesCarryHeadersAndAreNotCached(t *testing.T) {
	srv := healthServer(t, nil, nil)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := probe(t, srv.Handler(), path, "")
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("%s Content-Type = %q", path, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", path, cc)
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s is missing a request id", path)
		}
		assertSecurityHeaders(t, rec.Header())
	}
}
