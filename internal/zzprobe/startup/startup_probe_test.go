//go:build audit5

// Probes for the configuration / composition-root / observability audit
// (docs/audit-5/findings/config-startup-disclosure.md).
//
// Read-only: this package exists so the probes can import internal/... without
// touching any tracked file.
package startup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const probeIssuer = "https://auth.probe.test"

// probeCryptoKey satisfies oidchttp.Config.CryptoKey without touching a real key.
func probeCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// openProbeBackend builds the OpenID Provider the way cmd/re0auth's openOIDC
// does, because httpapi.New refuses a Config without one.
func openProbeBackend(t *testing.T, clients oauth.ClientRegistry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe", key),
		Login:    func(context.Context, string) string { return "/login" },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:        probeIssuer,
		Storage:       store,
		CryptoKey:     probeCryptoKey(),
		CryptoKeyID:   "probe",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store
}

func probeConfig(t *testing.T) httpapi.Config {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	handler, store := openProbeBackend(t, clients)
	return httpapi.Config{
		Issuer:            probeIssuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
	}
}

// blockingReady is a readiness probe that parks every caller until release is
// closed, and counts how many got in at once. It is what makes "unbounded
// concurrency" measurable instead of an assertion about a code path.
type blockingReady struct {
	release chan struct{}
	inside  atomic.Int64
	peak    atomic.Int64
	calls   atomic.Int64
}

func newBlockingReady() *blockingReady { return &blockingReady{release: make(chan struct{})} }

func (b *blockingReady) probe(context.Context) error {
	now := b.inside.Add(1)
	b.calls.Add(1)
	for {
		old := b.peak.Load()
		if now <= old || b.peak.CompareAndSwap(old, now) {
			break
		}
	}
	<-b.release
	b.inside.Add(-1)
	return nil
}

// panickyFederation panics on the one call a public route makes, so the real
// middleware chain can be driven to a panic deterministically.
type panickyFederation struct{ federation.Service }

func (panickyFederation) AllSources() []federation.Source { panic("probe: deliberate panic") }

// blockingFederation holds a request inside the handler until release, which is
// how the in-flight cap is saturated without a sleep.
type blockingFederation struct {
	federation.Service
	release chan struct{}
	entered atomic.Int64
}

func (b *blockingFederation) AllSources() []federation.Source {
	b.entered.Add(1)
	<-b.release
	return nil
}

// READY-1 probe: /readyz is exempt from both the rate limiter and the in-flight
// cap, and on a durable deployment it is not free — it is a database round trip.
//
// The exemption is deliberate and documented for the limiter ("a saturated bucket
// must not pull a serving instance out of rotation"). What the exemption does not
// distinguish is the orchestrator's probe from an anonymous caller's: both arrive
// on the public listener with no credentials, and both are admitted without
// spending a rate-limit token and without taking a slot in the concurrency cap.
//
// This probe measures the second half. It replaces the DB ping with a blocking
// function so the concurrency is observable; the durable path is
// `store.db.Ping` (cmd/re0auth/main.go:774), which acquires a pooled connection
// per call, bounded only by internal/httpapi's 2s readinessTimeout.
//
// 【原为发现演示，现为回归守卫】The 0e6b701 readiness cache — completed by the
// 22-1 / G-11 three-state fix — bounds the exempt work: at most one check runs at
// a time and its verdict is reused for readinessTTL. The old measurement (32
// concurrent calls inside the readiness probe, peak==32) is therefore no longer
// reachable and was itself the red
// (docs/audit-7/findings/22-audit5-red-reconciliation.md:63,219-221: "the red is
// the probe counting concurrent checks, not the exemption being lost"). The guard
// now pins the exemption the other way: every /readyz is admitted while the cap is
// saturated, and the dependency is reached exactly once.
func TestProbeReadyzBypassesTheLimiterAndTheInFlightCap(t *testing.T) {
	get := func(handler http.Handler, path string) int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	// Part 1: the rate limiter. One token, effectively no refill.
	limited := probeConfig(t)
	limited.Limiter = ratelimit.New(0.0001, 1)
	limited.Ready = func(context.Context) error { return nil }
	srv1, err := httpapi.New(limited)
	if err != nil {
		t.Fatal(err)
	}
	if code := get(srv1.Handler(), "/v1/me"); code != http.StatusUnauthorized {
		t.Fatalf("control failed: first /v1/me = %d, want 401", code)
	}
	if code := get(srv1.Handler(), "/v1/me"); code != http.StatusTooManyRequests {
		t.Fatalf("control failed: second /v1/me = %d, want 429", code)
	}
	for i := 0; i < 8; i++ {
		if code := get(srv1.Handler(), "/readyz"); code != http.StatusOK {
			t.Fatalf("/readyz #%d = %d, want 200 with an empty bucket", i, code)
		}
	}
	t.Logf("8 /readyz requests were served with the rate bucket already empty")

	// Part 2: the in-flight cap. The slot is held by a real request parked inside
	// the handler, so the cap can be observed to be in force.
	ready := newBlockingReady()
	blocking := &blockingFederation{release: make(chan struct{})}
	capped := probeConfig(t)
	capped.MaxInFlight = 1
	capped.Ready = ready.probe
	capped.Federation = blocking
	srv2, err := httpapi.New(capped)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv2.Handler()

	held := make(chan struct{})
	go func() {
		defer close(held)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sources", nil))
	}()
	waitFor(t, func() bool { return blocking.entered.Load() == 1 }, "the holder never entered the handler")

	if code := get(handler, "/v1/me"); code != http.StatusServiceUnavailable {
		t.Fatalf("control failed: a second ordinary request = %d, want 503 from the in-flight cap", code)
	}

	const n = 32
	var wg sync.WaitGroup
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	// The exempt work is now bounded: one readiness check runs at a time and is
	// reused for readinessTTL, so 32 concurrent probes make exactly ONE call into
	// the dependency (health.go's readinessCache). Waiting for 32 concurrent calls
	// was the pre-0e6b701 behavior and was this probe's red.
	waitFor(t, func() bool { return ready.calls.Load() == 1 }, "the readiness check did not coalesce to one call")
	close(ready.release)
	wg.Wait()
	close(blocking.release)
	<-held

	if calls := ready.calls.Load(); calls != 1 {
		t.Errorf("%d concurrent /readyz made %d readiness checks, want exactly 1 (the check must coalesce)",
			n, calls)
	}
	for i, code := range codes {
		if code == http.StatusOK {
			continue // a verdict landed before this caller was answered
		}
		// A probe must never be shed by the in-flight cap; the only 503 it may get
		// is the readiness cache's own cold-start "checking" (fail closed, never a
		// 200 without a verdict).
		if code != http.StatusServiceUnavailable || bodies[i] != "checking\n" {
			t.Fatalf("/readyz #%d = %d %q, want 200 or the readiness 503 \"checking\" — a probe was "+
				"refused by the in-flight cap", i, code, bodies[i])
		}
	}
	t.Logf("%d concurrent /readyz calls were all admitted while max_in_flight=1 was saturated; "+
		"the readiness check ran %d time(s)", n, ready.calls.Load())
}

// READY-2 probe: a readiness check that never returns holds its caller for
// exactly internal/httpapi's fixed two seconds, and refuses with 503 only then.
//
// That constant is the whole bound on how long one anonymous /readyz can occupy
// whatever the probe itself is holding — a pooled connection, on a durable
// deployment — so it is measured rather than read.
func TestProbeReadyzHoldsItsCallerForTheFixedTwoSeconds(t *testing.T) {
	blocked := make(chan struct{})
	cfg := probeConfig(t)
	cfg.Ready = func(ctx context.Context) error {
		select {
		case <-blocked:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer close(blocked)

	start := time.Now()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503", rec.Code)
	}
	if elapsed < 1900*time.Millisecond || elapsed > 2900*time.Millisecond {
		t.Fatalf("/readyz returned after %s; the readiness timeout is not the expected 2s", elapsed)
	}
	if body := rec.Body.String(); strings.Contains(body, "context") || strings.Contains(body, "deadline") {
		t.Errorf("the dependency error leaked into the unauthenticated body: %q", body)
	}
	t.Logf("an anonymous /readyz is admitted with no rate-limit token, no in-flight slot, "+
		"and holds its readiness check (a DB ping on a durable deployment) for %s", elapsed.Round(time.Millisecond))
}

// METRIC-1 probe: a recovered panic is counted exactly once, with status 500, and
// the in-flight gauge returns to zero.
//
// The order is: metrics outermost, then request context, access log and the
// browser recoverer; the plane recoverers sit inside the mux. A panic therefore
// unwinds to recoverBrowser, which writes the 500 and returns normally — so the
// counter and the histogram see a completed request rather than skipping. This
// pins that, because "the counter is only incremented after ServeHTTP returns" is
// exactly the shape that would drop every panic from the error rate.
func TestProbeRecoveredPanicIsCountedOnceAndInFlightReturnsToZero(t *testing.T) {
	metrics := observability.New()
	cfg := probeConfig(t)
	cfg.Metrics = metrics
	cfg.Federation = panickyFederation{}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sources", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panicking route = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("panic answered outside its plane: content-type %q", ct)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("the panic response carries no request id, so it cannot be correlated")
	}

	body := scrape(t, metrics)
	for _, want := range []string{
		`re0auth_http_requests_total{method="GET",plane="business",status="500"} 1`,
		`re0auth_http_in_flight_requests{plane="business"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition is missing %q:\n%s", want, body)
		}
	}
}

// LOG-1 probe: an attacker-chosen X-Request-Id reaches the log and the response
// header, and neither channel can be forged through it.
//
// The id is adopted verbatim (internal/httpapi/middleware.go:138) with no charset
// or length check, so it is worth knowing what the two sinks do with a hostile
// one. Two layers are measured, because they fail differently:
//
//   - the log sink: slog's text handler quotes any value containing a control
//     character or a space, so a bare \n cannot start a forged line;
//   - the transport: a raw socket is used, because Go's http.Client refuses to
//     send such a header at all and would otherwise make this pass vacuously.
func TestProbeAttackerRequestIDCannotForgeALogLineOrAHeader(t *testing.T) {
	cfg := probeConfig(t)
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Part 1: the in-process path, which the transport's validation does not
	// cover — httptest.NewRecorder hands the value straight to the handler.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	hostile := "req_x\nINFO server up\rX-Injected: yes\x1b[31m"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", hostile)
	srv.Handler().ServeHTTP(rec, req)

	out := buf.String()
	lines := strings.Count(strings.TrimRight(out, "\n"), "\n") + 1
	if lines != 1 {
		t.Fatalf("the access log line was forged into %d lines:\n%s", lines, out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("a raw escape byte reached the log: %q", out)
	}
	t.Logf("hostile id logged as: %s", strings.TrimRight(out, "\n"))

	// Part 2: the transport. A raw socket, so no client-side validation can make
	// the result vacuous.
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	for _, tc := range []struct {
		name string
		id   string
	}{
		{"a space", "probe id with spaces"},
		{"a bare CR", "probe\rid"},
		{"an ESC", "probe\x1b[31mid"},
	} {
		status, header := rawRequest(t, addr, tc.id)
		t.Logf("%s: status=%d X-Request-Id=%q", tc.name, status, header)
		if header != "" && strings.ContainsAny(header, "\r\n\x1b") {
			t.Fatalf("%s survived into the response header: %q", tc.name, header)
		}
	}

	// What the id does buy a caller: it is emitted verbatim, bounded only by
	// MaxHeaderBytes, so two requests can be made to share a correlation handle.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	req2.Header.Set("X-Request-Id", "req_chosen_by_the_caller")
	resp2, err := ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.Header.Get("X-Request-Id") != "req_chosen_by_the_caller" {
		t.Fatalf("the caller-chosen id was not adopted: %q", resp2.Header.Get("X-Request-Id"))
	}
}

// rawRequest writes one HTTP/1.1 request with the given header value over a bare
// TCP connection and returns the status line's code and the echoed header.
func rawRequest(t *testing.T, addr, id string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	raw := "GET /healthz HTTP/1.1\r\nHost: probe\r\nX-Request-Id: " + id + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	all, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	head, _, _ := strings.Cut(string(all), "\r\n\r\n")
	status := 0
	if _, rest, ok := strings.Cut(head, " "); ok {
		if code, _, ok := strings.Cut(rest, " "); ok {
			status, _ = strconv.Atoi(code)
		}
	}
	for _, line := range strings.Split(head, "\r\n") {
		if v, ok := strings.CutPrefix(line, "X-Request-Id: "); ok {
			return status, v
		}
	}
	return status, ""
}

// waitFor polls until cond holds, or fails the test. It fails loudly rather than
// hanging, because a probe that times out has not proved anything.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func scrape(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.InternalHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d", rec.Code)
	}
	return rec.Body.String()
}
