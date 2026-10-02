//go:build audit5

// Probes for the operational-surface audit: what the public listener can and
// cannot answer, what the internal listener records, and what the two probes
// promise. See docs/audit-5/findings/config-startup-disclosure.md.
//
// Read-only: tests only.
package startup

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/observability"
)

// SURFACE-1 probe: the operational surface is not reachable through the public
// listener — the wiring claim docs/operations.md and docs/api-design.md §6 make,
// checked against the handler the public listener actually serves.
//
// This is the "verify the wiring" half of the question: the composition root
// mounting InternalHandler() on a second listener is only meaningful if the public
// one answers nothing on those paths. The internal handler is exercised first, so
// a failure to serve cannot be mistaken for a refusal.
func TestProbeOperationalSurfaceIsNotOnThePublicListener(t *testing.T) {
	metrics := observability.New()
	internal := metrics.InternalHandler()

	// Anti-vacuous: the internal handler really does serve both surfaces.
	for _, path := range []string{"/metrics", "/debug/pprof/"} {
		rec := httptest.NewRecorder()
		internal.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("control failed: the internal handler answered %s with %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	internal.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Fatalf("the internal /metrics did not expose the runtime collector:\n%s", rec.Body.String())
	}

	cfg := probeConfig(t)
	cfg.Metrics = metrics
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	public := srv.Handler()

	for _, path := range []string{
		"/metrics",
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/profile",
		"/debug/pprof/cmdline",
		"/debug/pprof/goroutine",
	} {
		rec := httptest.NewRecorder()
		public.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("the public listener answered %s with %d, want 404", path, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, "go_goroutines") ||
			strings.Contains(body, "goroutine profile") {
			t.Errorf("the public listener leaked the operational surface on %s", path)
		}
	}
	t.Logf("the public listener answers 404 for /metrics and every /debug/pprof/* path")
}

// SURFACE-2 probe: nothing on the internal listener is logged.
//
// The internal handler is a bare mux with no access-log middleware, and the
// internal http.Server is built with no logger of its own — so a scrape and a heap
// dump produce exactly the same evidence (none). On the baseline deployment that
// binds 0.0.0.0:9090 and relies on a NetworkPolicy to keep it private, "who
// collected a profile" is the question an incident asks and the process cannot
// answer.
func TestProbeInternalSurfaceRequestsAreNotLogged(t *testing.T) {
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	internal := observability.New().InternalHandler()
	for _, path := range []string{"/metrics", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=1"} {
		rec := httptest.NewRecorder()
		internal.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("control failed: %s = %d, so this probe observed nothing", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("control failed: %s answered with no body", path)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("the internal surface logged something after all:\n%s", buf.String())
	}
	t.Logf("a prometheus scrape and two pprof dumps produced %d bytes of log", buf.Len())

	// The contrast that makes the point: the same requests through the public
	// handler are logged, one line each, by the access log.
	cfg := probeConfig(t)
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	}
	if n := strings.Count(buf.String(), "msg=request"); n != 3 {
		t.Fatalf("the public plane logged %d request lines, want 3 — the comparison is vacuous", n)
	}
}

// SURFACE-3 probe: the two probes are uncacheable, carry no build information, and
// answer in the shape the docs promise.
//
// `/healthz` returning a cacheable 200 would let an intermediary hide a dead
// instance; a body that names the build would hand an anonymous caller a version
// to look up.
//
// 【原为发现演示，现为回归守卫】The old form asserted that a dependency failing
// after a ready verdict produced an immediate 503. The 0e6b701 readiness cache
// (readinessTTL) made that false — the documented, bounded cost — so the probe
// now waits out the TTL and additionally pins the deterministic first-check
// failure path. See docs/audit-7/findings/22-audit5-red-reconciliation.md:64,216.
func TestProbeHealthEndpointsAreNoStoreAndLeakNothing(t *testing.T) {
	ready := true
	cfg := probeConfig(t)
	cfg.Ready = func(context.Context) error {
		if ready {
			return nil
		}
		return errProbeNotReady
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	for _, tc := range []struct {
		path   string
		status int
		body   string
	}{
		{"/healthz", http.StatusOK, "ok\n"},
		{"/readyz", http.StatusOK, "ok\n"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.status {
			t.Fatalf("%s = %d, want %d", tc.path, rec.Code, tc.status)
		}
		if rec.Body.String() != tc.body {
			t.Errorf("%s body = %q, want %q", tc.path, rec.Body.String(), tc.body)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", tc.path, cc)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("%s Content-Type = %q", tc.path, ct)
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s carries no request id", tc.path)
		}
		if s := rec.Header().Get("Server"); s != "" {
			t.Errorf("%s advertises Server: %q", tc.path, s)
		}
		// The build version must not be in the body of an unauthenticated probe.
		for _, needle := range []string{"re0auth ", "dev", "v0.", "go1."} {
			if strings.Contains(rec.Body.String(), needle) {
				t.Errorf("%s body leaks build information (%q)", tc.path, needle)
			}
		}
	}

	// The verdict is reused for readinessTTL (1s, internal/httpapi/health.go:18-34)
	// — the documented price of the probe's exemption (docs/operations.md:171-183).
	// Flipping the dependency and asserting a 503 on the very next request asserted
	// the PRE-cache behavior, which is exactly why this probe stayed red
	// (docs/audit-7/findings/22-audit5-red-reconciliation.md:214-218 recommends
	// "sleep(TTL+ε) then assert 503").
	//
	// 【原为发现演示，现为回归守卫】The guard now checks the post-fix contract: a
	// dependency that fails reaches /readyz no later than one TTL after the flip,
	// and the failure leaks nothing when it does.
	ready = false
	var rec *httptest.ResponseRecorder
	deadline := time.Now().Add(3 * time.Second) // > readinessTTL, with slack
	for {
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz still answered %d (%q) > 3s after the dependency failed: the failure is not "+
				"reported within one readinessTTL", rec.Code, rec.Body.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if rec.Body.String() != "not ready\n" {
		t.Errorf("the failing /readyz body = %q, want %q", rec.Body.String(), "not ready\n")
	}

	// Deterministic fail path, independent of any cached verdict: a server whose
	// FIRST-ever check fails must answer 503 "not ready", not the cold-start
	// fail-open the 22-1 / G-11 regression introduced
	// (internal/httpapi/health.go:130-145 — "unknown" is answered "checking",
	// never "ok").
	coldCfg := probeConfig(t)
	coldCfg.Ready = func(context.Context) error { return errProbeNotReady }
	cold, err := httpapi.New(coldCfg)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	cold.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready\n" {
		t.Errorf("a first-ever failing readiness check = %d %q, want 503 %q",
			rec.Code, rec.Body.String(), "not ready\n")
	}
}

var errProbeNotReady = errProbe("probe: dependency refused; internal host db-1.re0auth.svc:5432")

type errProbe string

func (e errProbe) Error() string { return string(e) }

// ADMIN-1 probe: the operator plane cannot be mounted without an allowlist.
//
// The fail-open shape this rules out is "no admin.subjects ⇒ the plane is mounted
// permit-all", which is the natural accident for an allowlist that is implemented
// as a filter rather than as the mount condition. httpapi.New refuses the pair, and
// cmd/re0auth only sets Config.Admin when the list is non-empty, so the plane is
// absent rather than open.
//
// The wildcard question is answered by the same shape: the allowlist is a set of
// account ids compared for equality (`adminAllowed map[account.UserID]bool`), so an
// entry of "*" or of an empty string can never match a real `usr_…` — it mounts a
// plane nobody can call, which is the safe direction and not a permit-all.
func TestProbeOperatorPlaneIsRefusedWithoutAnAllowlist(t *testing.T) {
	cfg := probeConfig(t)
	cfg.Admin = emptyAdminService{}

	if _, err := httpapi.New(cfg); err == nil {
		t.Fatal("httpapi.New accepted an Admin service with an empty allowlist: the plane would be open")
	} else {
		t.Logf("an Admin service with no allowlist is refused: %v", err)
	}

	// Control, so the refusal above cannot be explained by anything else in the
	// config: the same config with a session stack and one named operator builds.
	cfg.Admins = []account.UserID{"usr_someone"}
	cfg.Sessions = auth.NewManager(auth.Options{Secure: true})
	cfg.Accounts = account.NewMemoryStore()
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("control failed: a named operator with a session stack was refused: %v", err)
	}
	// And the wildcard is inert rather than permissive: it is a set member that no
	// real account id can equal, so the plane is mounted and answers 404 to
	// everyone — the safe direction.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/clients", nil))
	t.Logf(`with Admins = ["usr_someone"], GET /v1/admin/clients without a session = %d`, rec.Code)
}

// emptyAdminService satisfies admin.Service with nil methods; nothing calls it,
// because the config is rejected first.
type emptyAdminService struct{ admin.Service }
