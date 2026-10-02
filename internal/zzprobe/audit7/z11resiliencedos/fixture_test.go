//go:build audit7

// Package zzprobe_z11resiliencedos — round-7 audit probes, area Z11
// (resilience / rate limiting / concurrency caps / DoS surface).
//
// Every probe here drives the REAL HTTP surface (internal/httpapi mounted on an
// httptest server) rather than an internal function. Two harnesses are provided:
//
//   - miniAPI, which mounts the real middleware chain (limiter, in-flight cap,
//     compression, security headers, access log, recoverers) with stub OIDC and
//     stub business seams. It is enough for probes about the middleware itself.
//   - dataAPI, which additionally wires a real federation service over a real
//     upstream httptest server, so the raw passthrough path (the one that holds
//     megabytes) is exercised end to end.
package zzprobe_z11resiliencedos

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// zzGame is the game the data-plane probes register a source under.
const zzGame = "phigros"

// zzScope is the resource scope the stub token carries. It is the same string
// the registered source declares, so the real scope gate admits it.
const zzScope = "phigros.profile.read"

// zzMaxBody mirrors federation's own cap (service.go: maxBody = 4 << 20).
const zzMaxBody = 4 << 20

// ---------------------------------------------------------------- stubs

type stubIntrospector struct{ info oauth.TokenInfo }

func (s stubIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return s.info, nil
}

type stubGrants struct{}

func (stubGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (stubGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type stubDevices struct{}

func (stubDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (stubDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

// stubOIDC stands in for the OP handler. It answers everything with a fixed 200,
// which is enough for probes about the middleware in front of it.
var stubOIDC = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"ok":true}`)
})

// ---------------------------------------------------------------- harnesses

// miniConfig tunes miniAPI.
type miniConfig struct {
	// Ready is the readiness probe the real /readyz path calls.
	Ready httpapi.ReadinessProbe
	// Limiter, when set, is installed. Nil disables it.
	Limiter *ratelimit.Limiter
	// MaxInFlight > 0 installs the inbound concurrency cap.
	MaxInFlight int
	// Introspector overrides the default (inactive) token introspector.
	Introspector httpapi.TokenIntrospector
	// OIDC overrides the protocol-plane handler. The default answers every
	// request immediately; a probe that needs a request to STAY in a handler
	// (to hold an in-flight slot) supplies its own.
	OIDC http.Handler
}

// miniAPI mounts the real middleware chain with stub seams.
func miniAPI(t *testing.T, cfg miniConfig) *httptest.Server {
	t.Helper()
	if cfg.Introspector == nil {
		cfg.Introspector = stubIntrospector{}
	}
	if cfg.OIDC == nil {
		cfg.OIDC = stubOIDC
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              cfg.OIDC,
		TokenIntrospector: cfg.Introspector,
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		Limiter:           cfg.Limiter,
		MaxInFlight:       cfg.MaxInFlight,
		Ready:             cfg.Ready,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// dataConfig tunes dataAPI.
type dataConfig struct {
	// Upstream is the httptest server the registered source points at.
	Upstream string
	// MaxBufferedBytes is the joint upstream-body budget under test.
	MaxBufferedBytes int
}

// dataAPI mounts the real HTTP surface with a real federation service in front
// of upstream, and returns the server plus the bearer token the business plane
// accepts.
//
// The token seam is stubbed (a fixed active TokenInfo) rather than minted
// through the OP: the probe is about the data plane's memory and the middleware
// chain, and the stub keeps the fixture deterministic. The scope gate it feeds
// is the real handler's.
func dataAPI(t *testing.T, cfg dataConfig) (*httptest.Server, string) {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: "src", DisplayName: "Src",
		Issuer:  cfg.Upstream,
		RawBase: cfg.Upstream + "/native",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzScope},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	ctx := context.Background()
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{User: account.UserID("usr_v"), Game: zzGame, Source: "src", Version: 1}
	if err := bindings.Put(ctx, binding); err != nil {
		t.Fatalf("bindings.Put: %v", err)
	}
	v := newTestVault(t)
	payload, err := json.Marshal(map[string]string{"access_token": "upstream-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(binding), payload, nil); err != nil {
		t.Fatalf("vault.Enroll: %v", err)
	}
	hc := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Breaker: &httpclient.BreakerOptions{},
	})
	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: hc, HTTPClient: hc,
		BaseURL:          "https://re0auth.test",
		MaxBufferedBytes: cfg.MaxBufferedBytes,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer: "https://re0auth.test",
		OIDC:   stubOIDC,
		TokenIntrospector: stubIntrospector{info: oauth.TokenInfo{Active: true, Subject: "usr_v", ClientID: "cli",
			// The probes here drive the RAW passthrough, which since Z20-2 needs the
			// game's explicit `<game>.raw.read` scope; the resource scope rides along
			// because some reads are normalized.
			Scopes: []oauth.Scope{zzScope, oauth.Scope(oauth.RawScope(zzGame))}}},
		GrantStore:  stubGrants{},
		DeviceStore: stubDevices{},
		Federation:  fed,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, "probe-token"
}

func newTestVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// ---------------------------------------------------------------- helpers

// get performs one unauthenticated GET and returns the status, the headers and
// the body.
func get(t *testing.T, url string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header, body
}

// getAuth is get with a bearer token.
func getAuth(t *testing.T, c *http.Client, url, token string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header, body
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// waitUntil polls cond for up to d. A probe that needs "this has happened"
// cannot use a fixed sleep without either flaking or being slow.
func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func atomicAdd(p *int64, d int64) { atomic.AddInt64(p, d) }
func atomicLoad(p *int64) int64   { return atomic.LoadInt64(p) }

// captureHandler is a slog handler that keeps everything it is handed, so a
// probe can measure what the access log wrote.
type captureHandler struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(&h.buf, "%s %s", r.Level, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&h.buf, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.buf.WriteByte('\n')
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.buf.String()
}
