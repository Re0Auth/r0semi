//go:build audit7

package zzprobe_z11verify

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

const (
	zzGame    = "phigros"
	zzScope   = "phigros.profile.read"
	zzMaxBody = 4 << 20
)

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

var stubOIDC = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"ok":true}`)
})

type miniConfig struct {
	Ready       httpapi.ReadinessProbe
	Limiter     *ratelimit.Limiter
	MaxInFlight int
	OIDC        http.Handler
}

func miniAPI(t *testing.T, cfg miniConfig) *httptest.Server {
	t.Helper()
	if cfg.OIDC == nil {
		cfg.OIDC = stubOIDC
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              cfg.OIDC,
		TokenIntrospector: stubIntrospector{},
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

type dataConfig struct {
	Upstream         string
	MaxBufferedBytes int
}

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
	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"access_token": "upstream-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(binding), payload, nil); err != nil {
		t.Fatalf("vault.Enroll: %v", err)
	}
	hc := httpclient.NewOutboundClient(httpclient.OutboundConfig{Breaker: &httpclient.BreakerOptions{}})
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
		Issuer:            "https://re0auth.test",
		OIDC:              stubOIDC,
		TokenIntrospector: stubIntrospector{info: oauth.TokenInfo{Active: true, Subject: "usr_v", ClientID: "cli", Scopes: []oauth.Scope{zzScope}}},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		Federation:        fed,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, "probe-token"
}

// zzUpstream serves 4 MiB with a declared Content-Length at /native/big, and a
// header-only stall at /native/stall that stays parked until release is closed.
func zzUpstream(t *testing.T, release <-chan struct{}, stalled *int64) *httptest.Server {
	t.Helper()
	body := bytes.Repeat([]byte{'x'}, zzMaxBody)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/native/stall" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			atomic.AddInt64(stalled, 1)
			<-release
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(up.Close)
	return up
}

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

var _ = rand.Read
