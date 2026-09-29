//go:build audit6

// Fixture for the zone-05 probes: the full HTTP surface over an in-memory OP
// store, wired the way cmd/re0auth wires memory mode, with a clock the probe
// owns so a record can be aged past its deadline without sleeping.
package z05memstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const (
	probeIssuer   = "https://auth.test"
	probeClientID = "cli"
	probeRedirect = "https://app.example/cb"
)

// probeSigner shares one RSA key across the whole probe binary.
var (
	probeSignerOnce sync.Once
	probeSignerKey  *rsa.PrivateKey
)

func probeSigner(t *testing.T) *oidcstore.Signer {
	t.Helper()
	probeSignerOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		probeSignerKey = key
	})
	return oidcstore.NewSigner("probe", probeSignerKey)
}

func probeCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// wallClock is a mutable clock that starts at the real wall clock (the library
// computes some deadlines with time.Now of its own, notably the device
// authorization lifetime, so the store clock must begin in agreement with it)
// and can then be advanced past any deadline the store wrote.
type wallClock struct {
	offset atomic.Int64 // nanoseconds added to the wall clock
}

func (c *wallClock) Now() time.Time {
	return time.Now().Add(time.Duration(c.offset.Load()))
}

func (c *wallClock) Advance(d time.Duration) { c.offset.Add(int64(d)) }

// newProbeClients registers the public client the probes act as.
func newProbeClients(t *testing.T) *oauth.MemoryClientRegistry {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient(probeClientID, "probe client", oauth.ClientPublic, "",
		[]string{probeRedirect}, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return clients
}

// env is the full HTTP surface over an in-memory OP store with a probe-owned
// clock, assembled the way cmd/re0auth assembles memory mode: the same session
// manager fallback, the same oidchttp wiring.
type env struct {
	srv    *httpapi.Server
	store  *memory.OIDCStore
	clock  *wallClock
	logger *audit.MemoryLogger
}

func newEnv(t *testing.T, log audit.Logger) *env {
	t.Helper()
	clients := newProbeClients(t)
	if log == nil {
		log = audit.NewMemoryLogger()
	}
	clock := &wallClock{}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(t),
		Audit:    log,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
		Now: clock.Now,
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
	srv, err := httpapi.New(httpapi.Config{
		Issuer:            probeIssuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     handler,
		Sessions:          auth.NewManager(auth.Options{Store: nil, Audit: log}),
		Accounts:          account.NewMemoryStore(),
		AuditLog:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	var logger *audit.MemoryLogger
	if l, ok := log.(*audit.MemoryLogger); ok {
		logger = l
	}
	return &env{srv: srv, store: store, clock: clock, logger: logger}
}

func (e *env) do(method, target, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// deviceStart drives the device-authorization entrance the way the OP's own
// e2e flow does: a public client posts scopes and receives a device_code and
// user_code. Returns the parsed response.
func (e *env) deviceStart(t *testing.T, scope string) map[string]any {
	t.Helper()
	form := url.Values{"client_id": {probeClientID}, "scope": {scope}}.Encode()
	rec := e.do(http.MethodPost, "/oauth/device_authorization", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("device_authorization response does not parse: %v", err)
	}
	return resp
}

// devicePoll redeems the device code at the token endpoint.
func (e *env) devicePoll(deviceCode string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {probeClientID},
		"device_code": {deviceCode},
	}.Encode()
	return e.do(http.MethodPost, "/oauth/token", form)
}
