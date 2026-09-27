//go:build audit5

// Package concurrency holds adversarial probes for Re0Auth's concurrency,
// goroutine/timer lifetime and in-memory-store behaviour.
//
// Every test here is a probe written by the round-N concurrency auditor. Some of
// them FAIL on the code as found: a failing probe is the evidence, and the
// assertion in it is the guard the fix should satisfy.
package concurrency

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// probeSigner shares one RSA key across the whole probe binary: generating a
// 2048-bit key costs ~100ms and every store needs one.
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

// probeCryptoKey is the OP's token-encryption key.
func probeCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// newProbeClients registers one public client allowed the scopes the probes ask
// for. A public client with no secret is what an unauthenticated caller needs:
// nothing about the requests below carries a credential.
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

// newProbeStore builds the in-memory OP store exactly the way the composition
// root and internal/httpapi's own test fixture build it.
func newProbeStore(t *testing.T, log audit.Logger) *memory.OIDCStore {
	t.Helper()
	clients := newProbeClients(t)
	st, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(t),
		Audit:    log,
		Login:    func(context.Context, string) string { return "/login?authRequestID=x" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// newProbeEnv is the full HTTP surface over an in-memory OP store, wired as
// cmd/re0auth wires it: the same session manager (with the in-memory fallback it
// uses when there is no DATABASE_URL), the same OP handler as protocol plane and
// consent interaction. The caller stays unauthenticated throughout: nothing it
// sends carries a session cookie, a bearer token or a client secret.
type probeEnv struct {
	srv    *httpapi.Server
	store  *memory.OIDCStore
	client *oauth.MemoryClientRegistry
}

func newProbeEnv(t *testing.T) *probeEnv {
	t.Helper()
	clients := newProbeClients(t)
	logger := audit.NewMemoryLogger()
	sessions := auth.NewManager(auth.Options{Store: nil, Audit: logger})
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(t),
		Audit:    logger,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
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
		Sessions:          sessions,
		Accounts:          account.NewMemoryStore(),
		AuditLog:          logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &probeEnv{srv: srv, store: store, client: clients}
}

func (e *probeEnv) do(method, target, body string) *httptest.ResponseRecorder {
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

// tokenRequest is the minimal op.TokenRequest the store's minting methods need.
func tokenRequest(subject string, scopes ...string) *oidcstore.AuthRequest {
	return &oidcstore.AuthRequest{
		ID: "req_1", ClientID: probeClientID, RedirectURI: probeRedirect,
		Subject: subject, Scopes: scopes,
	}
}

// blockingAudit is an audit.Logger whose Record signals that it has been entered
// and then blocks until the test releases it. It is how "is the store's lock held
// while the audit write runs?" is answered from the outside.
type blockingAudit struct {
	entered chan context.Context
	release chan struct{}
}

func newBlockingAudit() *blockingAudit {
	return &blockingAudit{entered: make(chan context.Context, 16), release: make(chan struct{})}
}

func (b *blockingAudit) Record(ctx context.Context, _ audit.Event) error {
	b.entered <- ctx
	<-b.release
	return nil
}

// lockHeldDuring runs op, waits for its audit write to be entered, and reports
// whether the store's own lock was held at that moment — probed by asking the
// store for something that needs the same lock.
//
// The probe is a fresh goroutine because a held lock must not block the test; the
// wait is bounded, which is the only way to observe "held" without a lock
// introspection API. There is no race detector dependency: the answer comes from
// whether a lock acquisition completes, not from a data race.
func lockHeldDuring(t *testing.T, st *memory.OIDCStore, log *blockingAudit, op func() error) bool {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()

	select {
	case <-log.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the operation never reached its audit write")
	}

	completed := make(chan struct{})
	go func() {
		_ = st.Counts() // takes the store's single lock
		close(completed)
	}()

	held := true
	select {
	case <-completed:
		held = false
	case <-time.After(500 * time.Millisecond):
	}

	close(log.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the operation did not finish after its audit write was released")
	}
	if !held {
		// The probe goroutine has already returned; nothing to wait for.
		return false
	}
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("the store's lock was never released")
	}
	return true
}

// recordingAudit keeps the context of every Record call, so a probe can ask what
// the store handed the audit logger.
type recordingAudit struct {
	mu   sync.Mutex
	ctxs []context.Context
}

func (r *recordingAudit) Record(ctx context.Context, _ audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ctxs = append(r.ctxs, ctx)
	return nil
}

func (r *recordingAudit) last() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ctxs) == 0 {
		return nil
	}
	return r.ctxs[len(r.ctxs)-1]
}

func (r *recordingAudit) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ctxs)
}
