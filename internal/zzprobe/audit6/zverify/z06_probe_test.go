//go:build audit6

// Adversarial verification of claims 11 and 12 (the HTTP edge).
package zverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type vStubIntrospector struct{}

func (vStubIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, context.DeadlineExceeded
}

// The two stub types below exist only so httpapi.New accepts the config; no
// probe here reaches them.
type vStubGrants struct{}

func (vStubGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (vStubGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type vStubDevices struct{}

func (vStubDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, context.Canceled
}

func (vStubDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return context.Canceled
}

func vEdgeConfig() httpapi.Config {
	return httpapi.Config{
		Issuer: "https://vfy.test",
		OIDC: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TokenIntrospector: vStubIntrospector{},
		GrantStore:        vStubGrants{},
		DeviceStore:       vStubDevices{},
	}
}

// vRealOPConfig is the stub-config shape EXCEPT that the protocol plane is the
// real oidchttp handler. The verb matrix of the well-known documents is decided
// jointly by httpapi's mux and the OP handler's own endpointMethods table, so a
// stub handler answers 200 for every verb and measures nothing.
func vRealOPConfig(t *testing.T) httpapi.Config {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	c, err := oauth.NewClient("vfy-edge", "Vfy Edge", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("vfy-edge", key),
		Login:    func(context.Context, string) string { return "/login" },
	})
	if err != nil {
		t.Fatal(err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("vfy-edge-key-0123456789abcdef00"))
	op, err := oidchttp.New(oidchttp.Config{
		Issuer:        "https://vfy.test",
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "vfy",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := vEdgeConfig()
	cfg.OIDC = op
	return cfg
}

func vEdgeGet(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// vBlockingReady parks every readiness probe until released and counts calls.
type vBlockingReady struct {
	release chan struct{}
	calls   atomic.Int64
	err     error
}

func (b *vBlockingReady) probe(context.Context) error {
	b.calls.Add(1)
	<-b.release
	return b.err
}

// ---------------------------------------------------------------------------
// 11 · /readyz answers 200 before the first check has ever completed
// ---------------------------------------------------------------------------

// TestV11ReadyzColdStartAnswersOKBeforeTheFirstCheckCompletes recreates the race
// claim 11 describes: a dependency that is DOWN (or merely hung) is being
// checked for the first time, and a second /readyz arrives while that check is
// still running. readinessCache.check answers from c.err, which is the zero
// value (nil) until the first check stores its result.
func TestV11ReadyzColdStartAnswersOKBeforeTheFirstCheckCompletes(t *testing.T) {
	depErr := context.DeadlineExceeded // the dependency is DOWN
	ready := &vBlockingReady{release: make(chan struct{}), err: depErr}

	cfg := vEdgeConfig()
	cfg.Ready = ready.probe
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	h := srv.Handler()

	firstDone := make(chan int, 1)
	go func() {
		firstDone <- vEdgeGet(t, h, http.MethodGet, "/readyz").Code
	}()

	deadline := time.Now().Add(2 * time.Second)
	for ready.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ready.calls.Load() != 1 {
		t.Fatal("the first /readyz never entered the readiness check; the probe is vacuous")
	}

	// The first check is still parked inside the dependency.
	racing := vEdgeGet(t, h, http.MethodGet, "/readyz")
	t.Logf("the racing /readyz answered %d %q while the first-ever check was still running",
		racing.Code, racing.Body.String())

	close(ready.release)
	first := <-firstDone
	if first != http.StatusServiceUnavailable {
		t.Fatalf("the first /readyz = %d, want 503 once the failing check returned", first)
	}

	if racing.Code != http.StatusOK {
		t.Logf("FALSIFIED: the racing probe was not told \"ready\" (%d)", racing.Code)
		return
	}
	t.Errorf("CONFIRMED: /readyz answered 200 ok from an UNVERIFIED cache — the first-ever check was "+
		"still running (and later returned %v, making the first caller's answer 503) — so a cold-started "+
		"replica with a dead database is admitted by an orchestrator that polls before the first check "+
		"finishes", depErr)
}

// TestV11ReadyzNeverAnswersOKOnceAFailedCheckHasCompleted is the boundary of the
// finding: after one completed FAILED check the cached error is no longer the
// zero value, and the answer is honest for the whole TTL. This is what makes the
// window "before the first check completes" rather than a permanent fail-open.
func TestV11ReadyzNeverAnswersOKOnceAFailedCheckHasCompleted(t *testing.T) {
	ready := &vBlockingReady{release: make(chan struct{}), err: context.DeadlineExceeded}
	close(ready.release) // checks return immediately

	cfg := vEdgeConfig()
	cfg.Ready = ready.probe
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	if code := vEdgeGet(t, h, http.MethodGet, "/readyz").Code; code != http.StatusServiceUnavailable {
		t.Fatalf("the first check returned 503; got %d", code)
	}
	for i := 0; i < 3; i++ {
		if code := vEdgeGet(t, h, http.MethodGet, "/readyz").Code; code != http.StatusServiceUnavailable {
			t.Fatalf("cached answer #%d = %d, want 503", i, code)
		}
	}
	t.Logf("after one completed failed check the cache is honest for its TTL; the window is only "+
		"\"before the first check completes\" — %d checks ran so far", ready.calls.Load())
}

// TestV11ReadyzWithNoProbeIsAlwaysReady is the benign case the claim must be
// distinguished from: with no dependency configured there is nothing to verify,
// and 200 is correct.
func TestV11ReadyzWithNoProbeIsAlwaysReady(t *testing.T) {
	srv, err := httpapi.New(vEdgeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if code := vEdgeGet(t, srv.Handler(), http.MethodGet, "/readyz").Code; code != http.StatusOK {
		t.Fatalf("a probe-less deployment answered %d, want 200 (nothing to reach)", code)
	}
}

// ---------------------------------------------------------------------------
// 12 · /.well-known/oauth-protected-resource on non-GET verbs (G-24, fixed)
// ---------------------------------------------------------------------------

// TestV12WellKnownVerbMatrixAsTheEdgeAnswersIt was the G-24 probe. All three
// well-known documents now answer an unlisted verb the same way: 405 with the
// Allow header RFC 9110 §15.5.6 requires. Comparing the protected-resource
// document against its two siblings is what makes this a guard rather than a
// local assertion — the defect was exactly that the third one was wired
// differently.
func TestV12WellKnownVerbMatrixAsTheEdgeAnswersIt(t *testing.T) {
	srv, err := httpapi.New(vRealOPConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	paths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
	}
	verbs := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions}

	for _, p := range paths {
		for _, v := range verbs {
			rec := vEdgeGet(t, h, v, p)
			allow := rec.Header().Get("Allow")
			t.Logf("%-7s %-48s -> %d  Allow=%q", v, p, rec.Code, allow)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405: an unlisted verb on a document this server serves is "+
					"refused, not routed to the /.well-known/ catch-all's 404 (G-24)", v, p, rec.Code)
			}
			if allow != "GET, HEAD" {
				t.Errorf("%s %s: Allow=%q, want %q — a 405 must name what the endpoint accepts "+
					"(RFC 9110 §15.5.6)", v, p, allow, "GET, HEAD")
			}
		}
	}
}

// TestV12ProtectedResourceWrongVerbShape pins the exact shape of the response
// the finding was about: 405 in the protocol plane's error format, with Allow,
// rather than a 404 for a URL this server does serve.
func TestV12ProtectedResourceWrongVerbShape(t *testing.T) {
	srv, err := httpapi.New(vRealOPConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	target := "/.well-known/oauth-protected-resource"
	rec := vEdgeGet(t, h, http.MethodPost, target)
	allow := rec.Header().Get("Allow")
	t.Logf("POST %s = %d Allow=%q Content-Type=%q Body=%q",
		target, rec.Code, allow, rec.Header().Get("Content-Type"), rec.Body.String())

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST %s = %d, want 405", target, rec.Code)
	}
	if allow != "GET, HEAD" {
		t.Errorf("POST %s: Allow=%q, want %q", target, allow, "GET, HEAD")
	}
}

// TestV12TheOtherTwoDocumentsDoAnswer405 is the claim's control, measured the
// same way: if the two discovery documents did not answer 405 either, the
// comparison would be vacuous.
func TestV12TheOtherTwoDocumentsDoAnswer405(t *testing.T) {
	srv, err := httpapi.New(vRealOPConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, p := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	} {
		rec := vEdgeGet(t, h, http.MethodPost, p)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s = %d, want 405 — the claim's premise about the sibling documents is false",
				p, rec.Code)
		}
		t.Logf("POST %s = 405 Allow=%q body=%q", p, rec.Header().Get("Allow"), rec.Body.String())
	}
}
