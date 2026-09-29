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
// 12 · /.well-known/oauth-protected-resource on non-GET verbs
// ---------------------------------------------------------------------------

// TestV12WellKnownVerbMatrixAsTheEdgeAnswersIt asks all three well-known
// documents the same question and records the answer, so the claim's comparison
// ("404 here, 405 for the other two") is measured rather than assumed.
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

	answers := map[string]map[string]int{}
	for _, p := range paths {
		answers[p] = map[string]int{}
		for _, v := range verbs {
			rec := vEdgeGet(t, h, v, p)
			answers[p][v] = rec.Code
			t.Logf("%-7s %-48s -> %d  Allow=%q  Content-Type=%q",
				v, p, rec.Code, rec.Header().Get("Allow"), rec.Header().Get("Content-Type"))
		}
	}

	// The claim's comparison.
	var divergent []string
	for _, v := range verbs {
		pr := answers["/.well-known/oauth-protected-resource"][v]
		other := answers["/.well-known/openid-configuration"][v]
		if pr != other {
			divergent = append(divergent, v)
		}
	}
	if len(divergent) == 0 {
		t.Logf("FALSIFIED: all three documents answer the same code for every verb")
	} else {
		t.Errorf("CONFIRMED (verb half): /.well-known/oauth-protected-resource diverges from the OIDC "+
			"document on %v — protected-resource=%d, openid-configuration=%d. The mechanism is the ROUTE "+
			"REGISTRATION, not the shared method table: server.go:519-522 registers the other two with "+
			"`root.Handle(\"GET /.well-known/...\")` and this one with "+
			"`root.HandleFunc(\"GET /.well-known/oauth-protected-resource\", ...)`, so a wrong verb falls "+
			"through to `root.Handle(\"/.well-known/\", s.oidc)` and the OP answers the catch-all's "+
			"\"unknown OAuth endpoint\" 404 for a URL it does serve. Both are valid OAuth JSON, so the "+
			"divergence is status-code only.",
			divergent,
			answers["/.well-known/oauth-protected-resource"][divergent[0]],
			answers["/.well-known/openid-configuration"][divergent[0]])
	}

	// The Allow half, measured for every document and verb.
	var missingAllow []string
	for _, p := range paths {
		for _, v := range verbs {
			rec := vEdgeGet(t, h, v, p)
			if (rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotFound) &&
				rec.Header().Get("Allow") == "" {
				missingAllow = append(missingAllow, v+" "+p+" ("+itoa(rec.Code)+")")
			}
		}
	}
	if len(missingAllow) == 0 {
		t.Logf("FALSIFIED (Allow half): every refusal carries an Allow header")
		return
	}
	t.Errorf("CONFIRMED (Allow half, wider than claimed): %d refusals carry no Allow header at all — "+
		"%v. RFC 9110 §15.5.6 requires Allow on a 405, and RFC 9110 §15.5.5 says a 404 SHOULD NOT carry "+
		"one but a 405 MUST; the project's own writer (writeOAuthJSONError) never sets it either, so this "+
		"is not special to the protected-resource document",
		len(missingAllow), missingAllow)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestV12ProtectedResourceWrongVerbShape records exactly what the response IS,
// including the Allow header the claim says is missing, so the report can state
// the shape instead of a guess.
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

	if rec.Code == http.StatusMethodNotAllowed {
		if allow == "" {
			t.Errorf("CONFIRMED (Allow half): the 405 carries no Allow header, which RFC 9110 §15.5.6 " +
				"requires")
			return
		}
		t.Logf("FALSIFIED (Allow half): the 405 does carry Allow=%q", allow)
		return
	}
	t.Errorf("CONFIRMED (verb half): POST %s = %d, not 405", target, rec.Code)
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
