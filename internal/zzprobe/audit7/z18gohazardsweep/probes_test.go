//go:build audit7

// Z18 probes. The first three began as the zone's red findings; their fixes have
// landed, so each is now the regression guard for its fix (names kept for the
// audit coverage matrix):
//
//   - Z18-1 TestZ18ReadinessIsFailOpenWhileTheFirstCheckRuns
//   - Z18-2 TestZ18ConcurrentLoginIsBlockedByAnotherLoginsDiscovery
//   - Z18-3 TestZ18IntrospectionDoesNotHandOutTheStoredScopeSlice
//   - guard TestZ18NonPositiveBulkheadCapIsIgnored
package zzprobe_z18gohazardsweep

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------- httpapi stubs

type zzIntrospector struct{}

func (zzIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type zzGrants struct{}

func (zzGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (zzGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type zzDevices struct{}

func (zzDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (zzDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

type zzOIDC struct{}

func (zzOIDC) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// zzReadyServer mounts the real middleware chain with a readiness probe under
// the caller's control.
//
// The fixture installs a REAL rate limiter and in-flight cap (one token, one
// slot) rather than leaving both disabled. With Limiter nil and MaxInFlight 0 the
// chain's probe exemption is untestable: there is no bound for the probe to be
// exempt from, so a /readyz that answered 200 would prove only that nothing was
// saturated. Every probe built on this fixture now runs against a server whose
// budget is spent and whose slot is held. Callers that need a different wiring
// (a blocking introspector, say) pass an option.
func zzReadyServer(t *testing.T, ready httpapi.ReadinessProbe, opts ...func(*httpapi.Config)) *httptest.Server {
	t.Helper()
	cfg := httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              zzOIDC{},
		TokenIntrospector: zzIntrospector{},
		GrantStore:        zzGrants{},
		DeviceStore:       zzDevices{},
		Ready:             ready,
		// One token, effectively no refill, and one in-flight slot: the smallest
		// bounds the middleware can be configured with, so saturating them is
		// one request each.
		Limiter:     ratelimit.New(0.001, 1),
		MaxInFlight: 1,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	api, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func zzGet(t *testing.T, srv *httptest.Server, path string) int {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// zzGetBearer is zzGet with a bearer token, so the request reaches the business
// plane's introspector (and therefore the limiter and the in-flight cap) instead
// of being answered 401 before either sees it.
func zzGetBearer(t *testing.T, srv *httptest.Server, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer zz-stub")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// zzBlockingIntrospector parks an authenticated request inside the business
// plane until released, so the single in-flight slot stays held in a way the
// test controls rather than a sleep guesses at.
type zzBlockingIntrospector struct {
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	calls       atomic.Int64
}

// unblock releases a parked call, at most once. The test registers it as a
// cleanup, so a failure before the normal release point cannot leave the
// httptest server waiting on a request that will never finish.
func (b *zzBlockingIntrospector) unblock() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func (b *zzBlockingIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	// Only the FIRST call parks. That way a fixture with no in-flight cap cannot
	// deadlock the probe: the second call answers, and the control assertion (which
	// expects a refusal) fails visibly instead of hanging.
	if b.calls.Add(1) == 1 {
		close(b.entered)
		<-b.release
	}
	return oauth.TokenInfo{
		Active: true, Subject: "usr_z18", ClientID: "cli",
		Scopes: []oauth.Scope{oauth.ScopeAccountID},
	}, nil
}

// ---------------------------------------------------------------- Z18-1

// TestZ18ReadinessIsFailOpenWhileTheFirstCheckRuns was the Z18-1 finding and is
// now its regression guard (the name is kept for the audit coverage matrix).
//
// The finding: readinessCache.check returned c.err whenever `fresh || c.running`,
// so during the window in which the first dependency check was in flight `checked`
// was still false and c.err was still nil, and every /readyz answered 200 "ready"
// even with the dependency down. The cache now fails closed until the first result
// exists, and the assertion below fails if that regresses.
func TestZ18ReadinessIsFailOpenWhileTheFirstCheckRuns(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	ready := func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			select {
			case started <- struct{}{}:
			default:
			}
			// Park the FIRST check: it is what "a dependency round trip that
			// has not answered yet" looks like.
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return errors.New("database unreachable")
	}
	srv := zzReadyServer(t, ready)

	// Request 1 starts the first, cold check and parks inside it.
	first := make(chan int, 1)
	go func() { first <- zzGet(t, srv, "/readyz") }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the readiness probe was never invoked")
	}

	// Request 2 arrives while request 1's dependency check is still running and
	// no result has EVER been cached for this process.
	code2 := zzGet(t, srv, "/readyz")

	close(release)
	code1 := <-first

	// Positive control: once the (failing) result exists, every /readyz is 503.
	code3 := zzGet(t, srv, "/readyz")
	if code1 != http.StatusServiceUnavailable || code3 != http.StatusServiceUnavailable {
		t.Fatalf("control failed: /readyz after the failing check = %d (first) / %d (third), want 503 each; "+
			"the probe does not report the dependency failure at all, so this fixture cannot attribute anything",
			code1, code3)
	}
	if calls.Load() != 1 {
		t.Fatalf("the in-flight short-circuit did not hold: the probe ran %d times", calls.Load())
	}

	if code2 != http.StatusServiceUnavailable {
		t.Errorf("REGRESSION: a /readyz that arrived while the first dependency check was still in flight "+
			"answered %d (the dependency is down and the later, cached answer is 503). The readiness cache "+
			"must fail closed until the first result exists, rather than answer the zero-value nil error "+
			"while `running` is true (Z18-1 regressed). An orchestrator probing this window would route "+
			"traffic to an instance that cannot serve it.", code2)
	}
}

// TestZ18ProbesAreExemptFromSaturatedLimiterAndInFlight makes the middleware's
// probe exemption falsifiable.
//
// The exemption is a load-bearing claim in docs/operations.md: a saturated
// bucket must not fail a liveness probe and get a healthy process restarted, and
// it must not fail a readiness probe and pull a serving instance out of
// rotation. A fixture with Limiter nil and MaxInFlight 0 cannot test it — there
// is no bound to be exempt from. This probe therefore drives a server whose rate
// bucket is empty AND whose only in-flight slot is held, and asserts that the
// probe still answers 200 while a business request from the same address is
// refused with 503 (in-flight full) and 429 (bucket empty). Both controls are
// asserted first: if the business path were not refused, a 200 on /readyz would
// prove nothing about an exemption.
func TestZ18ProbesAreExemptFromSaturatedLimiterAndInFlight(t *testing.T) {
	var readyCalls atomic.Int64
	block := &zzBlockingIntrospector{entered: make(chan struct{}), release: make(chan struct{})}
	srv := zzReadyServer(t, func(context.Context) error {
		readyCalls.Add(1)
		return nil
	}, func(cfg *httpapi.Config) {
		cfg.TokenIntrospector = block
	})
	// Registered AFTER the server, so LIFO cleanup runs this first: a failure
	// before the normal release point must not leave the httptest server waiting
	// on the parked request forever.
	t.Cleanup(block.unblock)

	// ---- saturation 1: the in-flight cap is full -----------------------------
	//
	// One authenticated request is parked inside the introspector. MaxInFlight is
	// 1 and the per-client share is max(1/2, 1) = 1, so this request alone holds
	// the cap the chain shares with every other caller.
	held := make(chan int, 1)
	go func() { held <- zzGetBearer(t, srv, "/v1/me") }()
	select {
	case <-block.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request that was meant to hold the in-flight slot never reached the introspector")
	}

	// Control: a second business request from the same address is refused for
	// concurrency. Without this, a 200 on the probe below would not be attributable
	// to the exemption.
	if got := zzGetBearer(t, srv, "/v1/me"); got != http.StatusServiceUnavailable {
		t.Fatalf("control failed: a business request while the only in-flight slot was held answered %d, "+
			"want 503; the cap is not engaged, so the probe exemption cannot be observed here", got)
	}

	// The fact under test: the readiness probe is served anyway.
	if got := zzGet(t, srv, "/readyz"); got != http.StatusOK {
		t.Errorf("REGRESSION: /readyz = %d while the in-flight cap was full (the business plane answered "+
			"503 for the same condition). A readiness probe that fails under load pulls a serving instance "+
			"out of rotation exactly when it is needed most; the probe paths must stay exempt from the "+
			"in-flight cap.", got)
	}

	// Release the holder, so the limiter half starts from a clean concurrency
	// state. The holder spent the single rate-limit token on its way in.
	block.unblock()
	if code := <-held; code != http.StatusOK {
		t.Fatalf("control failed: the request that held the slot answered %d, want 200 (the fixture, not "+
			"the exemption, is broken)", code)
	}

	// ---- saturation 2: the rate bucket is empty ------------------------------
	//
	// The holder spent the burst's single token and the refill is 1/1000 per
	// second, so the bucket is empty for the rest of this probe.
	if got := zzGetBearer(t, srv, "/v1/me"); got != http.StatusTooManyRequests {
		t.Fatalf("control failed: a business request after the single token was spent answered %d, want "+
			"429; the bucket is not empty, so the probe exemption cannot be observed here", got)
	}

	// The fact under test, from the same (throttled) address.
	if got := zzGet(t, srv, "/readyz"); got != http.StatusOK {
		t.Errorf("REGRESSION: /readyz = %d from an address whose rate bucket is empty (its business "+
			"requests answer 429). A throttled readiness probe pulls a serving instance out of rotation; "+
			"the probe paths must stay exempt from the limiter.", got)
	}
	if readyCalls.Load() == 0 {
		t.Fatal("the readiness probe was never invoked, so the 200s above did not come from the readiness path")
	}
}

// ---------------------------------------------------------------- Z18-2

// TestZ18ConcurrentLoginIsBlockedByAnotherLoginsDiscovery was the Z18-2 finding
// and is now its regression guard (the name is kept for the audit coverage matrix).
//
// The finding: Client.oidcProvider held providerMu across the outbound discovery
// request, so a second sign-in for the same provider could not proceed until the
// first one's discovery answered. The provider is now discovered without the lock
// held, and the second login in this probe must finish while the first discovery is
// still parked.
func TestZ18ConcurrentLoginIsBlockedByAnotherLoginsDiscovery(t *testing.T) {
	var discoCalls atomic.Int64
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var base string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Only the FIRST discovery request is slow. Everything after it answers
		// immediately, so a caller that is not serialised does not wait.
		if discoCalls.Add(1) == 1 {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	issuer := httptest.NewServer(mux)
	defer issuer.Close()
	base = issuer.URL

	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   issuer.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.Provider("zzoidc"), ClientID: "cid", ClientSecret: "sec",
			Issuer: issuer.URL,
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}
	c, ok := reg.Get(idp.Provider("zzoidc"))
	if !ok {
		t.Fatal("the custom provider was not registered")
	}

	// Login 1: issuer-only provider, so this is what discovers the endpoints.
	first := make(chan error, 1)
	go func() {
		_, err := c.AuthCodeURL(context.Background(), "st-1", c.NewVerifier(), "n-1")
		first <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery was never requested")
	}

	// Login 2: an independent browser session, same provider. The issuer answers
	// this cheaply; nothing but providerMu can make it wait.
	second := make(chan error, 1)
	go func() {
		_, err := c.AuthCodeURL(context.Background(), "st-2", c.NewVerifier(), "n-2")
		second <- err
	}()
	secondFinished := false
	select {
	case err := <-second:
		secondFinished = true
		if err != nil {
			t.Fatalf("second login: %v", err)
		}
	case <-time.After(400 * time.Millisecond):
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first login: %v (the fixture, not the lock, is broken)", err)
	}
	if !secondFinished {
		if err := <-second; err != nil {
			t.Fatalf("second login (late): %v", err)
		}
		t.Errorf("REGRESSION: a second sign-in on the same provider did not complete while the first one's "+
			"discovery was still in flight, although the issuer answers a later discovery immediately (%d "+
			"requests seen). The provider's discovery must run without the provider mutex held, or every "+
			"concurrent login for that provider queues behind one network round trip (Z18-2 regressed).",
			discoCalls.Load())
	}
}

// ---------------------------------------------------------------- Z18-3

// TestZ18IntrospectionDoesNotHandOutTheStoredScopeSlice was the Z18-3 finding and
// is now its regression guard (the name is kept for the audit coverage matrix).
//
// The finding: oauth/tokens.go stored AccessToken by value but its Scopes field is
// a slice header, so the store and the caller shared one backing array and
// Service.Introspect handed that array to its caller as TokenInfo.Scopes. The store
// now copies the slice on return, so a consumer that narrows, sorts or writes the
// scopes it was handed cannot edit a live token's grant.
func TestZ18IntrospectionDoesNotHandOutTheStoredScopeSlice(t *testing.T) {
	ctx := context.Background()
	store := oauth.NewMemoryStore()

	scopes := make([]oauth.Scope, 1, 8) // spare capacity: exactly the aliasing case
	scopes[0] = oauth.ScopeAccountID
	if err := store.SaveAccess(ctx, "zz-token-value", oauth.AccessToken{
		ClientID: "cli", Subject: "usr_1", Scopes: scopes,
	}); err != nil {
		t.Fatalf("SaveAccess: %v", err)
	}

	// Positive control: the record is readable and carries what was written.
	got, err := store.GetAccess(ctx, "zz-token-value")
	if err != nil {
		t.Fatalf("GetAccess: %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != oauth.ScopeAccountID {
		t.Fatalf("control failed: stored scopes = %v, want [%s]", got.Scopes, oauth.ScopeAccountID)
	}

	// A consumer narrows the slice it was handed (the shape Introspect's caller
	// can write in one line) without touching the store.
	got.Scopes[0] = oauth.Scope("phigros.score.read")

	again, err := store.GetAccess(ctx, "zz-token-value")
	if err != nil {
		t.Fatalf("GetAccess (second): %v", err)
	}
	if again.Scopes[0] != oauth.ScopeAccountID {
		t.Errorf("REGRESSION: rewriting the slice returned by GetAccess changed the STORED token's scope from %q "+
			"to %q. The store must copy Scopes on return (the copy-on-return invariant 05-4 established for the "+
			"OP store, applied here), or a caller that narrows or reorders the scopes it introspected grants or "+
			"revokes scopes on a live token (Z18-3 regressed).",
			oauth.ScopeAccountID, again.Scopes[0])
	}
}

// ---------------------------------------------------------------- guard (green)

// TestZ18NonPositiveBulkheadCapIsIgnored is the positive control for the
// int-to-uint conversion at httpclient/outbound.go:203-210: maxConcurrent <= 0
// must return next unchanged rather than converting a negative int into an
// enormous uint capacity. It is green today and is the guard that keeps it so.
//
// The pointer-identity half alone cannot tell "no bulkhead was installed" from
// "a bulkhead was installed that bounds nothing", so the second half drives three
// concurrent RoundTrips through Bulkhead(next, 2) against a transport that parks.
// The third must be held at the gate — it must not reach the wrapped transport
// while two are inside — and it must proceed once a slot frees, which is what
// distinguishes "queued" from "dropped".
func TestZ18NonPositiveBulkheadCapIsIgnored(t *testing.T) {
	next := http.RoundTripper(http.DefaultTransport)
	for _, cap := range []int{0, -1, -1 << 20} {
		got := httpclient.Bulkhead(next, cap)
		if got != next {
			t.Errorf("Bulkhead(next, %d) installed a bulkhead; a non-positive cap must be ignored", cap)
		}
	}
	if got := httpclient.Bulkhead(next, 1); got == next {
		t.Error("Bulkhead(next, 1) did not install anything, so the check above proves nothing")
	}

	// Behavioural half: the cap of two must actually bound concurrency.
	gate := &zzGatedTransport{entering: make(chan struct{}, 3), release: make(chan struct{})}
	bounded := httpclient.Bulkhead(gate, 2)
	runs := make(chan error, 3)
	run := func() {
		resp, err := bounded.RoundTrip(zzStubRequest(t))
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		runs <- err
	}
	go run()
	go run()
	for i := 0; i < 2; i++ {
		select {
		case <-gate.entering:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of the first two RoundTrips reached the wrapped transport", i)
		}
	}
	if got := gate.inFlight.Load(); got != 2 {
		t.Fatalf("in-flight through the wrapped transport = %d, want 2", got)
	}

	// The third concurrent RoundTrip must be blocked at the bulkhead: while the
	// cap is full it may neither enter the wrapped transport nor return.
	go run()
	select {
	case <-gate.entering:
		t.Fatal("a third concurrent RoundTrip entered the wrapped transport while Bulkhead(next, 2) " +
			"already had two in flight: the cap does not bound concurrency")
	case err := <-runs:
		t.Fatalf("a third concurrent RoundTrip returned while the cap was full (%v): it was dropped "+
			"rather than waited for", err)
	case <-time.After(300 * time.Millisecond):
	}

	// Free the two slots; the queued third must then take one.
	close(gate.release)
	for i := 0; i < 3; i++ {
		select {
		case err := <-runs:
			if err != nil {
				t.Errorf("a RoundTrip through Bulkhead(next, 2) failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of the three RoundTrips finished after the gate opened: the third was "+
				"blocked but never ran", i)
		}
	}
	if peak := gate.peak.Load(); peak > 2 {
		t.Errorf("peak concurrency through Bulkhead(next, 2) = %d, want at most 2", peak)
	}
}

// zzGatedTransport parks every RoundTrip until release is closed, and records the
// concurrency it sees, so a test can observe whether a bulkhead let a third
// request through.
type zzGatedTransport struct {
	entering chan struct{}
	release  chan struct{}
	inFlight atomic.Int32
	peak     atomic.Int32
}

func (g *zzGatedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	n := g.inFlight.Add(1)
	for {
		p := g.peak.Load()
		if n <= p || g.peak.CompareAndSwap(p, n) {
			break
		}
	}
	// Buffered so this never blocks on a test that has stopped receiving.
	g.entering <- struct{}{}
	<-g.release
	g.inFlight.Add(-1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

// zzStubRequest is a request the stub transport ignores the target of.
func zzStubRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://bulkhead.zz.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
