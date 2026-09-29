//go:build audit7

// Z18 probes: three red findings plus one green guard.
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/httpapi"
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
func zzReadyServer(t *testing.T, ready httpapi.ReadinessProbe) *httptest.Server {
	t.Helper()
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              zzOIDC{},
		TokenIntrospector: zzIntrospector{},
		GrantStore:        zzGrants{},
		DeviceStore:       zzDevices{},
		Ready:             ready,
	})
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

// ---------------------------------------------------------------- Z18-1

// TestZ18ReadinessIsFailOpenWhileTheFirstCheckRuns is red while
// readinessCache.check answers from a nil error before any result exists.
//
// health.go:111-120 returns c.err whenever `fresh || c.running`. `running` is
// true for exactly the window in which the first dependency check is in flight,
// and in that window `checked` is still false and c.err is still nil — so every
// /readyz that arrives while the first check runs is answered 200 "ready",
// including when the dependency is down. The failure is silent: the caller sees
// the same 200 it would see from a healthy instance.
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
		t.Errorf("RED: a /readyz that arrived while the first dependency check was still in flight answered %d "+
			"(the dependency is down and the later, cached answer is 503). health.go:111-120 answers c.err when "+
			"`running` is true without first requiring `checked`, so before the first result exists the zero-value "+
			"nil error is indistinguishable from 'ready'. An orchestrator probing during this window routes traffic "+
			"to an instance that cannot serve it; no credential or budget is needed (probes are exempt from both).",
			code2)
	}
}

// ---------------------------------------------------------------- Z18-2

// TestZ18ConcurrentLoginIsBlockedByAnotherLoginsDiscovery is red while
// Client.oidcProvider holds a mutex across the outbound discovery request.
//
// idp.go:619-637 takes providerMu and then calls oidc.NewProvider — a network
// round trip — with the lock still held. A second sign-in for the same provider
// cannot proceed until the first one's discovery answers, so the login plane's
// throughput for that provider is 1/(discovery latency), and a slow or hanging
// issuer (the client's timeout is 10s) queues every user behind it.
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
		t.Errorf("RED: a second sign-in on the same provider did not complete while the first one's discovery was "+
			"still in flight, although the issuer answers a later discovery immediately (%d requests seen). "+
			"idp.go:620-633 holds providerMu across oidc.NewProvider, so every concurrent login for that provider "+
			"queues behind one network round trip — up to the 10s client timeout per attempt when the issuer is "+
			"slow, and a failed discovery is not cached, so each new attempt repeats it.",
			discoCalls.Load())
	}
}

// ---------------------------------------------------------------- Z18-3

// TestZ18IntrospectionDoesNotHandOutTheStoredScopeSlice is red while the
// in-memory token store returns the slice it stores.
//
// oauth/tokens.go stores AccessToken by value but its Scopes field is a slice
// header: the store and the caller share one backing array. Service.Introspect
// (oauth/as.go:280) hands that array to its caller as TokenInfo.Scopes, so any
// consumer that narrows, sorts or writes the scopes it was handed edits a live
// token's grant. No in-repo consumer mutates it today — this is the same
// copy-on-return invariant 05-4 established for the OP store, at a different
// site, and the probe pins the invariant rather than a live exploit.
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
		t.Errorf("RED: rewriting the slice returned by GetAccess changed the STORED token's scope from %q to %q "+
			"(oauth/tokens.go:224-232 returns the record without copying Scopes; oauth/as.go:280 passes it on as "+
			"TokenInfo.Scopes). A caller that narrows or reorders the scopes it introspected therefore grants or "+
			"revokes scopes on a live token.",
			oauth.ScopeAccountID, again.Scopes[0])
	}
}

// ---------------------------------------------------------------- guard (green)

// TestZ18NonPositiveBulkheadCapIsIgnored is the positive control for the
// int-to-uint conversion at httpclient/outbound.go:203-210: maxConcurrent <= 0
// must return next unchanged rather than converting a negative int into an
// enormous uint capacity. It is green today and is the guard that keeps it so.
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
}
