//go:build audit7

// Probes for the readiness endpoint's cost bound (fix 0e6b701, round-5 P1-4).
//
// They exist because the round-5 `audit5` probes for /readyz are red at HEAD for
// two different reasons, and only one of them is the deliberate 1s TTL:
//
//   - TestZ22ReadinessTTLIsTheStaleAudit5Probe's reason: the deliberate reuse
//     window, documented in docs/operations.md and internal/httpapi/health.go.
//   - TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning's reason: a request
//     that arrives while the very first check is still running is answered from a
//     zero-valued cached error, i.e. "ready", although no result has ever been
//     produced. That is not the TTL; it is a fail-open introduced by the cache.
package z22reconcile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const z22Issuer = "https://auth.probe.test"

// z22CryptoKey satisfies oidchttp.Config.CryptoKey without touching a real key.
func z22CryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// z22Config mirrors what internal/zzprobe/startup's probeConfig builds: the
// smallest Config that httpapi.New accepts, so /readyz can be driven through the
// real middleware chain and the real handler.
func z22Config(t *testing.T) httpapi.Config {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
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
		Issuer:        z22Issuer,
		Storage:       store,
		CryptoKey:     z22CryptoKey(),
		CryptoKeyID:   "probe",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.Config{
		Issuer:            z22Issuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
	}
}

func z22Get(handler http.Handler, path string) (int, string) {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning demonstrates the
// fail-open: while the first-ever dependency check is in flight, every other
// /readyz request is answered 200 because readinessCache returns its zero-valued
// err.
//
// The control (the request that actually ran the check) must be 503, so the 200
// cannot be explained by a healthy dependency.
func TestZ22ReadinessAnswersReadyWhileTheFirstCheckIsRunning(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	depErr := errors.New("probe: database unreachable")

	cfg := z22Config(t)
	cfg.Ready = func(ctx context.Context) error {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return depErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	var first int
	done := make(chan struct{})
	go func() {
		defer close(done)
		first, _ = z22Get(handler, "/readyz")
	}()
	<-entered // the background request is inside the dependency check

	// This request arrives while the first check is still running and no result
	// has ever been cached. The dependency is unreachable.
	second, secondBody := z22Get(handler, "/readyz")

	close(release)
	<-done

	t.Logf("the request that ran the check = %d; a request that arrived while it was "+
		"still running (nothing cached yet) = %d %q", first, second, secondBody)

	if first != http.StatusServiceUnavailable {
		t.Fatalf("control failed: the request that ran the failing check = %d, want 503", first)
	}
	if second != http.StatusServiceUnavailable {
		t.Errorf("a /readyz that arrived while the first dependency check was still running "+
			"was answered %d (ready) although the dependency is unreachable and no result had "+
			"ever been produced; the readiness cache returned its zero-valued error "+
			"(internal/httpapi/health.go:111-118)", second)
	}
}

// TestZ22ReadinessTTLIsTheStaleAudit5Probe shows the other red reason, and shows
// the check itself still refuses: the audit5 probe
// TestProbeHealthEndpointsAreNoStoreAndLeakNothing flips the probe to failing and
// asserts 503 immediately, which the deliberate readinessTTL reuse defeats. After
// the TTL the same endpoint answers 503, so no dependency failure is hidden
// beyond one second.
func TestZ22ReadinessTTLIsTheStaleAudit5Probe(t *testing.T) {
	var mu sync.Mutex
	healthy := true

	cfg := z22Config(t)
	cfg.Ready = func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if healthy {
			return nil
		}
		return errors.New("probe: database unreachable")
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	// Prime the cache with a healthy result (fresh, within readinessTTL).
	if code, _ := z22Get(handler, "/readyz"); code != http.StatusOK {
		t.Fatalf("control failed: healthy /readyz = %d, want 200", code)
	}

	mu.Lock()
	healthy = false
	mu.Unlock()

	if code, body := z22Get(handler, "/readyz"); code != http.StatusOK {
		t.Fatalf("the deliberate TTL did not produce the stale 200 the audit5 probe trips on: %d %q", code, body)
	} else {
		t.Logf("within readinessTTL the flipped dependency is still reported %d %q (deliberate: docs/operations.md)", code, body)
	}

	time.Sleep(1100 * time.Millisecond)

	if code, body := z22Get(handler, "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("after readinessTTL the unreachable dependency was still reported ready: %d %q", code, body)
	} else {
		t.Logf("after readinessTTL the same endpoint answers %d %q", code, body)
	}
}
