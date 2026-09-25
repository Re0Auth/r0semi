package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// newOPBackend builds the OpenID Provider handler and its in-memory store, wired
// the way the composition root wires them. It is the test counterpart of
// cmd/re0auth's openOIDC: /oauth/* and both discovery documents come from here,
// and the business plane gets the handler as introspector plus the store as its
// grants/device seam.
//
// Tests that exercise the session-bound consent flow pass a session manager; the
// rest pass nil, and the login hook then points at a path the tests parse.
//
// The optional metrics argument mirrors the composition root, which hands the OP
// handler the same metrics set as the HTTP layer. A test proving the protocol
// plane's signals must build the handler with them, because the wiring lives
// inside oidchttp: a handler built without metrics records nothing, however the
// Config on the outside is set.
//
// It takes a testing.TB rather than a *testing.T so the capacity benchmarks can
// build the same wired backend the tests do, instead of a second wiring that
// could drift from it.
func newOPBackend(t testing.TB, issuer string, clients oauth.ClientRegistry, sessions *auth.Manager, metrics ...*observability.Metrics) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	var m *observability.Metrics
	if len(metrics) > 0 {
		m = metrics[0]
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var login func(context.Context, string) string
	if sessions != nil {
		login = func(ctx context.Context, id string) string {
			// Bind the handle to the browser, exactly as the composition root
			// does, so a relayed id cannot be approved elsewhere.
			sessions.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
		}
	} else {
		login = func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		}
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("test", key),
		Login:    login,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:        issuer,
		Storage:       store,
		CryptoKey:     testCryptoKey(),
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
		Metrics:       m,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store
}

func testCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}
