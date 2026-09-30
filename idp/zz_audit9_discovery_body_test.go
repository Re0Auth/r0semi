package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// audit9DiscoveryServer serves a syntactically valid OIDC discovery document
// padded with `padding` bytes of junk.
func audit9DiscoveryServer(t *testing.T, padding int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,`+
			`"jwks_uri":%q,"response_types_supported":["code"],`+
			`"subject_types_supported":["public"],`+
			`"id_token_signing_alg_values_supported":["RS256"],"padding":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks",
			strings.Repeat("a", padding))
	})
	return srv
}

func audit9DiscoveryClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		// srv.Client() is the only client that can reach the loopback test
		// server; the production client's DenyPrivateAddresses guard is not what
		// this test is about.
		HTTPClient: srv.Client(),
		Credentials: []Credentials{{
			Provider: "bigoidc", ClientID: "cid", ClientSecret: "sec", Issuer: srv.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("bigoidc")
	if !ok {
		t.Fatal("the custom provider was not registered")
	}
	return c
}

// AUDIT9 / S06-1 (fixed) — the discovery document and the key set are read through
// a body-capped transport.
//
// go-oidc reads both with an unbounded io.ReadAll, and net/http decompresses gzip,
// so a configured — or hijacked — issuer could make an ordinary sign-in allocate
// unbounded memory. The transport now refuses a document over maxDiscoveryBytes.
func TestAudit9DiscoveryBodyOverTheCapIsRefused(t *testing.T) {
	srv := audit9DiscoveryServer(t, 2<<20) // 2 MiB, twice the cap
	c := audit9DiscoveryClient(t, srv)

	if _, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), c.NewNonce()); err == nil {
		t.Fatal("a 2 MiB discovery document was accepted: the body cap is not applied")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want it to name the size limit", err)
	}
}

// The cap must not break a normal provider: a small, valid document still works.
func TestAudit9DiscoveryBodyWithinTheCapIsAccepted(t *testing.T) {
	srv := audit9DiscoveryServer(t, 0)
	c := audit9DiscoveryClient(t, srv)

	authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), c.NewNonce())
	if err != nil {
		t.Fatalf("a within-cap discovery document was refused: %v", err)
	}
	if authURL == "" {
		t.Fatal("empty authorization URL")
	}
}
