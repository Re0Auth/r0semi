//go:build audit7

// A controllable OpenID Provider for the zone-14 RP probes.
//
// It is deliberately under the probe's control — discovery document (including
// jwks_uri), the JWKS contents, and the keys the probe signs id_tokens with —
// because the questions worth asking about the RP are "what does it accept when
// the provider's document says X" and "how long does a key it no longer
// publishes keep verifying".
package z14kitrptaptap

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/idp"
)

// probeKey is one RSA signing key with a kid.
type probeKey struct {
	priv *rsa.PrivateKey
	kid  string
}

func newProbeKey(t *testing.T, kid string) *probeKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &probeKey{priv: priv, kid: kid}
}

func (k *probeKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.priv.Public(), KeyID: k.kid, Algorithm: string(jose.RS256), Use: "sig"}
}

// sign mints an RS256 id_token carrying this key's kid in the header.
func (k *probeKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}},
		(&jose.SignerOptions{}).WithHeader("kid", k.kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// idClaims builds the claim set a compliant provider would mint for this client.
func idClaims(issuer, sub, audience, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"sub":   sub,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": nonce,
	}
}

// fakeOP is a controllable OpenID Provider. A handler reads its fields under the
// mutex, so a probe can flip them between two Identity calls.
type fakeOP struct {
	t   *testing.T
	srv *httptest.Server

	mu              sync.Mutex
	jwksURIOverride string
	discoveryStatus int
	jwksStatus      int
	key             *probeKey
	jwks            []jose.JSONWebKey

	discoveryHits, jwksHits int
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	k := newProbeKey(t, "issuer-k1")
	f := &fakeOP{
		t:               t,
		key:             k,
		jwks:            []jose.JSONWebKey{k.jwk()},
		discoveryStatus: http.StatusOK,
		jwksStatus:      http.StatusOK,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.discoveryHits++
		status := f.discoveryStatus
		jwksURI := f.jwksURIOverride
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if jwksURI == "" {
			jwksURI = f.srv.URL + "/jwks"
		}
		probeWriteJSON(w, map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              jwksURI,
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.jwksHits++
		status := f.jwksStatus
		keys := append([]jose.JSONWebKey(nil), f.jwks...)
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		probeWriteJSON(w, jose.JSONWebKeySet{Keys: keys})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOP) issuer() string { return f.srv.URL }

func (f *fakeOP) setJWKSURIOverride(uri string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksURIOverride = uri
}

func (f *fakeOP) setDiscoveryStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryStatus = status
}

// rotate publishes only the new key: the previous one is retired, exactly as an
// upstream does after a key compromise.
func (f *fakeOP) rotate(k *probeKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = k
	f.jwks = []jose.JSONWebKey{k.jwk()}
}

func (f *fakeOP) hits() (discovery, jwks int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryHits, f.jwksHits
}

// probeRegistry wires one custom (issuer-only) OIDC provider against the fake OP.
// A custom provider has no built-in endpoints, so its authorization and token
// endpoints come from the discovery document — which is the shape pinToIssuer
// exists for.
func probeRegistry(t *testing.T, f *fakeOP, ttl time.Duration) *idp.Client {
	t.Helper()
	const name idp.Provider = "acmeprobe"
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       f.srv.Client(),
		ProviderCacheTTL: ttl,
		Credentials: []idp.Credentials{{
			Provider:     name,
			ClientID:     probeAudience,
			ClientSecret: "probe-secret",
			Issuer:       f.srv.URL,
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}
	c, ok := reg.Get(name)
	if !ok {
		t.Fatalf("provider %q was not registered", name)
	}
	return c
}

const probeAudience = "cid"

// verifyMinted asks the RP to verify an id_token the probe minted itself: "the
// provider returned this id_token", without going through /token.
func verifyMinted(t *testing.T, c *idp.Client, rawIDToken, nonce string) (idp.Identity, error) {
	t.Helper()
	tok := (&oauth2.Token{AccessToken: "probe-at"}).WithExtra(map[string]any{"id_token": rawIDToken})
	return c.Identity(t.Context(), tok, nonce)
}

func probeWriteJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
