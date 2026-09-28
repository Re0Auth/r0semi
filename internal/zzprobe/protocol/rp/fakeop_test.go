//go:build audit5

// Package rp probes Re0Auth acting as an OAuth/OIDC *client* (RP): the idp
// package plus the consent interaction seam. It creates no production code and
// modifies no existing file.
//
// The fake OpenID Provider below is deliberately under the probe's control —
// discovery document, JWKS contents, the claims of the id_token the token
// endpoint mints — because the questions worth asking about an RP are "what does
// it accept when the provider says X" and "what does it do when the provider's
// key material changes".
package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/idp"
)

// testKey is one RSA signing key with a kid.
type testKey struct {
	priv *rsa.PrivateKey
	kid  string
}

func newTestKey(t *testing.T, kid string) *testKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{priv: priv, kid: kid}
}

func (k *testKey) publicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.priv.Public(), KeyID: k.kid, Algorithm: string(jose.RS256), Use: "sig"}
}

// sign mints an RS256 id_token carrying this key's kid in the header.
func (k *testKey) sign(t *testing.T, claims map[string]any) string {
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

// unsignedToken is an `alg: none` JWT, hand-rolled because go-jose will not
// produce one for us.
func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "none", "typ": "JWT"}) + "." + enc(claims) + "."
}

// hmacToken signs with a symmetric key: the classic RS256→HS256 confusion.
func hmacToken(t *testing.T, key []byte, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "oct-1"),
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

// fakeOP is a controllable OpenID Provider.
type fakeOP struct {
	t   *testing.T
	srv *httptest.Server

	mu              sync.Mutex
	issuerOverride  string
	authURLOverride string
	tokenURLOverrd  string
	omitAuthURL     bool
	algs            []string
	discoveryStatus int
	jwksStatus      int
	key             *testKey
	jwks            []jose.JSONWebKey
	claims          map[string]any
	nonce           string
	omitIDToken     bool
	tokenStatus     int
	rawIDToken      string
	userinfoSubject string

	discoveryHits, jwksHits, tokenHits, infoHits int
	lastTokenForm                                url.Values
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	k := newTestKey(t, "k1")
	f := &fakeOP{
		t:               t,
		key:             k,
		jwks:            []jose.JSONWebKey{k.publicJWK()},
		algs:            []string{"RS256"},
		claims:          map[string]any{},
		tokenStatus:     http.StatusOK,
		discoveryStatus: http.StatusOK,
		jwksStatus:      http.StatusOK,
		userinfoSubject: "rp-user-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.discoveryHits++
		status := f.discoveryStatus
		algs := append([]string(nil), f.algs...)
		authURL := f.authURLOverride
		tokenURL := f.tokenURLOverrd
		omitAuth := f.omitAuthURL
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if authURL == "" && !omitAuth {
			authURL = f.srv.URL + "/authorize"
		}
		if tokenURL == "" {
			tokenURL = f.srv.URL + "/token"
		}
		doc := map[string]any{
			"issuer":                                f.issuer(),
			"token_endpoint":                        tokenURL,
			"userinfo_endpoint":                     f.srv.URL + "/userinfo",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": algs,
		}
		if !omitAuth {
			doc["authorization_endpoint"] = authURL
		}
		writeJSON(w, doc)
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
		writeJSON(w, jose.JSONWebKeySet{Keys: keys})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.infoHits++
		sub := f.userinfoSubject
		f.mu.Unlock()
		writeJSON(w, map[string]any{"sub": sub, "name": "Userinfo Fallback"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.tokenHits++
		f.lastTokenForm = r.PostForm
		status := f.tokenStatus
		omit := f.omitIDToken
		raw := f.rawIDToken
		nonce := f.nonce
		overlay := map[string]any{}
		for k, v := range f.claims {
			overlay[k] = v
		}
		signerKey := f.key
		f.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		out := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}
		if !omit {
			if raw == "" {
				now := time.Now()
				claims := map[string]any{
					"iss": f.issuer(), "sub": "rp-user-1", "aud": clientIDOf(r),
					"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				}
				if nonce != "" {
					claims["nonce"] = nonce
				}
				for key, v := range overlay {
					if v == nil {
						delete(claims, key)
						continue
					}
					claims[key] = v
				}
				raw = signerKey.sign(f.t, claims)
			}
			out["id_token"] = raw
		}
		writeJSON(w, out)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOP) issuer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issuerOverride != "" {
		return f.issuerOverride
	}
	return f.srv.URL
}

// The accessors below exist so a probe never writes a field the server
// goroutine reads without the lock.
func (f *fakeOP) setIssuerOverride(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuerOverride = v
}

// setEndpointsOverride points the discovered endpoints at another origin, and
// omitAuthURL removes the authorization endpoint from the document entirely.
func (f *fakeOP) setEndpointsOverride(authURL, tokenURL string, omitAuthURL bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authURLOverride = authURL
	f.tokenURLOverrd = tokenURL
	f.omitAuthURL = omitAuthURL
}

func (f *fakeOP) setAlgs(algs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.algs = algs
}

func (f *fakeOP) setNonce(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = nonce
}

func (f *fakeOP) setOmitIDToken(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.omitIDToken = v
}

func (f *fakeOP) signingKey() *testKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key
}

func (f *fakeOP) setSigningKey(k *testKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = k
}

func (f *fakeOP) setJWKS(keys ...jose.JSONWebKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwks = keys
}

func (f *fakeOP) setJWKSStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksStatus = status
}

func (f *fakeOP) setClaims(claimer func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claims == nil {
		f.claims = map[string]any{}
	}
	claimer(f.claims)
}

func (f *fakeOP) hits() (discovery, jwks, token, info int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryHits, f.jwksHits, f.tokenHits, f.infoHits
}

func (f *fakeOP) tokenForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastTokenForm
}

func clientIDOf(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		return id
	}
	_ = r.ParseForm()
	return r.PostFormValue("client_id")
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

// idpCred is an empty override set: the fake OP's URL for everything.
func idpCred() idp.Credentials { return idp.Credentials{} }

// newRegistry wires one provider against the fake OP. An override passed in
// replaces the fake OP's URL for that field.
func newRegistry(t *testing.T, f *fakeOP, provider idp.Provider, cred idp.Credentials) *idp.Client {
	t.Helper()
	return newRegistryTTL(t, f, provider, cred, 0)
}

// newRegistryTTL is newRegistry with an explicit provider cache TTL. Zero means
// the library default; a tiny value makes the next call re-discover, which is how
// a probe exercises "the upstream rotated its signing key".
func newRegistryTTL(t *testing.T, f *fakeOP, provider idp.Provider, cred idp.Credentials, ttl time.Duration) *idp.Client {
	t.Helper()
	cred.Provider = provider
	if cred.ClientID == "" {
		cred.ClientID = "cid"
	}
	if cred.ClientSecret == "" {
		cred.ClientSecret = "sec"
	}
	if cred.AuthURL == "" {
		cred.AuthURL = f.srv.URL + "/authorize"
	}
	if cred.TokenURL == "" {
		cred.TokenURL = f.srv.URL + "/token"
	}
	if cred.Issuer == "" {
		cred.Issuer = f.srv.URL
	}
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       f.srv.Client(),
		ProviderCacheTTL: ttl,
		Credentials:      []idp.Credentials{cred},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	c, ok := reg.Get(provider)
	if !ok {
		t.Fatalf("provider %q was not registered", provider)
	}
	return c
}

// newFakeRegistryErr builds a registry for a single provider name, for the
// provider-name validation probe.
func newFakeRegistryErr(p idp.Provider) (*idp.Registry, error) {
	return idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials:  []idp.Credentials{{Provider: p, ClientID: "cid", Issuer: "https://issuer.example"}},
	})
}

// newIssuerOnlyRegistry wires a custom (non-built-in) provider that names only
// its issuer. That is the shape that makes the RP take its OAuth endpoints from
// the discovery document.
func newIssuerOnlyRegistry(t *testing.T, f *fakeOP, name idp.Provider) *idp.Client {
	t.Helper()
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   f.srv.Client(),
		Credentials: []idp.Credentials{{
			Provider: name, ClientID: "cid", ClientSecret: "top-secret", Issuer: f.srv.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(name)
	if !ok {
		t.Fatalf("provider %q was not registered", name)
	}
	return c
}

// ctxOf is a plain context: the client carries its own HTTP client
// (RegistryConfig.HTTPClient) and both Exchange and Identity install it.
func ctxOf(*fakeOP) context.Context { return context.Background() }

// login drives the whole RP round trip against the fake OP: exchange a code,
// then verify the identity with the nonce the flow was started with.
func login(t *testing.T, c *idp.Client, f *fakeOP, nonce string) (idp.Identity, error) {
	t.Helper()
	token, err := c.Exchange(ctxOf(f), "code-1", c.NewVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return c.Identity(ctxOf(f), token, nonce)
}

// identityOf verifies a token the probe minted itself: "the provider returned
// this id_token", without going through /token.
func identityOf(t *testing.T, c *idp.Client, f *fakeOP, rawIDToken, nonce string) (idp.Identity, error) {
	t.Helper()
	tok := (&oauth2.Token{AccessToken: "at-1"}).WithExtra(map[string]any{"id_token": rawIDToken})
	return c.Identity(ctxOf(f), tok, nonce)
}
