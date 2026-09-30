//go:build audit || audit6

package idp

// Audit probes for the RP side (round 6): id_token claim enforcement, the
// lifetime of a retired signing key, and which parts of a discovery document the
// client actually pins.

import (
	"context"
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
)

// --- a rotatable fake OpenID Provider -------------------------------------

type auditKey struct {
	jwk    jose.JSONWebKey
	signer jose.Signer
}

func newAuditKey(t *testing.T, kid string) *auditKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &auditKey{jwk: k, signer: signer}
}

func (k *auditKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Signed(k.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// auditOP serves discovery and a JWKS whose contents the test controls, including
// pointing jwks_uri and token_endpoint at other origins.
type auditOP struct {
	*httptest.Server

	mu        sync.Mutex
	published []jose.JSONWebKey // what /jwks currently serves
	jwksURI   string            // overrides the advertised jwks_uri
	tokenURL  string            // overrides the advertised token_endpoint
	discovery int
	jwks      int
	// discoveryStatus, when non-zero and not 200, is what discovery answers with.
	discoveryStatus int
}

func newAuditOP(t *testing.T) *auditOP {
	t.Helper()
	op := &auditOP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		op.mu.Lock()
		op.discovery++
		jwksURI, tokenURL, status := op.jwksURI, op.tokenURL, op.discoveryStatus
		op.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if jwksURI == "" {
			jwksURI = op.URL + "/jwks"
		}
		if tokenURL == "" {
			tokenURL = op.URL + "/token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                op.URL,
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        tokenURL,
			"jwks_uri":                              jwksURI,
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		op.mu.Lock()
		op.jwks++
		keys := append([]jose.JSONWebKey(nil), op.published...)
		op.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	})
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	return op
}

func (op *auditOP) publish(keys ...*auditKey) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.published = nil
	for _, k := range keys {
		op.published = append(op.published, k.jwk.Public())
	}
}

func (op *auditOP) counts() (discovery, jwks int) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.discovery, op.jwks
}

// failDiscovery makes the discovery document answer status instead of 200.
func (op *auditOP) failDiscovery(status int) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.discoveryStatus = status
}

func auditClient(t *testing.T, op *auditOP, name Provider, ttl time.Duration) *Client {
	t.Helper()
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       op.Client(),
		ProviderCacheTTL: ttl,
		Credentials: []Credentials{{
			Provider: name, ClientID: "cid", ClientSecret: "sec",
			Issuer: op.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(name)
	if !ok {
		t.Fatalf("%s not configured", name)
	}
	return c
}

func auditCtx(op *auditOP) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, op.Client())
}

func idTokenWith(t *testing.T, key *auditKey, iss, nonce string, aud any, extra map[string]any) *oauth2.Token {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": iss, "sub": "rp-subject", "aud": aud,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range extra {
		claims[k] = v
	}
	return (&oauth2.Token{AccessToken: "at-1"}).WithExtra(map[string]any{"id_token": key.sign(t, claims)})
}

// --- RP-1 revisited: the azp rules ----------------------------------------

// TestZZAuditRPAZPRules walks OIDC Core 3.1.3.7's azp requirement. RP-1 (audit 5)
// recorded azp as entirely unchecked; idp.go:589-594 now checks it.
func TestZZAuditRPAZPRules(t *testing.T) {
	op := newAuditOP(t)
	key := newAuditKey(t, "k1")
	op.publish(key)
	c := auditClient(t, op, "auditrp", 0)
	ctx := auditCtx(op)

	for _, tc := range []struct {
		name    string
		aud     any
		extra   map[string]any
		wantErr bool
	}{
		{"single audience, no azp", "cid", nil, false},
		{"single audience, azp is us", "cid", map[string]any{"azp": "cid"}, false},
		{"two audiences, azp is us", []string{"cid", "other"}, map[string]any{"azp": "cid"}, false},
		{"two audiences, no azp", []string{"cid", "other"}, nil, true},
		{"two audiences, azp is another client", []string{"cid", "other"}, map[string]any{"azp": "other"}, true},
		{"single audience, azp is another client", "cid", map[string]any{"azp": "other"}, true},
	} {
		tok := idTokenWith(t, key, op.URL, "n1", tc.aud, tc.extra)
		_, err := c.Identity(ctx, tok, "n1")
		if tc.wantErr && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if err != nil {
			t.Logf("%s -> %v", tc.name, err)
		}
	}
}

// --- RP-2 revisited: how long a retired signing key keeps verifying --------

// TestZZAuditRPRetiredKeyKeepsVerifying measures the window. The client rebuilds
// its discovered provider only after providerTTL (default 15 minutes, and not
// reachable from the deployment config), and go-oidc's key set is only refetched
// when a kid is unknown -- so an id_token signed by a key the provider has since
// retired still verifies until that rebuild.
func TestZZAuditRPRetiredKeyKeepsVerifying(t *testing.T) {
	op := newAuditOP(t)
	oldKey := newAuditKey(t, "k-old")
	newKey := newAuditKey(t, "k-new")
	op.publish(oldKey)

	// A long TTL is the shipped shape: nothing but the TTL ages the key out.
	c := auditClient(t, op, "auditrettp", time.Hour)
	ctx := auditCtx(op)
	retired := idTokenWith(t, oldKey, op.URL, "n", "cid", nil)

	if _, err := c.Identity(ctx, retired, "n"); err != nil {
		t.Fatalf("the live key was refused: %v", err)
	}

	// The provider retires k-old: the JWKS now publishes only k-new.
	op.publish(newKey)
	if _, err := c.Identity(ctx, retired, "n"); err != nil {
		t.Fatalf("a token signed by the retired key was refused inside the TTL: %v", err)
	}
	d, j := op.counts()
	t.Logf("after two verifications: discovery fetches=%d jwks fetches=%d; the retired key still verifies", d, j)

	// A tiny TTL is what closes it: the provider is rebuilt and the key set with it.
	fresh := auditClient(t, op, "auditfresh", time.Nanosecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := fresh.Identity(ctx, retired, "n"); err == nil {
		t.Error("a rebuilt provider still accepted the retired key")
	} else {
		t.Logf("with ProviderCacheTTL=1ns the retired key is refused: %v", err)
	}
}

// TestZZAuditRPDiscoveryIsCachedForTheTTL counts the discovery round trips, so
// the cost of the TTL (and the fact that it is the only refresh trigger) is
// visible rather than asserted.
func TestZZAuditRPDiscoveryIsCachedForTheTTL(t *testing.T) {
	op := newAuditOP(t)
	key := newAuditKey(t, "k1")
	op.publish(key)
	c := auditClient(t, op, "auditcache", time.Hour)
	ctx := auditCtx(op)

	for i := 0; i < 3; i++ {
		if _, err := c.Identity(ctx, idTokenWith(t, key, op.URL, "n", "cid", nil), "n"); err != nil {
			t.Fatalf("verification %d: %v", i, err)
		}
	}
	d, j := op.counts()
	t.Logf("3 verifications inside a 1h TTL: discovery=%d jwks=%d", d, j)
	if d != 1 {
		t.Errorf("discovery was fetched %d times inside the TTL, want 1", d)
	}
	if j != 1 {
		t.Errorf("jwks was fetched %d times inside the TTL, want 1", j)
	}
}

// TestZZAuditRPDiscoveryOutageCannotExtendTheKeySetsLife pins the ceiling on the
// retain-the-cached-provider branch.
//
// A failed re-discovery keeps serving the last good provider, and that provider
// owns a go-oidc key set that never expires on its own. While discovery keeps
// failing, discoveredAt never advances, so without a ceiling the retired key
// would verify for the whole outage. retainOnDiscoveryFailure now serves the
// cached provider only while it is younger than providerStaleCeiling*providerTTL
// and refuses it past that, naming the age.
func TestZZAuditRPDiscoveryOutageCannotExtendTheKeySetsLife(t *testing.T) {
	op := newAuditOP(t)
	retired := newAuditKey(t, "k-retired")
	replacement := newAuditKey(t, "k-replacement")
	op.publish(retired)

	ctx := auditCtx(op)

	// boundedTTL is short enough that 2*TTL is reachable in a test. controlTTL
	// is long enough that the same wait stays well inside its ceiling, so the
	// availability control exercises the retain branch rather than the ordinary
	// cache hit.
	const boundedTTL = 200 * time.Millisecond
	const controlTTL = time.Second

	bounded := auditClient(t, op, "auditbounded", boundedTTL)
	available := auditClient(t, op, "auditavailable", controlTTL)

	tok := idTokenWith(t, retired, op.URL, "n", "cid", nil)
	for _, c := range []*Client{bounded, available} {
		if _, err := c.Identity(ctx, tok, "n"); err != nil {
			t.Fatalf("setup: the published key was rejected: %v", err)
		}
	}

	// Upstream retires k-retired and publishes only k-replacement; discovery
	// starts failing at the same time.
	op.publish(replacement)
	op.failDiscovery(http.StatusInternalServerError)

	// Wait past the bounded client's ceiling but still inside the control's.
	time.Sleep(1200 * time.Millisecond)

	// Availability control, inside the ceiling: discovery fails, the TTL has
	// elapsed, and the cached key still verifies -- a bad minute upstream must
	// not become a login outage.
	if ident, err := available.Identity(ctx, tok, "n"); err != nil {
		t.Fatalf("control: a cached key was refused inside the ceiling while discovery was failing: %v", err)
	} else if ident.Subject != "rp-subject" {
		t.Fatalf("control: sub = %q", ident.Subject)
	} else {
		t.Log("control: inside 2*controlTTL the cached key still verified through the failing discovery")
	}

	// Past 2*boundedTTL the cache is refused rather than served, so the retired
	// key stops verifying even though discovery is still failing.
	if _, err := bounded.Identity(ctx, tok, "n"); err == nil {
		t.Fatal("a token signed by the retired key still verified past 2*TTL while discovery was failing")
	} else {
		t.Logf("past 2*TTL the retired key was refused: %v", err)
	}
}

// --- RP-3 revisited: what the discovery document may point at --------------

// TestZZAuditRPForeignTokenEndpointIsRefused confirms the pinning that exists:
// a discovered token_endpoint on another origin is refused, so the client secret
// cannot be posted elsewhere.
func TestZZAuditRPForeignTokenEndpointIsRefused(t *testing.T) {
	op := newAuditOP(t)
	other := newAuditOP(t)
	op.mu.Lock()
	op.tokenURL = other.URL + "/token"
	op.mu.Unlock()

	c := auditClient(t, op, "auditpin", 0)
	if _, err := c.AuthCodeURL(auditCtx(op), "st", c.NewVerifier(), "n"); err == nil {
		t.Fatal("a discovered token_endpoint on a foreign origin was accepted")
	} else {
		t.Logf("foreign token_endpoint refused: %v", err)
	}
}

// TestZZAuditRPForeignJWKSURIIsRefused is the third endpoint, now pinned: the
// trust anchor for id_token signatures is not chosen by another origin. A
// document that names a foreign jwks_uri is refused as a failed discovery, so a
// token signed by that foreign key is never even looked at. (The half that used
// to be open accepted it; the probe in
// internal/zzprobe/audit7/z14kitrptaptap is the end-to-end form.)
func TestZZAuditRPForeignJWKSURIIsRefused(t *testing.T) {
	op := newAuditOP(t)
	foreign := newAuditOP(t)
	foreignKey := newAuditKey(t, "k-foreign")
	foreign.publish(foreignKey)

	op.publish() // this issuer publishes no key of its own
	op.mu.Lock()
	op.jwksURI = foreign.URL + "/jwks"
	op.mu.Unlock()

	c := auditClient(t, op, "auditjwks", 0)
	tok := idTokenWith(t, foreignKey, op.URL, "n", "cid", nil)
	if _, err := c.Identity(auditCtx(op), tok, "n"); err == nil {
		t.Fatal("accepted a token signed by the key a foreign jwks_uri named")
	} else {
		t.Logf("foreign jwks_uri refused: %v", err)
	}
	if _, j := foreign.counts(); j != 0 {
		t.Errorf("the foreign key set was fetched %d times although jwks_uri was refused", j)
	}
}
