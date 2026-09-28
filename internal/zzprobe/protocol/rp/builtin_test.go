//go:build audit5

package rp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
)

// A custom OIDC provider's endpoints come from its discovery document, but an
// endpoint that is not on the configured issuer's origin is refused (FIXED).
//
// Was: the RP used the discovered endpoints as given, so whoever could answer the
// discovery request (a plain-http issuer, a hijacked DNS answer, a mis-issued
// certificate, a compromised upstream) could move the login, and the client
// secret — a long-lived credential that outlives their control of that answer —
// would follow.
func TestRPDiscoveredAuthorizationEndpointIsPinnedToTheIssuer(t *testing.T) {
	f := newFakeOP(t)
	f.setEndpointsOverride("https://evil.example/authorize", "", false)
	c := newIssuerOnlyRegistry(t, f, "authentik")

	authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce")
	if err == nil {
		t.Errorf("the discovery document moved the login off the issuer's origin and was accepted: %s", authURL)
		return
	}
	t.Logf("refused as expected: %v", err)
}

// The other half (FIXED): the secret is not sent to a discovered token endpoint on
// another origin.
func TestRPDiscoveredTokenEndpointOnAnotherOriginIsRefused(t *testing.T) {
	f := newFakeOP(t)

	var mu sync.Mutex
	var gotAuth string
	var gotForm url.Values
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotForm = r.PostForm
		mu.Unlock()
		writeJSON(w, map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer other.Close()

	f.setEndpointsOverride(f.srv.URL+"/authorize", other.URL+"/token", false)
	c := newIssuerOnlyRegistry(t, f, "authentik")

	// Both AuthCodeURL and Exchange resolve the endpoints through the same
	// discovery, so both must refuse the off-origin token endpoint. The login URL
	// is refused first.
	if authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce"); err == nil {
		t.Errorf("AuthCodeURL accepted a discovered token endpoint on another origin: %s", authURL)
	}
	if _, err := c.Exchange(context.Background(), "code-1", "verifier-1"); err == nil {
		t.Errorf("the code exchange followed a discovered token endpoint on another origin")
	}

	// Anti-vacuity: discovery did run, so the refusal was about the origin, not a
	// failure to reach the document. And the other origin never saw the secret.
	if discovery, _, _, _ := f.hits(); discovery == 0 {
		t.Fatal("the probe never reached discovery, so the refusal proves nothing")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotForm != nil {
		secret := base64.StdEncoding.EncodeToString([]byte("cid:top-secret"))
		if strings.Contains(gotAuth, secret) || gotForm.Get("client_secret") == "top-secret" || gotForm.Get("code") == "code-1" {
			t.Errorf("the client secret or authorization code reached the other origin: auth=%q form=%v", gotAuth, gotForm)
		}
	}
}

// A discovery document with no authorization endpoint at all leaves the RP with
// an empty AuthURL, and the browser is then handed a relative Location.
func TestRPDiscoveryWithoutAuthorizationEndpointYieldsARelativeLoginURL(t *testing.T) {
	f := newFakeOP(t)
	f.setEndpointsOverride("", f.srv.URL+"/token", true)
	c := newIssuerOnlyRegistry(t, f, "authentik")

	authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce")
	if err != nil {
		t.Logf("refused the misconfigured document: %v", err)
		return
	}
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		t.Errorf("the RP handed the browser a non-absolute login URL %q (discovery omitted authorization_endpoint)", authURL)
	}
}

// The default client the library falls back to refuses to resolve a discovery
// document on a private address: the address guard is the reason a
// caller-supplied issuer is not an SSRF primitive out of the box.
func TestRPDefaultOutboundClientRefusesLoopbackDiscovery(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": "http://127.0.0.1", "token_endpoint": "http://127.0.0.1/token"})
	}))
	defer local.Close()

	// No HTTPClient: the registry builds the hardened default itself.
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials: []idp.Credentials{{
			Provider: "authentik", ClientID: "cid", ClientSecret: "sec", Issuer: local.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := reg.Get("authentik")
	if _, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce"); err == nil {
		t.Error("the default client reached a loopback discovery endpoint")
	} else {
		t.Logf("refused as expected: %v", err)
	}
}

// The built-in Microsoft issuer is refused at construction (FIXED), so the login
// cannot silently fail at the callback.
//
// Was: [idp.microsoft] with only client_id/client_secret built the multi-tenant
// /common/v2.0 issuer, whose discovery document reports a literal {tenantid}
// placeholder. The endpoints are static, so the user WAS sent to Microsoft and
// only the callback failed — generically, with no hint. NewRegistry now rejects
// the built-in default and names the tenant URL.
//
// Offline: this asserts construction, so it does not need the network.
func TestRPMicrosoftBuiltInIssuerIsRefusedAtConstruction(t *testing.T) {
	_, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials:  []idp.Credentials{{Provider: idp.Microsoft, ClientID: "probe-client-id", ClientSecret: "probe-secret"}},
	})
	if err == nil {
		t.Fatal("the built-in Microsoft provider (no tenant issuer) was accepted; it can never verify an id_token")
	}
	t.Logf("refused as expected: %v", err)

	// Anti-vacuity: the tenant form builds, and a non-Microsoft built-in is
	// unaffected.
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials: []idp.Credentials{
			{Provider: idp.Microsoft, ClientID: "cid", ClientSecret: "sec",
				Issuer: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"},
			{Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec"},
		},
	})
	if err != nil {
		t.Fatalf("control: the tenant form (and github) was refused: %v", err)
	}
	if _, ok := reg.Get(idp.Microsoft); !ok {
		t.Error("control: microsoft with a tenant issuer was not registered")
	}
	if _, ok := reg.Get(idp.GitHub); !ok {
		t.Error("control: github was not registered")
	}
}

// A provider's userinfo endpoint must not be able to deflect the bearer token at
// another origin. The shipped outbound client refuses a cross-host redirect;
// this is the guard for that.
func TestRPUserinfoRedirectToAnotherOriginIsRefused(t *testing.T) {
	var mu sync.Mutex
	var stolen string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stolen = r.Header.Get("Authorization")
		mu.Unlock()
		writeJSON(w, map[string]any{"id": 7, "login": "stolen"})
	}))
	defer other.Close()

	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			writeJSON(w, map[string]any{"access_token": "at-secret", "token_type": "Bearer", "expires_in": 3600})
		case "/user":
			http.Redirect(w, r, other.URL+"/user", http.StatusFound)
		case "/user-ok":
			writeJSON(w, map[string]any{"id": 42, "login": "octocat"})
		}
	}))
	defer idpSrv.Close()
	target := idpSrv.URL

	// The composition root's client shape, with the address guard relaxed so a
	// loopback test server is reachable.
	hc := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Timeout: 5 * time.Second, Transport: httpclient.TransportConfig{DenyPrivateAddresses: false},
	})

	newClient := func(userInfo string) *idp.Client {
		reg, err := idp.NewRegistry(idp.RegistryConfig{
			RedirectBase: "https://re0auth.test",
			HTTPClient:   hc,
			Credentials: []idp.Credentials{{
				Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
				AuthURL: target + "/authorize", TokenURL: target + "/token", UserInfoURL: target + userInfo,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := reg.Get(idp.GitHub)
		return c
	}

	// Anti-vacuity: without the redirect the login completes through userinfo.
	ok := newClient("/user-ok")
	token, err := ok.Exchange(context.Background(), "code-1", ok.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	ident, err := ok.Identity(context.Background(), token, "")
	if err != nil {
		t.Fatalf("control userinfo login failed: %v", err)
	}
	if ident.Subject != "42" {
		t.Fatalf("control identity = %+v", ident)
	}

	redirecting := newClient("/user")
	token, err = redirecting.Exchange(context.Background(), "code-1", redirecting.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirecting.Identity(context.Background(), token, ""); err == nil {
		t.Error("the login followed a cross-origin redirect from the userinfo endpoint")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(stolen, "at-secret") {
		t.Errorf("the access token reached another origin: %q", stolen)
	}
}

// sub is namespaced by provider in the account key: provider A's subject cannot
// collide with provider B's.
func TestRPSubIsNamespacedByProvider(t *testing.T) {
	store := account.NewMemoryStore()
	ctx := context.Background()

	a, _, err := store.CreateWithIdentity(ctx, idp.Identity{Provider: "alpha", Subject: "shared-subject", DisplayName: "A"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.FindByIdentity(ctx, "alpha", "shared-subject")
	if err != nil {
		t.Fatal(err)
	}
	if user != a.ID {
		t.Fatalf("lookup by the creating provider returned %q, want %q", user, a.ID)
	}
	if _, err := store.FindByIdentity(ctx, "beta", "shared-subject"); err == nil {
		t.Error("provider beta resolved provider alpha's subject to an account")
	}

	b, _, err := store.CreateWithIdentity(ctx, idp.Identity{Provider: "beta", Subject: "shared-subject", DisplayName: "B"})
	if err != nil {
		t.Fatalf("the same subject under another provider was refused: %v", err)
	}
	if b.ID == a.ID {
		t.Error("two providers' subjects collapsed into one account")
	}
}

// iat is not checked at all: a token that claims to have been issued in the
// future verifies. Low impact, recorded so a guard can pin the decision.
func TestRPFutureIssuedAtIsAccepted(t *testing.T) {
	f := newFakeOP(t)
	c := newRegistry(t, f, "google", idpCred())
	nonce := c.NewNonce()
	f.setNonce(nonce)
	f.setClaims(func(m map[string]any) { m["iat"] = time.Now().Add(365 * 24 * time.Hour).Unix() })

	ident, err := login(t, c, f, nonce)
	if err != nil {
		t.Fatalf("a future iat was refused: %v", err)
	}
	t.Logf("accepted a token whose iat is a year in the future: sub=%q", ident.Subject)
}
