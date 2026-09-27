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

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
)

// A custom OIDC provider's endpoints come from its discovery document, and the
// RP uses them as given: the browser is sent wherever authorization_endpoint
// points, and the client secret plus the authorization code go wherever
// token_endpoint points. Neither is required to belong to the issuer the
// operator configured.
//
// The premise is the interesting part and it is stated: whoever can answer the
// discovery request (a plain-http issuer, a hijacked DNS answer, a mis-issued
// certificate, a compromised upstream) can move the login, and the client secret
// is a long-lived credential that outlives their control of that answer.
func TestRPDiscoveredAuthorizationEndpointIsNotPinnedToTheIssuer(t *testing.T) {
	f := newFakeOP(t)
	f.setEndpointsOverride("https://evil.example/authorize", "", false)
	c := newIssuerOnlyRegistry(t, f, "authentik")

	authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("AuthCodeURL returned %q", authURL)
	}
	if u.Host == "" || u.Scheme == "" {
		t.Fatalf("the login URL is not absolute: %q", authURL)
	}
	issuer, _ := url.Parse(f.srv.URL)
	if u.Host != issuer.Host {
		t.Errorf("the discovery document moved the login off the issuer's origin: %s (issuer %s)", authURL, f.srv.URL)
	}
}

// The other half: the code exchange follows the discovered token_endpoint.
func TestRPDiscoveredTokenEndpointReceivesTheClientSecret(t *testing.T) {
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

	// Anti-vacuity: the login URL is on the issuer, so discovery ran and the
	// authorization endpoint is the issuer's.
	if authURL, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "nonce"); err != nil || !strings.HasPrefix(authURL, f.srv.URL) {
		t.Fatalf("discovery did not run as expected: %q %v", authURL, err)
	}
	if _, err := c.Exchange(context.Background(), "code-1", "verifier-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotForm == nil {
		t.Fatal("the other origin was never reached, so this probe proves nothing")
	}
	secret := base64.StdEncoding.EncodeToString([]byte("cid:top-secret"))
	if strings.Contains(gotAuth, secret) {
		t.Errorf("the client secret (Basic %s) went to the discovered token endpoint on another origin", gotAuth)
	}
	if gotForm.Get("client_secret") == "top-secret" {
		t.Errorf("the client secret went to the discovered token endpoint on another origin")
	}
	if gotForm.Get("code") == "code-1" {
		t.Errorf("the authorization code was posted to another origin: %v", gotForm.Encode())
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

// Hitting the real Microsoft discovery endpoint, the way a login does. The
// built-in issuer is the multi-tenant /common/v2.0, whose document reports
// issuer = https://login.microsoftonline.com/{tenantid}/v2.0 -- a literal
// placeholder.
func TestRPRealMicrosoftBuiltInIssuerCannotDiscover(t *testing.T) {
	// Control first: the same call with a tenant-specific issuer discovers.
	tenant := "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	if !reachable(t, tenant+"/.well-known/openid-configuration") {
		t.Skip("no network: cannot reach login.microsoftonline.com")
	}
	if !reachable(t, "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration") {
		t.Skip("no network: cannot reach login.microsoftonline.com/common")
	}

	control := builtInClientWithIssuer(t, idp.Microsoft, tenant)
	junk := (&oauth2.Token{AccessToken: "at-1"}).WithExtra(map[string]any{"id_token": "not.a.jwt"})
	_, err := control.Identity(context.Background(), junk, "nonce")
	if err != nil && strings.Contains(err.Error(), "discovery failed") {
		t.Fatalf("control: the tenant issuer did not discover either: %v", err)
	}
	if err == nil {
		t.Fatal("control: a junk id_token was accepted")
	}
	t.Logf("control (tenant issuer) fails only at the token: %v", err)

	// The built-in configuration: AuthCodeURL succeeds because the endpoints are
	// static, so the user is sent to Microsoft and only the callback fails.
	authURL, err := builtInClient(t, idp.Microsoft).AuthCodeURL(context.Background(), "st", "verifier", "nonce")
	if err != nil {
		t.Fatalf("the built-in Microsoft authorization URL failed early (%v); the probe's premise changed", err)
	}
	if !strings.Contains(authURL, "login.microsoftonline.com/common") {
		t.Fatalf("unexpected authorization URL %q", authURL)
	}

	c := builtInClient(t, idp.Microsoft)
	_, err = c.Identity(context.Background(), junk, "nonce")
	if err == nil {
		t.Fatal("the built-in Microsoft issuer verified a junk token")
	}
	if strings.Contains(err.Error(), "discovery failed") {
		t.Errorf("the built-in Microsoft provider cannot complete any login: %v", err)
		return
	}
	t.Logf("built-in issuer got past discovery: %v", err)
}

// reachable reports whether a URL answers at all, so a network probe skips
// rather than asserting something about this machine's connectivity.
func reachable(t *testing.T, target string) bool {
	t.Helper()
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// builtInClient builds the registry from the built-in definition alone, which is
// the shipped configuration.
func builtInClient(t *testing.T, p idp.Provider) *idp.Client {
	t.Helper()
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials:  []idp.Credentials{{Provider: p, ClientID: "probe-client-id", ClientSecret: "probe-secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(p)
	if !ok {
		t.Fatalf("provider %q was not registered", p)
	}
	return c
}

// builtInClientWithIssuer is the built-in definition with the issuer overridden,
// which is how an operator works around a multi-tenant issuer.
func builtInClientWithIssuer(t *testing.T, p idp.Provider, issuer string) *idp.Client {
	t.Helper()
	reg, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials: []idp.Credentials{{
			Provider: p, ClientID: "probe-client-id", ClientSecret: "probe-secret", Issuer: issuer,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := reg.Get(p)
	return c
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
