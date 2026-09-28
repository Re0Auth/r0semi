package idp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// recordingTransport answers from the test and remembers that it was asked, so a
// client that is used can be told apart from one that is not.
type recordingTransport struct {
	calls atomic.Int64
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`)),
		Request: req,
	}, nil
}

// The registry's client must be used by Exchange without the caller putting it in
// the context.
//
// x/oauth2 reads the client from the context and falls back to http.DefaultClient
// when it finds none — no timeout, the default transport, and the standard
// library's redirect policy on a request whose body is the authorization code and
// the client secret. The siblings of this test inject the client themselves, which
// is exactly why the gap survived: the production caller passes the request
// context, so the fallback was the only path it ever took. The token endpoint here
// is a host that cannot resolve, so a fallback to the default client fails rather
// than silently passing.
func TestExchangeUsesTheConfiguredClient(t *testing.T) {
	rt := &recordingTransport{}
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   &http.Client{Transport: rt},
		Credentials: []Credentials{{
			Provider: GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: "https://idp.invalid/auth", TokenURL: "https://idp.invalid/token",
			UserInfoURL: "https://idp.invalid/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(GitHub)
	if !ok {
		t.Fatal("provider not registered")
	}

	token, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	if err != nil {
		t.Fatalf("Exchange did not use the configured client: %v", err)
	}
	if token.AccessToken != "at-1" {
		t.Fatalf("access token = %q", token.AccessToken)
	}
	if got := rt.calls.Load(); got != 1 {
		t.Fatalf("the configured transport saw %d requests, want 1", got)
	}
}

func TestNewRegistryValidation(t *testing.T) {
	if _, err := NewRegistry(RegistryConfig{}); err == nil {
		t.Fatal("accepted an empty RedirectBase")
	}
	if _, err := NewRegistry(RegistryConfig{RedirectBase: "https://x", Credentials: []Credentials{{Provider: "myspace"}}}); err == nil {
		t.Fatal("accepted an unknown provider")
	}
	if _, err := NewRegistry(RegistryConfig{RedirectBase: "https://x", Credentials: []Credentials{{Provider: GitHub}}}); err == nil {
		t.Fatal("accepted a provider without a client id")
	}
	// The provider name ends up in the callback URL and in every stored identity,
	// so a name that is not one URL path segment is rejected rather than trusted.
	if _, err := NewRegistry(RegistryConfig{RedirectBase: "https://x", Credentials: []Credentials{
		{Provider: "bad/name", ClientID: "cid", Issuer: "https://id.example"},
	}}); err == nil {
		t.Fatal("accepted a provider name that is not a URL path segment")
	}
}

func TestAuthCodeURLCarriesPKCE(t *testing.T) {
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test/",
		Credentials:  []Credentials{{Provider: Google, ClientID: "cid", ClientSecret: "sec"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(Google)
	if !ok {
		t.Fatal("google not configured")
	}

	verifier := c.NewVerifier()
	raw, err := c.AuthCodeURL(context.Background(), "state123", verifier, "nonce123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != "cid" || q.Get("state") != "state123" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("nonce") != "nonce123" {
		t.Fatalf("nonce not carried: %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("missing PKCE: %v", q)
	}
	if q.Get("redirect_uri") != "https://re0auth.test/auth/google/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
}

func TestExchangeAndIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "authorization_code" {
				t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
			}
			if r.PostForm.Get("code_verifier") == "" {
				t.Error("missing code_verifier")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
			})
		case "/user":
			if got := r.Header.Get("Authorization"); got != "Bearer at-1" {
				t.Errorf("authorization = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": float64(42), "login": "octocat", "name": "The Octocat",
				"email": "octo@example.com", "avatar_url": "https://avatars/octo",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   srv.Client(),
		Credentials: []Credentials{{
			Provider: GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := reg.Get(GitHub)

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, srv.Client())
	token, err := c.Exchange(ctx, "code-1", "verifier-1")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := c.Identity(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	if ident.Provider != GitHub || ident.Subject != "42" || ident.DisplayName != "The Octocat" {
		t.Fatalf("identity = %+v", ident)
	}
	if ident.Email != "octo@example.com" {
		t.Fatalf("email = %q", ident.Email)
	}
}

func TestQQFetchHandlesJSONP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/me":
			_, _ = w.Write([]byte(`callback( {"client_id":"100000","openid":"OPENID","unionid":"UNIONID"} );`))
		case "/userinfo":
			q := r.URL.Query()
			if q.Get("oauth_consumer_key") != "cid" || q.Get("openid") != "OPENID" || q.Get("fmt") != "json" {
				t.Errorf("query = %v", q)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ret": 0, "nickname": "QQ用户", "figureurl_qq_2": "https://qlogo/2",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	def := definition{qqMeURL: srv.URL + "/me?unionid=1", qqUserInfoURL: srv.URL + "/userinfo"}
	ident, err := fetchQQ(context.Background(), srv.Client(), def, "cid", &oauth2.Token{AccessToken: "at"})
	if err != nil {
		t.Fatal(err)
	}
	if ident.Subject != "UNIONID" || ident.DisplayName != "QQ用户" || ident.AvatarURL != "https://qlogo/2" {
		t.Fatalf("identity = %+v", ident)
	}
}

func TestStripJSONP(t *testing.T) {
	cases := map[string]string{
		`callback( {"openid":"x"} );`: `{"openid":"x"}`,
		`callback({"uid":"y"});`:      `{"uid":"y"}`,
		`{"uid":"z"}`:                 `{"uid":"z"}`,
	}
	for in, want := range cases {
		if got := stripJSONP(in); got != want {
			t.Errorf("stripJSONP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityValidate(t *testing.T) {
	if err := (Identity{Provider: GitHub, Subject: "1"}).Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	if err := (Identity{Provider: GitHub}).Validate(); err == nil {
		t.Fatal("accepted an identity without a subject")
	}
	if err := (Identity{Subject: "1"}).Validate(); err == nil {
		t.Fatal("accepted an identity without a provider")
	}
}

// The built-in Microsoft issuer is the multi-tenant /common/v2.0, whose discovery
// document reports a literal {tenantid} placeholder, so it can never verify an
// id_token. Because the endpoints are static the login is SENT to Microsoft and
// only the callback fails, generically — so the misconfiguration is refused at
// construction, where an operator sees it, and the tenant form is accepted.
func TestMicrosoftBuiltInIssuerIsRefusedAtConstruction(t *testing.T) {
	if _, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials:  []Credentials{{Provider: Microsoft, ClientID: "cid", ClientSecret: "sec"}},
	}); err == nil {
		t.Fatal("accepted the built-in microsoft provider with no tenant issuer; it can never complete a login")
	} else if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("the refusal does not name the fix: %v", err)
	}

	// Anti-vacuity: the tenant form builds, and another built-in is unaffected.
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials: []Credentials{
			{Provider: Microsoft, ClientID: "cid", ClientSecret: "sec",
				Issuer: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"},
			{Provider: GitHub, ClientID: "cid", ClientSecret: "sec"},
		},
	})
	if err != nil {
		t.Fatalf("the tenant form (and github) was refused: %v", err)
	}
	if _, ok := reg.Get(Microsoft); !ok {
		t.Error("microsoft with a tenant issuer was not registered")
	}
	if _, ok := reg.Get(GitHub); !ok {
		t.Error("github was not registered")
	}
}

// A discovered OAuth endpoint that is not on the configured issuer's origin is
// refused, so the client secret cannot be sent to another origin. Paths may
// differ; scheme and host may not.
func TestDiscoveredEndpointMustMatchIssuerOrigin(t *testing.T) {
	c := &Client{provider: "authentik", issuer: "https://auth.example/application/o/re0auth/"}
	// Same origin, different path: allowed.
	if err := c.pinToIssuer("https://auth.example/application/o/re0auth/authorize",
		"https://auth.example/application/o/re0auth/token"); err != nil {
		t.Fatalf("a same-origin endpoint was refused: %v", err)
	}
	// Another host, and another scheme: refused.
	if err := c.pinToIssuer("https://evil.example/authorize", ""); err == nil {
		t.Error("accepted an authorization endpoint on another host")
	}
	if err := c.pinToIssuer("", "http://auth.example/token"); err == nil {
		t.Error("accepted a token endpoint on a downgraded scheme")
	}
	// A missing endpoint is not this check's business.
	if err := c.pinToIssuer("", ""); err != nil {
		t.Errorf("pinToIssuer rejected empty endpoints: %v", err)
	}
}

// The fallback client, used when a caller does not inject one, must carry the
// same address guard as the composition root: a provider whose endpoint resolves
// to a private address is refused at dial time rather than reached. The
// composition root always injects a hardened client, so this path is only
// reachable from a direct library consumer — which is exactly why the default
// has to be safe on its own.
func TestFallbackClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer"})
	}))
	defer srv.Close()

	newReg := func(hc *http.Client) *Registry {
		t.Helper()
		r, err := NewRegistry(RegistryConfig{
			RedirectBase: "https://re0auth.test",
			HTTPClient:   hc, // nil exercises the fallback
			Credentials: []Credentials{{
				Provider: GitHub, ClientID: "cid", ClientSecret: "sec",
				AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/me",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Anti-vacuous: with an injected client the loopback fixture is reachable, so
	// the refusal below is the guard and not a broken fixture.
	okClient, _ := newReg(srv.Client()).Get(GitHub)
	if _, err := okClient.Exchange(context.Background(), "c", "v"); err != nil {
		t.Fatalf("the loopback fixture was unreachable with an injected client: %v", err)
	}

	c, _ := newReg(nil).Get(GitHub)
	if _, err := c.Exchange(context.Background(), "c", "v"); err == nil ||
		!strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("the fallback client did not refuse a private address: %v", err)
	}
}
