package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

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
