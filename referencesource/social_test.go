package referencesource_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/testoidc"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/vault"
)

// socialSource builds a source whose only login is Google OAuth, pointed at a
// fake OpenID Provider. It is the mirror image of the TapTap test: the source's
// own login is itself OIDC, and Re0Auth still only ever sees the subject.
func socialSource(t *testing.T, provider *testoidc.Server) (*referencesource.Source, *httptest.Server, referencesource.Deps) {
	t.Helper()
	base := fakeDeps(t)
	var deps referencesource.Deps
	src, srv := startSourceWith(t, func(issuer string) referencesource.Deps {
		registry, err := idp.NewRegistry(idp.RegistryConfig{
			RedirectBase: issuer,
			CallbackPath: "/login/{provider}/callback",
			HTTPClient:   provider.Client(),
			Credentials: []idp.Credentials{{
				Provider: idp.Google, ClientID: "cid", ClientSecret: "sec",
				AuthURL:  provider.URL + "/authorize",
				TokenURL: provider.URL + "/token",
				Issuer:   provider.URL,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		login, err := referencesource.NewSocialLogin(
			referencesource.SocialConfig{},
			referencesource.SocialDeps{Registry: registry},
		)
		if err != nil {
			t.Fatal(err)
		}
		deps = base
		deps.Logins = []referencesource.Login{login}
		deps.Auth = nil // a real login must be the only authenticator
		return deps
	})
	return src, srv, deps
}

// startSocial drives /login/google/start and returns the provider redirect, from
// which the test learns the state and the nonce the provider must echo.
func startSocial(t *testing.T, browser *http.Client, base string) *url.URL {
	t.Helper()
	resp, err := browser.Get(base + "/login/google/start?return_to=/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/authorize" {
		t.Fatalf("redirect = %s", loc)
	}
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("nonce") == "" {
		t.Fatalf("authorize URL lacks PKCE or nonce: %s", loc)
	}
	return loc
}

func TestSocialLoginEndToEnd(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, deps := socialSource(t, provider)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	loc := startSocial(t, browser, srv.URL)
	provider.SetNonce(loc.Query().Get("nonce"))

	confirmed := socialCallback(t, browser, srv.URL, loc.Query().Get("state"), "abc")
	if confirmed != "google:oidc-user-1" {
		t.Fatalf("subject = %q, want google:oidc-user-1", confirmed)
	}

	// The credential is stored under the SOURCE's account, namespaced by provider.
	exists, err := deps.Vault.Exists(context.Background(), vault.Identity{Subject: confirmed, Provider: "phigros"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the source did not store the social credential")
	}

	// The session now satisfies the Kit's Consent hook.
	fed, _ := newFederation(t, srv)
	bindWithBrowser(t, fed, browser)
	res, err := fed.Fetch(context.Background(), federation.FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != source {
		t.Fatalf("fetch = %+v", res)
	}
}

func TestSocialLoginStateIsSingleUse(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, _ := socialSource(t, provider)

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loc := startSocial(t, browser, srv.URL)
	provider.SetNonce(loc.Query().Get("nonce"))
	state := loc.Query().Get("state")
	socialCallback(t, browser, srv.URL, state, "abc")

	// Replaying the same state must fail.
	resp, err := browser.Get(srv.URL + "/login/google/callback?state=" + url.QueryEscape(state) + "&code=abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed state = %d, want 400", resp.StatusCode)
	}
}

func TestSocialLoginRejectsUnknownProvider(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	_, srv, _ := socialSource(t, provider)

	resp, err := srv.Client().Get(srv.URL + "/login/myspace/start")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider = %d, want 404", resp.StatusCode)
	}
}

// socialCallback drives the provider callback and returns the confirmed subject.
func socialCallback(t *testing.T, browser *http.Client, baseURL, state, code string) string {
	t.Helper()
	resp, err := browser.Get(baseURL + "/login/google/callback?state=" + url.QueryEscape(state) + "&code=" + code)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d, want 200: %s", resp.StatusCode, body)
	}
	var body struct {
		State   string `json:"state"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.State != "confirmed" {
		t.Fatalf("callback state = %q", body.State)
	}
	return body.Subject
}
