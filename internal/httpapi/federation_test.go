package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

const fedRedirect = "https://app.example/cb"

func mintToken(t *testing.T, as oauth.Service, clientID, subject string, scopes ...oauth.Scope) string {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	auth, err := as.Authorize(context.Background(), oauth.AuthorizationRequest{
		ClientID: clientID, RedirectURI: fedRedirect, Subject: subject, Scopes: scopes,
		CodeChallenge: pkce(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := as.Exchange(context.Background(), oauth.CodeExchangeRequest{
		ClientID: clientID, Code: auth.Code, RedirectURI: fedRedirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.AccessToken
}

func authedGet(t *testing.T, target, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestGameResourceDataPlane(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resources/profile" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer up-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"game":"phigros","user_id":"usr_test","rks":12.34}`))
	}))
	defer up.Close()

	registry, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: up.URL, TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{User: "usr_test", Game: "phigros", Source: "fake", Version: 1}
	if err := bindings.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	v := newTestVault(t)
	seedBindingSecret(t, v, binding, "up-token")
	fed, err := federation.NewService(federation.Config{Registry: registry, Bindings: bindings, Vault: v, Doer: up.Client()})
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{fedRedirect},
		[]oauth.Scope{oauth.ScopePhigrosProfile, oauth.ScopePhigrosB30})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://re0auth.test", Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{Issuer: "https://re0auth.test", AS: as, Federation: fed})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	at := mintToken(t, as, "cli", "usr_test", oauth.ScopePhigrosProfile)

	// Normalized fetch, with provenance.
	resp := authedGet(t, srv.URL+"/v1/games/phigros/profile", at)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Re0Auth-Source"); got != "fake" {
		t.Fatalf("Re0Auth-Source = %q", got)
	}
	body := decodeResp(t, resp)
	if body["rks"] != 12.34 || body["game"] != "phigros" {
		t.Fatalf("body = %v", body)
	}

	// Public source listing.
	resp = getURL(t, http.DefaultClient, srv.URL+"/v1/games/phigros/sources")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sources status = %d", resp.StatusCode)
	}
	listing := decodeResp(t, resp)
	items, _ := listing["data"].([]any)
	if len(items) != 1 {
		t.Fatalf("sources = %v", listing)
	}
	first, _ := items[0].(map[string]any)
	if first["source"] != "fake" || first["token_class"] != "revocable" {
		t.Fatalf("source view = %v", first)
	}

	// Scope is enforced before any upstream call.
	atB30 := mintToken(t, as, "cli", "usr_test", oauth.ScopePhigrosB30)
	resp = authedGet(t, srv.URL+"/v1/games/phigros/profile", atB30)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scope status = %d, want 403", resp.StatusCode)
	}
	problem := decodeResp(t, resp)
	if problem["code"] != "scope_not_granted" || problem["required_scope"] != "phigros.profile.read" {
		t.Fatalf("problem = %v", problem)
	}

	// An unbound source yields actionable guidance, not a bare failure.
	if err := bindings.Delete(context.Background(), "usr_test", "phigros", "fake"); err != nil {
		t.Fatal(err)
	}
	resp = authedGet(t, srv.URL+"/v1/games/phigros/profile", at)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("not-bound status = %d, want 409", resp.StatusCode)
	}
	problem = decodeResp(t, resp)
	if problem["code"] != "source_not_bound" || problem["game"] != "phigros" || problem["source"] != "fake" {
		t.Fatalf("problem = %v", problem)
	}
	bindURL, _ := problem["bind_url"].(string)
	if bindURL == "" || !strings.Contains(bindURL, "source=fake") {
		t.Fatalf("bind_url = %q", bindURL)
	}

	// Unknown resources are a plain 404.
	resp = authedGet(t, srv.URL+"/v1/games/phigros/nope", at)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown resource status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGameRawAndDegraded(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resources/profile":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"game":"phigros","rks":1}`))
		case "/v1/native/scores":
			if r.Header.Get("Authorization") != "Bearer up-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.native+json")
			_, _ = w.Write([]byte(`{"native":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer good.Close()

	registry, err := federation.NewRegistry(
		federation.Source{Game: "phigros", Name: "a-src", Issuer: bad.URL, TokenClass: "revocable",
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}}},
		federation.Source{Game: "phigros", Name: "b-src", Issuer: good.URL, TokenClass: "revocable", RawBase: good.URL,
			Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	for _, name := range []string{"a-src", "b-src"} {
		b := federation.Binding{User: "usr_test", Game: "phigros", Source: name, Version: 1}
		if err := bindings.Put(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		seedBindingSecret(t, v, b, "up-token")
	}
	fed, err := federation.NewService(federation.Config{Registry: registry, Bindings: bindings, Vault: v, Doer: good.Client(), BaseURL: "https://re0auth.test"})
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{fedRedirect}, []oauth.Scope{oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://re0auth.test", Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}

	api, err := New(Config{Issuer: "https://re0auth.test", AS: as, Federation: fed})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	at := mintToken(t, as, "cli", "usr_test", oauth.ScopePhigrosProfile)

	// a-src fails, b-src answers, and the response says so.
	resp := authedGet(t, srv.URL+"/v1/games/phigros/profile", at)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Re0Auth-Source"); got != "b-src" {
		t.Fatalf("Re0Auth-Source = %q", got)
	}
	if got := resp.Header.Get("Re0Auth-Degraded"); got != "true" {
		t.Fatalf("Re0Auth-Degraded = %q, want true", got)
	}
	resp.Body.Close()

	// Raw passthrough keeps the upstream body and content type.
	resp = authedGet(t, srv.URL+"/v1/games/phigros/sources/b-src/raw/v1/native/scores", at)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/vnd.native") {
		t.Fatalf("raw content-type = %q", got)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(rawBody) != `{"native":true}` {
		t.Fatalf("raw body = %s", rawBody)
	}

	// A source without a raw base is a 404.
	resp = authedGet(t, srv.URL+"/v1/games/phigros/sources/a-src/raw/x", at)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("raw unsupported = %d", resp.StatusCode)
	}
	resp.Body.Close()
}
