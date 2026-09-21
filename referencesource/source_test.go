package referencesource_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/upstreamkit/conformance"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	game         = "phigros"
	source       = "taptap-reference"
	re0auth      = "https://re0auth.test"
	re0authCB    = re0auth + "/auth/upstream/phigros/taptap-reference/callback"
	clientID     = "re0auth"
	clientSecret = "dev-secret"
	subject      = "openid_1"
)

func newVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("test", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func fakeDeps(t *testing.T) referencesource.Deps {
	t.Helper()
	return referencesource.Deps{
		Auth: referencesource.StaticAuthenticator{Principal: referencesource.Principal{
			Subject: subject, Display: "Paimon", Credential: []byte("native-credential"),
			Meta: map[string]string{"provider": "taptap"},
		}},
		Vault: newVault(t),
		Reader: referencesource.StaticReader{
			"profile": map[string]any{"game": "phigros", "rks": 15.2},
			"scores":  []any{map[string]any{"id": "s1", "score": 1000000}},
		},
	}
}

// startSource builds the source at a fixed loopback URL and serves it. The
// issuer must be known before the handler is built, hence the manual listener.
func startSource(t *testing.T, deps referencesource.Deps) (*referencesource.Source, *httptest.Server) {
	return startSourceWith(t, func(string) referencesource.Deps { return deps })
}

// startSourceWith builds the source at a fixed loopback URL and serves it. build
// receives the issuer so logins can register the right redirect URL. The issuer
// must be known before the handler is built, hence the manual listener.
func startSourceWith(t *testing.T, build func(issuer string) referencesource.Deps) (*referencesource.Source, *httptest.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	src, err := referencesource.New(referencesource.Config{
		Discovery: upstreamkit.Config{
			Game: game, Source: source, DisplayName: "Phigros (reference source)",
			Issuer: issuer, TokenClass: upstreamkit.TokenRevocable,
			Resources: []upstreamkit.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
			},
		},
		Provider: "phigros",
		Downstream: referencesource.Client{
			ID: clientID, Secret: clientSecret, RedirectURIs: []string{re0authCB},
		},
	}, build(issuer))
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(src.Handler())
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return src, srv
}

func newFederation(t *testing.T, srv *httptest.Server) (federation.Service, vault.Service) {
	t.Helper()
	registry, err := federation.NewRegistry(federation.Source{
		Game: game, Name: source, Issuer: srv.URL, TokenClass: "revocable",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
		},
		ClientID: clientID, ClientSecret: clientSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := newVault(t)
	fed, err := federation.NewService(federation.Config{
		Registry: registry,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    v,
		Doer:     srv.Client(),
		BaseURL:  re0auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fed, v
}

// bind drives the real OAuth 2.0 authorization-code + PKCE flow: Re0Auth's
// federation starts the bind, the browser visits the source's authorize
// endpoint, and the source redirects back with a code.
func bind(t *testing.T, fed federation.Service, srv *httptest.Server) federation.Binding {
	t.Helper()
	challenge, err := fed.BeginBind(context.Background(), "usr_1", game, source, "/")
	if err != nil {
		t.Fatal(err)
	}

	client := *srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(challenge.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if code == "" {
		t.Fatalf("no code in redirect %s", loc)
	}

	binding, _, err := fed.CompleteBind(context.Background(), "usr_1", state, code)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestDiscoveryDocument(t *testing.T) {
	src, srv := startSource(t, fakeDeps(t))

	if src.Discovery().OAuth.Issuer != srv.URL {
		t.Fatalf("issuer = %q, want %q", src.Discovery().OAuth.Issuer, srv.URL)
	}
	resp, err := srv.Client().Get(srv.URL + "/.well-known/re0auth-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var doc upstreamkit.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Game != game || doc.Source != source || doc.ProtocolVersion != 1 {
		t.Fatalf("discovery = %+v", doc)
	}
	want := map[string]bool{upstreamkit.AccountScope: false, "phigros.profile.read": false, "phigros.score.read": false}
	for _, s := range doc.ScopesSupported {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for scope, seen := range want {
		if !seen {
			t.Errorf("scopes_supported is missing %s", scope)
		}
	}
	if len(doc.Resources) != 2 {
		t.Fatalf("resources = %+v", doc.Resources)
	}
}

// The whole point of the Kit: a source whose native login is not OAuth 2.0 can
// still be bound by Re0Auth over OAuth 2.0, and the source keeps its own
// credential under its own account id.
func TestFederationEndToEnd(t *testing.T) {
	deps := fakeDeps(t)
	_, srv := startSource(t, deps)
	fed, fv := newFederation(t, srv)
	binding := bind(t, fed, srv)

	// The source stored its native credential under its OWN subject (openid_1),
	// not under Re0Auth's user id (usr_1).
	exists, err := deps.Vault.Exists(context.Background(), vault.Identity{Subject: subject, Provider: "phigros"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the source did not store its own credential")
	}
	if _, err := deps.Vault.Exists(context.Background(), vault.Identity{Subject: "usr_1", Provider: "phigros"}); err != nil {
		t.Fatal(err)
	}

	res, err := fed.Fetch(context.Background(), federation.FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != source || res.Degraded {
		t.Fatalf("fetch = %+v", res)
	}
	var profile map[string]any
	if err := json.Unmarshal(res.Data, &profile); err != nil {
		t.Fatal(err)
	}
	if profile["game"] != "phigros" {
		t.Fatalf("payload = %v", profile)
	}

	if _, err := fed.Fetch(context.Background(), federation.FetchRequest{User: "usr_1", Game: game, Resource: "scores"}); err != nil {
		t.Fatal(err)
	}

	// The binding's access token now lives in Re0Auth's vault, not in the
	// binding store, and must still satisfy the data-plane conformance checks.
	var at string
	if err := fv.Use(context.Background(), federation.BindingIdentity(binding), func(plain []byte) error {
		var secret struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(plain, &secret); err != nil {
			return err
		}
		at = secret.AccessToken
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if at == "" {
		t.Fatal("the binding store held no token and the vault had none either")
	}
	for _, f := range conformance.Run(context.Background(), srv.URL, conformance.Options{
		HTTPClient: srv.Client(), AccessToken: at,
	}) {
		if f.Level == conformance.LevelError {
			t.Errorf("conformance %s: %s", f.Check, f.Message)
		}
	}
}

// A user who has not logged in at the source must be denied -- never given a
// fabricated identity.
func TestAuthorizeWithoutLoginIsDenied(t *testing.T) {
	deps := fakeDeps(t)
	deps.Auth = referencesource.StaticAuthenticator{Err: errors.New("no session at the source")}
	_, srv := startSource(t, deps)
	fed, _ := newFederation(t, srv)

	challenge, err := fed.BeginBind(context.Background(), "usr_1", game, source, "/")
	if err != nil {
		t.Fatal(err)
	}
	client := *srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(challenge.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("denied authorize redirected to %s", loc)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	deps := fakeDeps(t)
	cfg := referencesource.Config{
		Discovery: upstreamkit.Config{
			Game: game, Source: source, DisplayName: "x", Issuer: "https://x.example",
			TokenClass: upstreamkit.TokenRevocable,
		},
		Provider:   "taptap",
		Downstream: referencesource.Client{ID: clientID, RedirectURIs: []string{re0authCB}},
	}
	if _, err := referencesource.New(cfg, referencesource.Deps{}); err == nil {
		t.Fatal("New accepted an empty Deps")
	}
	deps.Auth = nil
	if _, err := referencesource.New(cfg, deps); err == nil {
		t.Fatal("New accepted a nil Authenticator")
	}
}
