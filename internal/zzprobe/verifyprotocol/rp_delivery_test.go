//go:build audit5

package verifyprotocol

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// This file attacks the *impact* claim of RP-1 ("跨客户端令牌重放升级为账号接管"),
// not the code-level fact that `azp` is unread. The report's probe mints the
// foreign-client id_token inside the provider's /token response, i.e. it assumes
// the RP verifies a token an attacker chose. In the shipped flow the RP has one
// and only one source for an id_token -- the token endpoint response of an
// exchange it authenticates itself -- so the interesting question is whether an
// attacker can deliver a token to that verifier at all.
//
// The probe below builds the real browser stack (/auth/{provider}/start,
// /auth/{provider}/callback are the shipped routes) against a provider that can
// be told what to return, and drives both halves:
//
//   - "delivery": the callback carries an attacker-forged id_token (with the
//     genuine nonce of this flow, so the nonce check cannot be what refuses it)
//     while the provider's token endpoint returns no id_token. If the RP takes
//     anything from the request, this logs the victim in.
//   - "control": the same forged token, but returned by the token endpoint. This
//     must log the victim in -- otherwise the first half proves nothing about
//     the RP's verifier, only that the flow was broken.
type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu           sync.Mutex
	idToken      string // "" => the token endpoint returns no id_token
	tokenHits    int
	authzHits    int
	lastForm     url.Values
	lastAuthzURL string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, kid: "kid-verify"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONBody(w, map[string]any{
			"issuer":                                f.server.URL,
			"authorization_endpoint":                f.server.URL + "/authorize",
			"token_endpoint":                        f.server.URL + "/token",
			"userinfo_endpoint":                     f.server.URL + "/userinfo",
			"jwks_uri":                              f.server.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONBody(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: f.key.Public(), KeyID: f.kid, Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authzHits++
		f.lastAuthzURL = r.URL.String()
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK) // the probe never actually authorizes here
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.tokenHits++
		f.lastForm = r.PostForm
		idToken := f.idToken
		f.mu.Unlock()
		out := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}
		if idToken != "" {
			out["id_token"] = idToken
		}
		writeJSONBody(w, out)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONBody(w, map[string]any{"sub": "userinfo-fallback-should-never-be-used"})
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) setIdToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.key, KeyID: f.kid}},
		(&jose.SignerOptions{}).WithHeader("kid", f.kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.idToken = raw
	f.mu.Unlock()
	return raw
}

func (f *fakeIdP) token() (int, url.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenHits, f.lastForm
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// rpStack is the shipped browser-facing stack with fakeIdP in the IdP slot.
type rpStack struct {
	base     string
	accounts *account.MemoryStore
	idp      *fakeIdP
}

func newRPStack(t *testing.T) *rpStack {
	t.Helper()
	f := newFakeIdP(t)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   f.server.Client(),
		Credentials: []idp.Credentials{{
			Provider: "oidcx", ClientID: "cid", ClientSecret: "top-secret",
			Issuer: f.server.URL, // issuer only: endpoints come from discovery
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	accounts := account.NewMemoryStore()
	sessions := memstore.New()
	manager := auth.NewManager(auth.Options{Secure: false, Store: sessions})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Verify CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("test", key),
		Login: func(ctx context.Context, id string) string {
			manager.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer: "https://re0auth.test", Storage: store, CryptoKey: verifyCryptoKey(),
		CryptoKeyID: "test", AllowInsecure: true, Clients: clients,
		Registry: oauth.DefaultRegistry(), Consent: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer: "https://re0auth.test", OIDC: opHandler, TokenIntrospector: opHandler,
		GrantStore: store, DeviceStore: store, Authorization: opHandler,
		Sessions: manager, Accounts: accounts, Auth: authHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &rpStack{base: srv.URL, accounts: accounts, idp: f}
}

func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// start returns the flow's state and the nonce the RP sent upstream.
func (s *rpStack) start(t *testing.T, c *http.Client) (state, nonce string) {
	t.Helper()
	resp, err := c.Get(s.base + "/auth/oidcx/start")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state, nonce = loc.Query().Get("state"), loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("start redirect has no state/nonce: %q", resp.Header.Get("Location"))
	}
	return state, nonce
}

func (s *rpStack) callback(t *testing.T, c *http.Client, query string) (int, string) {
	t.Helper()
	resp, err := c.Get(s.base + "/auth/oidcx/callback?" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("Location")
}

func (s *rpStack) signedIn(t *testing.T, c *http.Client) string {
	t.Helper()
	resp, err := c.Get(s.base + "/v1/sessions/current")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	id, _ := body["user_id"].(string)
	return id
}

// forgedForeignClientToken mints the exact token RP-1 describes: issued by the
// right issuer, audience containing re0auth's client_id, azp naming ANOTHER
// client, subject the victim -- and carrying this flow's genuine nonce, which the
// attacker is assumed to have read out of the authorization URL he was sent to.
func (s *rpStack) forgedForeignClientToken(t *testing.T, nonce, sub string) string {
	t.Helper()
	now := time.Now()
	return s.idp.setIdToken(t, map[string]any{
		"iss":   s.idp.server.URL,
		"sub":   sub,
		"aud":   []string{"cid", "other-client"},
		"azp":   "other-client",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": nonce,
	})
}

// Delivery: the callback cannot be handed an id_token, even a perfectly
// well-formed one carrying this flow's nonce.
func TestVerifyRPCallbackCannotBeHandedAnIDToken(t *testing.T) {
	s := newRPStack(t)
	c := browser(t)

	state, nonce := s.start(t, c)
	forged := s.forgedForeignClientToken(t, nonce, "victim-of-another-client")

	// The token endpoint returns no id_token (this is "the exchange belongs to
	// somebody else's grant" as the RP experiences it).
	s.idp.mu.Lock()
	s.idp.idToken = ""
	s.idp.mu.Unlock()

	status, loc := s.callback(t, c, "code=stolen-code&state="+url.QueryEscape(state)+"&id_token="+url.QueryEscape(forged))
	if got := s.signedIn(t, c); got != "" {
		t.Fatalf("the RP signed a session in from an id_token that arrived in the request: user_id=%q (status=%d loc=%q)",
			got, status, loc)
	}
	if status == http.StatusSeeOther && loc != "" && !containsError(loc) {
		t.Fatalf("the callback reported success even though the exchange returned no id_token: %d %q", status, loc)
	}
	t.Logf("a request-supplied id_token was ignored: callback answered %d %q", status, loc)

	// The RP really did the exchange itself, with its own credentials.
	hits, form := s.idp.token()
	if hits == 0 {
		t.Fatalf("the probe never reached the token endpoint, so the assertion above is vacuous")
	}
	if form.Get("code") != "stolen-code" {
		t.Fatalf("the exchange did not carry the callback's code: %v", form)
	}
	if form.Get("code_verifier") == "" {
		t.Fatalf("the exchange carried no PKCE verifier: %v", form)
	}
}

// Control: the same forged token IS accepted when it comes from the token
// endpoint. This pins the report's code-level fact (azp unread) and proves the
// test above measured delivery, not a broken flow.
func TestVerifyRDTokenEndpointTokenWithForeignAzpIsAccepted(t *testing.T) {
	s := newRPStack(t)
	c := browser(t)

	state, nonce := s.start(t, c)
	s.forgedForeignClientToken(t, nonce, "victim-of-another-client")

	status, loc := s.callback(t, c, "code=c&state="+url.QueryEscape(state))
	if status != http.StatusSeeOther {
		t.Fatalf("control callback = %d %q", status, loc)
	}
	if user := s.signedIn(t, c); user == "" {
		t.Fatal("control: the forged token from the token endpoint was refused too")
	}
	identities, err := s.accounts.Identities(t.Context(), account.UserID(mustSignedIn(t, s, c)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range identities {
		if id.Provider == "oidcx" && id.Subject == "victim-of-another-client" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the session's identities do not include the forged subject: %+v", identities)
	}
	t.Logf("confirmed at unit level: an id_token with azp=other-client and aud=[cid other-client] is accepted as this client's identity")
}

func mustSignedIn(t *testing.T, s *rpStack, c *http.Client) string {
	t.Helper()
	u := s.signedIn(t, c)
	if u == "" {
		t.Fatal("not signed in")
	}
	return u
}

func containsError(loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	return u.Query().Get("error") != ""
}

func verifyCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}
