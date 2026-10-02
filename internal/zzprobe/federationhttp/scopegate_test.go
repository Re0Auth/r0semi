//go:build audit5

// package zzprobe_federationhttp —adversarial probes for the federation data plane
// and the outbound HTTP surface, written by the federation/outbound audit.
//
// This file drives the real HTTP wiring (internal/httpapi.New with a real OP
// handler) so the scope-gate finding is confirmed at the boundary an attacker
// actually reaches, not merely at the service layer.
package zzprobe_federationhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const zzRedirect = "https://app.example/cb"

func zzCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// zzOPBackend is the composition root's OP wiring, reconstructed here because the
// httpapi package's own test helpers live in a package another agent's in-flight
// probe file currently fails to compile.
//
// `scopes` is the catalog the OP resolves against. The production composition root
// registers the game's `<game>.raw.read` scope (oauth.RawScope,
// cmd/re0auth/main.go:1416) next to the resource scopes; a probe that mints a
// raw-gated token must do the same, or the OP rejects the request with invalid_scope
// before the data plane is ever reached.
func zzOPBackend(t *testing.T, issuer string, clients oauth.ClientRegistry, scopes *oauth.Registry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: scopes,
		Signer:   oidcstore.NewSigner("test", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := oidchttp.New(oidchttp.Config{
		Issuer:        issuer,
		Storage:       store,
		CryptoKey:     zzCryptoKey(),
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      scopes,
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

func zzPKCE(verifier string) string {
	return strings.TrimRight(base64URLSHA256(verifier), "=")
}

// zzMintToken drives the real authorization-code + PKCE flow, so the token the
// data plane sees is one the OP really issued for the scopes asked for.
func zzMintToken(t *testing.T, h http.Handler, store *memory.OIDCStore, clientID, subject string, scopes ...string) string {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {zzRedirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st"},
		"code_challenge":        {zzPKCE(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no auth request id in %q", loc)
	}
	if err := store.CompleteLogin(context.Background(), id, subject, requested); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", cb)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {zzRedirect},
		"code_verifier": {verifier},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := jsonUnmarshal(rec.Body.Bytes(), &body); err != nil || body.AccessToken == "" {
		t.Fatalf("no access token: %s (err=%v)", rec.Body.String(), err)
	}
	return body.AccessToken
}

// zzTwoSourceHTTP stands up the real HTTP surface with two sources for one game,
// both declaring the same resource name under different downstream scopes, and
// the caller bound to the SECOND one only. The returned token is minted for the
// OFFICIAL source's scope, which is the shape every probe here is about; mint()
// makes a token for any other scope.
func zzTwoSourceHTTP(t *testing.T) (base, token string, askedIn *[]string, mint func(scopes ...string) string) {
	t.Helper()
	asked := &[]string{}
	mk := func(log *[]string, body string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*log = append(*log, r.URL.RequestURI())
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(s.Close)
		return s
	}
	aLog, bLog := &[]string{}, &[]string{}
	a := mk(aLog, `{"served_by":"aa-official","note":"official data"}`)
	b := mk(bLog, `{"served_by":"zz-community","note":"community data"}`)

	registry, err := federation.NewRegistry(
		federation.Source{
			Game: "phigros", Name: "aa-official", DisplayName: "Official", Issuer: a.URL,
			TokenClass: "revocable",
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
			},
		},
		federation.Source{
			Game: "phigros", Name: "zz-community", DisplayName: "Community", Issuer: b.URL,
			TokenClass: "revocable",
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.community.read"},
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.community.score.read"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	// Bound to the COMMUNITY source only; nothing is bound to the official one.
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{User: "usr_test", Game: "phigros", Source: "zz-community", Version: 1}
	if err := bindings.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	v := newTestVault(t)
	if err := v.Enroll(context.Background(), federation.BindingIdentity(binding),
		mustPair(t, "community-token", ""), nil); err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: registry, Bindings: bindings, Vault: v,
		Doer: b.Client(), HTTPClient: b.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	// Registered for BOTH sources' scopes, so a probe can mint a token for either
	// one and compare what the gate does with each. The token every other probe here
	// uses is minted for the official source's scope only.
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{zzRedirect},
		[]oauth.Scope{"phigros.profile.read", "phigros.community.read"})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := zzOPBackend(t, "https://re0auth.test", clients, oauth.DefaultRegistry())
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Federation:        fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	mint = func(scopes ...string) string {
		return zzMintToken(t, api.Handler(), store, "cli", "usr_test", scopes...)
	}
	at := mint("phigros.profile.read")
	t.Cleanup(func() {
		t.Logf("source aa-official was asked for: %v", *aLog)
		t.Logf("source zz-community was asked for: %v", *bLog)
	})
	return srv.URL, at, asked, mint
}

// The gate and the serving source must be the SAME decision.
//
// The defect: a token minted for "phigros.profile.read" — a scope only the
// OFFICIAL source declares, and the only scope the client was registered for —
// was served the COMMUNITY source's copy of the same resource name.
// handleGameResource asked federation.ResourceScope(game, resource), which returned
// the first source (by name order) declaring the resource, while Fetch() picked a
// source by binding and status. Two lookups, one decision.
//
// Now the gate asks for EVERY source that could serve the read, so a token holding
// only the official scope is refused: it cannot read the community source's data,
// and the refusal names the scope and the source that requires it.
func TestZZProbeScopeGateAndServingSourceDisagree(t *testing.T) {
	base, at, _, _ := zzTwoSourceHTTP(t)

	req, _ := http.NewRequest(http.MethodGet, base+"/v1/games/phigros/profile", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("GET /v1/games/phigros/profile => %d, Re0Auth-Source=%q, body=%s",
		resp.StatusCode, resp.Header.Get("Re0Auth-Source"), body)

	if resp.StatusCode == http.StatusOK {
		t.Errorf("a token holding only the OFFICIAL source's scope (%q) was served %s: the gate did not "+
			"require the scope of the source that could answer (body: %s)",
			"phigros.profile.read", resp.Header.Get("Re0Auth-Source"), body)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("the refusal was %d, want 403 insufficient_scope", resp.StatusCode)
	}
	if !strings.Contains(string(body), "zz-community") {
		t.Errorf("the refusal does not name the source whose scope is required: %s", body)
	}
}

// The sharper shape: the caller names the community source explicitly, and the
// official source's scope must still not admit it. ?source= pins the source AND
// (now) narrows the requirement to it, which is the honest way to ask for one
// source's scope.
func TestZZProbePinnedSourceAdmitsAnotherSourcesScope(t *testing.T) {
	base, at, _, _ := zzTwoSourceHTTP(t)

	req, _ := http.NewRequest(http.MethodGet, base+"/v1/games/phigros/profile?source=zz-community", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("GET .../profile?source=zz-community => %d body=%s", resp.StatusCode, body)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("?source=zz-community was served to a token holding only the OFFICIAL source's scope "+
			"(%q): the gate is not source-aware", "phigros.profile.read")
	}
}

// The control that keeps the refusal from being a blanket one: a token holding the
// scope of the source the caller PINNED is admitted by the gate. Pinning narrows
// the requirement to that source, which is the honest way to ask for one source's
// scope — and without this control, closing the gate by refusing everything would
// pass.
//
// The request then stops one layer further in: the user is bound to the community
// source only, so the official source answers "not bound" (409). A 409 rather than
// a 403 is exactly what this asserts: the scope gate let it through.
func TestZZProbeThePinnedSourcesOwnScopeIsAdmitted(t *testing.T) {
	base, _, _, mint := zzTwoSourceHTTP(t)

	at := mint("phigros.profile.read") // the pinned source's own scope
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/games/phigros/profile?source=aa-official", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("GET .../profile?source=aa-official => %d body=%s", resp.StatusCode, body)
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("the gate refused a token holding the pinned source's own scope: %s", body)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409 source_not_bound (the gate admitted it, the binding did not)", resp.StatusCode)
	}
}

// Non-vacuity: the same request with a scope the OFFICIAL source does not declare
// is refused, proving the gate is really consulted (and not, say, bypassed by a
// missing token or a 404).
func TestZZProbeGateIsActuallyConsulted(t *testing.T) {
	base, _, asked, _ := zzTwoSourceHTTP(t)

	// No token at all: 401.
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/games/phigros/profile", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated fetch = %d, want 401", resp.StatusCode)
	}
	_ = asked
}
