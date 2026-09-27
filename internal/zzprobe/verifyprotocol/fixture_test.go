//go:build audit5

// Package verifyprotocol holds the ADVERSARIAL VERIFIER's probes for the
// protocol-plane report (docs/audit-5/findings/protocol.md).
//
// It contains no production code and modifies no existing file. Its fixture is a
// deliberately independent re-creation of the one in internal/zzprobe/protocol/
// (a real oidchttp.New on an httptest server over the in-memory OP store), so a
// spot-check here does not inherit a bug from the report's own fixture.
package verifyprotocol

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// noRedirect keeps a probe looking at the redirect itself.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type opEnv struct {
	server  *httptest.Server
	handler *oidchttp.Handler
	store   *memory.OIDCStore
	clients *oauth.MemoryClientRegistry

	webID  string
	webSec string
	pubID  string
}

// newOPEnv mounts the protocol plane the way the composition root does: a real
// oidchttp.Handler over the memory OP store, with a confidential client
// registered for account.id + phigros.score.read and a public one for account.id.
func newOPEnv(t *testing.T) opEnv {
	t.Helper()
	ctx := context.Background()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	tag := hex.EncodeToString(suffix)
	webID, pubID := "verify-web-"+tag, "verify-pub-"+tag
	const webSec = "verify-web-secret"

	clients := oauth.NewMemoryClientRegistry()
	web, err := oauth.NewClient(webID, "Verify Web", oauth.ClientConfidential, webSec,
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := oauth.NewClient(pubID, "Verify Public", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{web, pub} {
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("verify-kid", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("verify0123456789abcdef0123456789"))

	scopes := []string{}
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}

	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:        "https://issuer.verify",
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "verify",
		Scopes:        scopes,
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return opEnv{server: srv, handler: handler, store: store, clients: clients, webID: webID, webSec: webSec, pubID: pubID}
}

func (e opEnv) get(t *testing.T, u string) *http.Response {
	t.Helper()
	resp, err := noRedirect.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	return out
}

func pkceValue(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e opEnv) authValues(redirect string, scopes []string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-verify"},
		"nonce":                 {"nonce-verify"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
}

// code issues one authorization code through the real authorize -> login ->
// consent callback path, returning the code and the verifier that matches it.
func (e opEnv) code(t *testing.T, scopes []string) (code, verifier string) {
	t.Helper()
	verifier = strings.Repeat("v", 64)
	authz := e.authValues("https://client.example/cb", scopes)
	authz.Set("code_challenge", pkceValue(verifier))
	resp := e.get(t, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	_ = bodyOf(t, resp)
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, "usr_verify", scopes); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cb.Query().Get("code"); got != "" {
		return got, verifier
	}
	t.Fatalf("no code in %q", resp.Header.Get("Location"))
	return "", ""
}

func (e opEnv) postToken(t *testing.T, form url.Values) (map[string]any, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(e.webID, e.webSec)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := bodyOf(t, resp)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

// tokens runs a full code flow and returns the token response.
func (e opEnv) tokens(t *testing.T, scopes []string) map[string]any {
	t.Helper()
	code, verifier := e.code(t, scopes)
	out, status := e.postToken(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token = %d %v", status, out)
	}
	return out
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func idTokenClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSON(t, payload)
}
