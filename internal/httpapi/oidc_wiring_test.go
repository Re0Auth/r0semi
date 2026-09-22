package httpapi

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
	"os"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/oauth"
)

// TestOIDCWiringEndToEnd mounts the OpenID Provider as the protocol plane and
// proves the business plane accepts its tokens: an authorization-code flow
// issues an OP access token, and /v1/me resolves it through the introspector
// bridge. This is the seam Phase 2b adds.
func TestOIDCWiringEndToEnd(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres-backed wiring test")
	}
	ctx := context.Background()

	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	clientID := "wiring-web-" + hex.EncodeToString(suffix)
	client, err := oauth.NewClient(clientID, "Wiring", oauth.ClientConfidential, "s3cret",
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Clients().Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.OIDC(db.Clients(), postgres.OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   postgres.NewOIDCSigner("wiring", key),
		Login: func(id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))
	opHandler, err := oidchttp.New(oidchttp.Config{
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "wiring-test",
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	api, err := New(Config{
		Issuer:            "http://issuer.example",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id phigros.score.read"},
		"state":                 {"state-1234567890"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := noRedirect.Get(srv.URL + "/oauth/authorize?" + authz.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, b)
	}
	login, _ := url.Parse(resp.Header.Get("Location"))
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID: %s", resp.Header.Get("Location"))
	}
	if err := store.CompleteLogin(ctx, id, "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}

	resp, err = noRedirect.Get(srv.URL + "/oauth/authorize/callback?id=" + url.QueryEscape(id))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := url.Parse(resp.Header.Get("Location"))
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", cb)
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "s3cret")
	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d: %s", tokenResp.StatusCode, tokenBody)
	}
	var tokens map[string]any
	if err := json.Unmarshal(tokenBody, &tokens); err != nil {
		t.Fatal(err)
	}
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %s", tokenBody)
	}
	if _, ok := tokens["id_token"]; ok {
		t.Fatal("id_token returned without openid scope")
	}

	// The business plane must accept the OP token through the bridge.
	meReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+access)
	meResp, err := http.DefaultClient.Do(meReq)
	if err != nil {
		t.Fatal(err)
	}
	defer meResp.Body.Close()
	meBody, _ := io.ReadAll(meResp.Body)
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/me status = %d: %s", meResp.StatusCode, meBody)
	}
	var me struct {
		ID       string   `json:"id"`
		ClientID string   `json:"client_id"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		t.Fatal(err)
	}
	if me.ID != "usr_1" || me.ClientID != clientID {
		t.Fatalf("/v1/me = %+v", me)
	}
	if len(me.Scopes) != 1 || me.Scopes[0] != "account.id" {
		t.Fatalf("scopes = %v, want narrowed account.id", me.Scopes)
	}
}
