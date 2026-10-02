//go:build audit6

// Package zverify is the round-6 ADVERSARIAL REVIEW probe set. It exists to try
// to falsify the round-6 findings taken from the other audit6 zones, not to
// repeat them: every test here is written against the production surfaces from
// scratch (no audit6 fixture is imported or copied), so a mistaken assumption in
// another zone's fixture cannot make a claim look true here.
//
// Run:
//
//	go test -tags audit6 -count=1 ./internal/zzprobe/audit6/zverify/...
//
// Nothing here modifies production code.
package zverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

// vClock is a movable clock. It is guarded because the httptest server answers
// on other goroutines.
type vClock struct {
	mu  sync.Mutex
	now time.Time
}

func newVClock() *vClock { return &vClock{now: time.Now().UTC().Truncate(time.Second)} }

func (c *vClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *vClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

// vEnv is one mounted OP over one in-memory store, built only from exported
// constructors.
type vEnv struct {
	srv    *httptest.Server
	store  *memory.OIDCStore
	clock  *vClock
	issuer string

	// confidential clients
	webID             string
	webSec            string
	adminID, adminSec string

	// public clients
	pubID  string
	pubID2 string
}

func newVEnv(t *testing.T, clock *vClock, introspection []string) *vEnv {
	t.Helper()
	ctx := context.Background()

	const (
		webID    = "vfy-web"
		webSec   = "vfy-web-secret"
		adminID  = "vfy-admin"
		adminSec = "vfy-admin-secret"
		pubID    = "vfy-public"
		pubID2   = "vfy-public-two"
		redirect = "https://app.example/cb"
	)

	scopeAccount := oauth.ScopeAccountID
	scopeScore := oauth.ScopePhigrosScore

	clients := oauth.NewMemoryClientRegistry()
	must := func(c oauth.Client, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("build client: %v", err)
		}
		if err := clients.Create(ctx, c); err != nil {
			t.Fatalf("register client: %v", err)
		}
	}
	c1, e1 := oauth.NewClient(webID, "Vfy Web", oauth.ClientConfidential, webSec,
		[]string{redirect}, []oauth.Scope{scopeAccount, scopeScore})
	must(c1, e1)
	c2, e2 := oauth.NewClient(adminID, "Vfy Admin", oauth.ClientConfidential, adminSec,
		[]string{redirect}, []oauth.Scope{scopeAccount})
	must(c2, e2)
	c3, e3 := oauth.NewClient(pubID, "Vfy Public", oauth.ClientPublic, "",
		[]string{redirect}, []oauth.Scope{scopeAccount})
	must(c3, e3)
	c4, e4 := oauth.NewClient(pubID2, "Vfy Public Two", oauth.ClientPublic, "",
		[]string{redirect}, []oauth.Scope{scopeAccount, scopeScore})
	must(c4, e4)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("vfy-kid", key),
		Now:      clock.Now,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + id
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("vfy-probe-key-0123456789abcdef00"))

	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:               "https://issuer.vfy",
		Storage:              store,
		CryptoKey:            cryptoKey,
		CryptoKeyID:          "vfy",
		AllowInsecure:        true,
		Clients:              clients,
		Registry:             oauth.DefaultRegistry(),
		Consent:              store,
		IntrospectionClients: introspection,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &vEnv{
		srv: srv, store: store, clock: clock, issuer: "https://issuer.vfy",
		webID: webID, webSec: webSec, adminID: adminID, adminSec: adminSec,
		pubID: pubID, pubID2: pubID2,
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// vNoRedirect never follows a redirect, so the probes can read the answer the
// protocol plane actually wrote.
var vNoRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (e *vEnv) do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := vNoRedirect.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func (e *vEnv) get(t *testing.T, target string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e.do(t, req)
}

// post sends a form POST with an optional HTTP Basic identity. basicID is sent
// verbatim (no escaping of its own), which is what the percent-encoding probe
// needs.
func (e *vEnv) post(t *testing.T, path string, form map[string]string, basicID, basicSecret string) (*http.Response, []byte) {
	t.Helper()
	body := encodeForm(form)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	return e.do(t, req)
}

func encodeForm(m map[string]string) string {
	var b strings.Builder
	first := true
	for k, v := range m {
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(urlEscape(k))
		b.WriteByte('=')
		b.WriteString(urlEscape(v))
	}
	return b.String()
}

func urlEscape(s string) string {
	// A small, dependency-free form encoder for the probe's ASCII keys/values.
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

func vJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	return out
}

// vTokenFields is a token response decoded into the fields a probe compares.
type vTokenFields struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func vTokens(t *testing.T, raw []byte) vTokenFields {
	t.Helper()
	var out vTokenFields
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not a token response: %s", raw)
	}
	return out
}

// idTokenPayload decodes the JWS payload without verifying it. These probes
// inspect what the OP ISSUED.
func idTokenPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	return vJSON(t, payload)
}

// ---------------------------------------------------------------------------
// flow drivers
// ---------------------------------------------------------------------------

const vRedirect = "https://app.example/cb"

// vPKCE is a syntactically valid RFC 7636 verifier/challenge pair, S256.
func vPKCE() (verifier, challenge string) {
	verifier = strings.Repeat("k", 64)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize starts the interactive flow and returns the pending auth request id
// the OP redirected to, plus the raw response.
func (e *vEnv) authorize(t *testing.T, clientID string, scopes []string, extra map[string]string) (string, *http.Response, []byte) {
	t.Helper()
	_, challenge := vPKCE()
	q := map[string]string{
		"response_type":         "code",
		"client_id":             clientID,
		"redirect_uri":          vRedirect,
		"scope":                 strings.Join(scopes, " "),
		"state":                 "vfy-state",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
	for k, v := range extra {
		q[k] = v
	}
	parts := make([]string, 0, len(q))
	for k, v := range q {
		parts = append(parts, urlEscape(k)+"="+urlEscape(v))
	}
	resp, raw := e.get(t, "/oauth/authorize?"+strings.Join(parts, "&"))
	return authRequestID(t, resp), resp, raw
}

func authRequestID(t *testing.T, resp *http.Response) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	i := strings.Index(loc, "authRequestID=")
	if i < 0 {
		return ""
	}
	id := loc[i+len("authRequestID="):]
	if j := strings.IndexByte(id, '&'); j >= 0 {
		id = id[:j]
	}
	return id
}

// completeLogin records an auth_time the way the production login hook does
// (SetAuthTime, before the consent page is shown) and completes the pending
// request. It RETURNS the store's error instead of failing, so a probe can
// assert the S02-1 refusal (oidcstore.ErrReauthenticationRequired) rather than
// treat it as a fixture problem.
func (e *vEnv) completeLogin(t *testing.T, id, subject string, scopes []string, authTime time.Time) error {
	t.Helper()
	if !authTime.IsZero() {
		if err := e.store.SetAuthTime(context.Background(), id, authTime); err != nil {
			t.Fatalf("SetAuthTime: %v", err)
		}
	}
	return e.store.CompleteLogin(context.Background(), id, subject, scopes)
}

// finishCallback drives the OP callback leg and returns the authorization code.
func (e *vEnv) finishCallback(t *testing.T, id string) string {
	t.Helper()
	resp, raw := e.get(t, "/oauth/authorize/callback?id="+id)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d: %s", resp.StatusCode, raw)
	}
	loc := resp.Header.Get("Location")
	i := strings.Index(loc, "code=")
	if i < 0 {
		t.Fatalf("no code in %q", loc)
	}
	code := loc[i+len("code="):]
	if j := strings.IndexByte(code, '&'); j >= 0 {
		code = code[:j]
	}
	return code
}

// approveAndExchange completes the request and exchanges the code, so a probe
// can inspect the id_token the completion produced.
func (e *vEnv) approveAndExchange(t *testing.T, id, subject, clientID, secret string, scopes []string, authTime time.Time) vTokenFields {
	t.Helper()
	if err := e.completeLogin(t, id, subject, scopes, authTime); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	code := e.finishCallback(t, id)
	verifier, _ := vPKCE()
	resp, raw := e.post(t, "/oauth/token", map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  vRedirect,
		"code_verifier": verifier,
	}, clientID, secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange = %d: %s", resp.StatusCode, raw)
	}
	return vTokens(t, raw)
}

// approveAndCallback runs the consent decision's store call and completes the
// callback, with an optional auth_time recorded the way the production login
// hook does (SetAuthTime, before the consent page is shown).
func (e *vEnv) approveAndCallback(t *testing.T, id, subject string, scopes []string, authTime time.Time) string {
	t.Helper()
	if err := e.completeLogin(t, id, subject, scopes, authTime); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	return e.finishCallback(t, id)
}

// codeFlow drives one full authorization-code exchange.
func (e *vEnv) codeFlow(t *testing.T, clientID, secret string, scopes []string, subject string, authTime time.Time) vTokenFields {
	t.Helper()
	verifier, _ := vPKCE()
	id, resp, raw := e.authorize(t, clientID, scopes, map[string]string{"nonce": "vfy-nonce"})
	if id == "" {
		t.Fatalf("authorize did not start the interactive flow: %d %s", resp.StatusCode, raw)
	}
	code := e.approveAndCallback(t, id, subject, scopes, authTime)
	resp, raw = e.post(t, "/oauth/token", map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  vRedirect,
		"code_verifier": verifier,
	}, clientID, secret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange = %d: %s", resp.StatusCode, raw)
	}
	return vTokens(t, raw)
}

// userinfoStatus asks the userinfo endpoint for one bearer and returns the
// status.
func (e *vEnv) userinfoStatus(t *testing.T, bearer string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, raw := e.do(t, req)
	return resp.StatusCode, raw
}

func (e *vEnv) refresh(t *testing.T, clientID, secret, refreshToken string) (*http.Response, []byte) {
	t.Helper()
	form := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}
	if secret == "" {
		form["client_id"] = clientID
		return e.post(t, "/oauth/token", form, "", "")
	}
	return e.post(t, "/oauth/token", form, clientID, secret)
}

// deviceStart asks for a device authorization. A public client names itself in
// the body; a confidential one authenticates with Basic.
func (e *vEnv) deviceStart(t *testing.T, clientID, secret string, scopes []string) (*http.Response, []byte) {
	t.Helper()
	form := map[string]string{
		"client_id": clientID,
		"scope":     strings.Join(scopes, " "),
	}
	if secret == "" {
		return e.post(t, "/oauth/device_authorization", form, "", "")
	}
	return e.post(t, "/oauth/device_authorization", form, clientID, secret)
}

// devicePoll asks the token endpoint for the device grant.
func (e *vEnv) devicePoll(t *testing.T, deviceCode, clientID, secret string, postSecret bool) (*http.Response, []byte) {
	t.Helper()
	form := map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode,
	}
	switch {
	case postSecret:
		form["client_id"] = clientID
		form["client_secret"] = secret
		return e.post(t, "/oauth/token", form, "", "")
	case secret == "":
		// The public "none" shape: the client names itself in the body.
		if clientID != "" {
			form["client_id"] = clientID
		}
		return e.post(t, "/oauth/token", form, "", "")
	default:
		return e.post(t, "/oauth/token", form, clientID, secret)
	}
}
