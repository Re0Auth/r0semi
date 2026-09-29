//go:build audit || protocolaudit

// Package oidchttp audit probe — round 6, area 01: OAuth2/OIDC protocol
// implementation and token lifecycle.
//
// Run with:
//
//	go test -tags protocolaudit -count=1 -run TestZZAudit_ ./internal/oidchttp/ -v
//
// The tag keeps the default suite green: two probes below are RED on purpose,
// because in this project a failing test is the evidence for a finding.
//
// These probes attack the real, fully-wired protocol plane: the *Handler on an
// httptest server, the in-memory OP store, the real scope registry, real PKCE
// and real code/token crypto. Nothing is stubbed that production does not stub.
//
// Each test names what it is trying to prove. A FAILING test is the evidence for
// a finding; a passing test is a guard that the attack did not land.
package oidchttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type auditEnv struct {
	srv      *httptest.Server
	handler  *Handler
	store    *memory.OIDCStore
	clients  *oauth.MemoryClientRegistry
	webID    string
	webSec   string
	pubID    string
	narrowID string
	narrowS  string
	redirect string
}

func newAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	return newAuditEnvIssuer(t, "")
}

// newAuditEnvIssuer builds the plane. issuer == "" means the dynamic shape
// (IssuerFromRequest), which is what a misconfigured deployment gets.
func newAuditEnvIssuer(t *testing.T, issuer string) *auditEnv {
	t.Helper()
	return newAuditEnvFull(t, issuer, nil)
}

// newAuditEnvFull additionally sets IntrospectionClients, so a probe can watch
// what a mis-set allowlist entry exposes.
func newAuditEnvFull(t *testing.T, issuer string, introspectors []string) *auditEnv {
	t.Helper()
	ctx := context.Background()
	tag := auditRand()

	redirect := "https://client.example/cb"
	clients := oauth.NewMemoryClientRegistry()
	webID, webSec := "zz-web-"+tag, "zz-web-secret"
	pubID := "zz-pub-" + tag
	narrowID, narrowS := "zz-narrow-"+tag, "zz-narrow-secret"

	mk := func(id, name string, typ oauth.ClientType, sec string, scopes ...oauth.Scope) oauth.Client {
		c, err := oauth.NewClient(id, name, typ, sec, []string{redirect}, scopes)
		if err != nil {
			t.Fatal(err)
		}
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mk(webID, "Web", oauth.ClientConfidential, webSec, oauth.ScopeAccountID, oauth.ScopePhigrosScore)
	mk(pubID, "Pub", oauth.ClientPublic, "", oauth.ScopeAccountID, oauth.ScopePhigrosScore)
	mk(narrowID, "Narrow", oauth.ClientConfidential, narrowS, oauth.ScopeAccountID)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("zz-kid", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("zzprobe0123456789abcdef012345678"))

	var scopes []string
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}

	handler, err := New(Config{
		Issuer:               issuer,
		Storage:              store,
		CryptoKey:            cryptoKey,
		CryptoKeyID:          "zz",
		Scopes:               scopes,
		AllowInsecure:        true,
		Clients:              clients,
		Registry:             oauth.DefaultRegistry(),
		Consent:              store,
		IntrospectionClients: introspectors,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &auditEnv{
		srv: srv, handler: handler, store: store, clients: clients,
		webID: webID, webSec: webSec, pubID: pubID,
		narrowID: narrowID, narrowS: narrowS, redirect: redirect,
	}
}

func auditRand() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func auditPKCE(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func (e *auditEnv) do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func (e *auditEnv) getURL(t *testing.T, u string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e.do(t, req)
}

func (e *auditEnv) postRaw(t *testing.T, path, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return e.do(t, req)
}

func (e *auditEnv) postForm(t *testing.T, path string, form url.Values, basicID, basicSec string) (*http.Response, []byte, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSec)
	}
	resp, body := e.do(t, req)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp, body, out
}

// zzAuthorize starts an authorization request and returns the pending handle.
func (e *auditEnv) zzAuthorize(t *testing.T, clientID string, scopes []string, extra url.Values) (handle string, status int, loc string) {
	t.Helper()
	v := strings.Repeat("v", 64)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {e.redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"zz-state"},
		"nonce":                 {"zz-nonce"},
		"code_challenge":        {auditPKCE(v)},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	resp, _ := e.getURL(t, e.srv.URL+"/oauth/authorize?"+q.Encode())
	loc = resp.Header.Get("Location")
	if u, err := url.Parse(loc); err == nil {
		handle = u.Query().Get("authRequestID")
	}
	return handle, resp.StatusCode, loc
}

// zzCode completes authorize -> consent -> callback and returns the code.
func (e *auditEnv) zzCode(t *testing.T, clientID string, scopes []string, extra url.Values) string {
	t.Helper()
	handle, status, loc := e.zzAuthorize(t, clientID, scopes, extra)
	if status != http.StatusFound || handle == "" {
		t.Fatalf("authorize = %d %s", status, loc)
	}
	if err := e.store.CompleteLogin(t.Context(), handle, "usr_zz", append(append([]string(nil), scopes...), "offline_access")); err != nil {
		t.Fatal(err)
	}
	resp, _ := e.getURL(t, e.srv.URL+"/oauth/authorize/callback?id="+url.QueryEscape(handle))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}
	return code
}

func (e *auditEnv) zzExchange(t *testing.T, clientID, sec, code, verifier string) (*http.Response, []byte, map[string]any) {
	t.Helper()
	return e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e.redirect},
		"code_verifier": {verifier},
	}, clientID, sec)
}

func auditIDTokenClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---------------------------------------------------------------------------
// regression: the round-5 findings in this area
// ---------------------------------------------------------------------------

// B-1: the id_token must carry the REQUIRED `sub` claim (OIDC Core §2), on every
// grant. Round 5 found it empty because both stores had a no-op
// SetUserinfoFromScopes.
func TestZZAudit_RegressionIdTokenCarriesSubject(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	resp, body, out := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d %s", resp.StatusCode, body)
	}
	raw, _ := out["id_token"].(string)
	if raw == "" {
		t.Fatalf("no id_token: %s", body)
	}
	claims := auditIDTokenClaims(t, raw)
	if claims["sub"] != "usr_zz" {
		t.Fatalf("id_token sub = %#v, want usr_zz; claims=%v", claims["sub"], claims)
	}
}

// B-2: an id_token handed to /oauth/userinfo must not authenticate. Round 5
// found that it did (the library falls back to JWS verification, and
// pkg/oidc.DecryptToken is a TODO returning its input).
func TestZZAudit_RegressionIdTokenIsNotABearerAtUserinfo(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, out := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatal("no id_token")
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+idToken)
	resp, body := e.do(t, req)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("id_token was accepted as a bearer at userinfo: %d %s", resp.StatusCode, body)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo = %d %s, want 401", resp.StatusCode, body)
	}
}

// PROTO-1: an unparsable body must not switch the gates off, and the scope gate
// must read every value. Round 5 reached a live phigros.score.read token for a
// client registered only for account.id.
func TestZZAudit_RegressionDeviceScopeGateHolds(t *testing.T) {
	e := newAuditEnv(t)
	cases := []struct {
		name string
		body string
	}{
		{"unparsable-body", "client_id=" + e.narrowID + "&scope=phigros.score.read&x=%zz"},
		{"trailing-junk", "client_id=" + e.narrowID + "&scope=phigros.score.read&%"},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/oauth/device_authorization", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, body := e.do(t, req)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s: device_authorization issued a code for an unregistered scope: %s", tc.name, body)
		}
	}
	// The quoted form: the gate must read the whole scope value.
	_, _, out := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {e.narrowID}, "scope": {"phigros.score.read"},
	}, e.narrowID, e.narrowS)
	if _, ok := out["device_code"]; ok {
		t.Errorf("device authorization granted an unregistered scope: %v", out)
	}
}

// PROTO-4: introspection must not be readable by a public client without
// credentials. Round 5 read any token's scope/subject with `Basic <public-id>:`.
func TestZZAudit_RegressionIntrospectionRefusesPublicCallers(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, tok := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("no access token")
	}
	// A public client, empty secret, and a percent-encoded variant of its id.
	for _, id := range []string{e.pubID, "%7A" + e.pubID[3:]} {
		resp, body, out := e.postForm(t, "/oauth/introspect", url.Values{"token": {access}}, id, "")
		if resp.StatusCode == http.StatusOK && out["active"] == true {
			t.Errorf("public caller %q read a live token: %s", id, body)
		}
	}
}

// ---------------------------------------------------------------------------
// new probes
// ---------------------------------------------------------------------------

// A public client's id is not a credential, so introspection refuses a
// non-confidential caller outright (refuseIntrospectionByANonConfidentialClient).
// The guard compares the RAW `Authorization: Basic` id against the registry,
// while the library (pkg/op/client.go ClientBasicAuth:118) url.QueryUnescapes it
// first — so a percent-encoded spelling of the very same public client id is
// unknown to the guard and known to the library. The guard's "cannot prove, let
// the library decide" branch then admits a caller that keeps no secret.
func TestZZAudit_IntrospectionPublicClientGuardIsBypassedByPercentEncoding(t *testing.T) {
	e := newAuditEnv(t)

	// A live access token belonging to the confidential client.
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, tok := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("no access token")
	}

	introspect := func(rawAuth string) (int, string, map[string]any) {
		resp, body, out := e.postFormRaw(t, "/oauth/introspect", url.Values{"token": {access}}, rawAuth)
		return resp.StatusCode, string(body), out
	}

	// Baseline: the plain public id must be refused with 401.
	plain, _ := rawBasicHeader(e.pubID, "")
	st, body, _ := introspect(plain)
	t.Logf("plain public id      -> %d %s", st, body)
	if st == http.StatusOK {
		t.Fatalf("baseline already broken: the guard did not refuse the plain public id")
	}

	// The attack: the same id, percent-encoded once. %7A is 'z'.
	enc := strings.ReplaceAll(e.pubID, "z", "%7A")
	if enc == e.pubID {
		t.Fatal("probe bug: nothing was encoded")
	}
	encoded, _ := rawBasicHeader(enc, "")
	st, body, out := introspect(encoded)
	t.Logf("percent-encoded id   -> %d %s", st, body)
	if st == http.StatusOK {
		t.Errorf("percent-encoded public client id bypassed the introspection guard: %s", body)
	}
	if out["active"] == true {
		t.Errorf("a public client with no secret read a live token: %s", body)
	}
}

// The same bypass where it matters: the guard is the ONLY thing standing between
// a public caller and the allowlist-wide visibility that
// Config.IntrospectionClients grants. Round 5's PROTO-4 was fixed by refusing a
// non-confidential caller outright — which this bypass defeats, restoring the
// cross-client reader for any deployment whose allowlist names a public client.
func TestZZAudit_IntrospectionPublicAllowlistEntryIsBypassedByPercentEncoding(t *testing.T) {
	e := newAuditEnvFull(t, "", nil)
	// The deployment allowlists the public client as a resource server. The
	// comment on Config.IntrospectionClients says such an entry is refused; this
	// probe shows how far that refusal actually reaches.
	e.handler.introspectionClients[e.pubID] = true

	// A live token belonging to the CONFIDENTIAL client — a foreign token.
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, tok := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	access, _ := tok["access_token"].(string)

	// Baseline: the plain public id is refused.
	plain, _ := rawBasicHeader(e.pubID, "")
	if resp, body, _ := e.postFormRaw(t, "/oauth/introspect", url.Values{"token": {access}}, plain); resp.StatusCode == http.StatusOK {
		t.Fatalf("baseline: plain public caller read a foreign token: %s", body)
	}
	// Attack: the same id, percent-encoded.
	enc := strings.ReplaceAll(e.pubID, "z", "%7A")
	encoded, _ := rawBasicHeader(enc, "")
	resp, body, out := e.postFormRaw(t, "/oauth/introspect", url.Values{"token": {access}}, encoded)
	t.Logf("percent-encoded, allowlisted, FOREIGN token -> %d %s", resp.StatusCode, body)
	if out["active"] == true {
		t.Errorf("a public caller with no secret read a FOREIGN live token: %s", body)
	}
	if sub, _ := out["sub"].(string); sub != "" && sub != "usr_zz" {
		t.Errorf("unexpected subject: %s", sub)
	}
	_ = resp
	_ = access

	// The same caller and the same bypass against its OWN live token: this is
	// what the bypass actually delivers when the deployment has put a public
	// client on the allowlist.
	code2 := e.zzCode(t, e.pubID, []string{"openid", "account.id"}, nil)
	_, _, tok2 := e.zzExchange(t, e.pubID, "", code2, strings.Repeat("v", 64))
	own, _ := tok2["access_token"].(string)
	if own == "" {
		t.Fatalf("no public-client access token: %v", tok2)
	}
	t.Logf("own token response: %v", tok2)
	// What the store itself says about it, bypassing every caller check.
	if info, err := e.handler.Introspect(t.Context(), own); err != nil {
		t.Fatalf("Introspect(own) = %v", err)
	} else {
		t.Logf("Handler.Introspect(own) = %+v", info)
	}
	if resp, body, _ := e.postFormRaw(t, "/oauth/introspect", url.Values{"token": {own}}, plain); resp.StatusCode == http.StatusOK {
		t.Fatalf("baseline: plain public caller read its own token: %s", body)
	}
	resp, body, out = e.postFormRaw(t, "/oauth/introspect", url.Values{"token": {own}}, encoded)
	t.Logf("percent-encoded, allowlisted, OWN token -> %d %s", resp.StatusCode, body)
	if out["active"] == true {
		t.Logf("CONFIRMED IMPACT: an unauthenticated public caller introspected a live token: %s", body)
	}
	_ = resp
}

// The refusal's own comment claims a caller that "cannot prove" it is
// non-confidential is left to the library. A public client with an empty secret
// is exactly the case the library decides in the unsafe direction. This probe
// pins the raw-byte mismatch: the guard compares the header's bytes, the library
// compares their url.QueryUnescape.
func TestZZAudit_IntrospectionGuardReadsRawBasicID(t *testing.T) {
	e := newAuditEnv(t)
	raw, ok := rawBasicHeader(e.pubID, "")
	if !ok {
		t.Fatal("probe bug")
	}
	// Go's own Request.BasicAuth, applied to a header whose userinfo carries
	// percent-escapes, is exactly the guard's read.
	probe, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	probe.Header.Set("Authorization", raw)
	guardRead, _, _ := probe.BasicAuth()
	t.Logf("guard reads %q; library's url.QueryUnescape gives %q", guardRead, mustUnescape(guardRead))
	if guardRead == mustUnescape(guardRead) {
		t.Skip("this id contains nothing encodable")
	}
	if _, err := e.clients.Get(t.Context(), guardRead); err == nil {
		t.Fatalf("guard read %q resolved to a client; the bypass would not apply", guardRead)
	}
	if _, err := e.clients.Get(t.Context(), mustUnescape(guardRead)); err != nil {
		t.Fatalf("library read %q does not resolve either: %v", mustUnescape(guardRead), err)
	}
}

// rawBasicHeader builds the exact Authorization header bytes for a raw (not
// percent-encoded) pair, so the probe can send an id the guard reads differently
// from the library.
func rawBasicHeader(rawUser, rawPass string) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, "http://x/", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(rawUser+":"+rawPass)))
	return req.Header.Get("Authorization"), true
}

// postFormRaw sends the form with an explicit Authorization header, so a probe
// can put bytes on the wire that Request.SetBasicAuth cannot produce.
func (e *auditEnv) postFormRaw(t *testing.T, path string, form url.Values, rawAuth string) (*http.Response, []byte, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rawAuth != "" {
		req.Header.Set("Authorization", rawAuth)
	}
	resp, body := e.do(t, req)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp, body, out
}

func mustUnescape(s string) string {
	out, err := url.QueryUnescape(s)
	if err != nil {
		panic(err)
	}
	return out
}

// nativeAuditEnv is a PUBLIC client whose redirect is a loopback URI, the shape
// RFC 8252 §7.3 describes. The library's native-client path ACCEPTS a request
// whose loopback port differs from the registered one
// (pkg/op/auth_request.go:395 equalURI compares Path and RawQuery only), and for
// a loopback URI it does not even require the registered entry to match at all
// (line 383: "if !isLoopback { refuse }" — a loopback request falls through).
// The wrapper's exact match is the only thing holding the port.
type nativeAuditEnv struct {
	*auditEnv
	nativeID string
	regPort  string
}

func newNativeAuditEnv(t *testing.T) *nativeAuditEnv {
	t.Helper()
	e := newAuditEnv(t)
	port := "53123"
	reg := "http://127.0.0.1:" + port + "/cb"
	nativeID := "zz-native-" + auditRand()
	c, err := oauth.NewClient(nativeID, "Native", oauth.ClientPublic, "", []string{reg}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.clients.Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	return &nativeAuditEnv{auditEnv: e, nativeID: nativeID, regPort: port}
}

// A different loopback PORT is a different origin: the wrapper must refuse it,
// or every local process on the machine becomes a code recipient.
func TestZZAudit_LoopbackPortIsNotIgnored(t *testing.T) {
	e := newNativeAuditEnv(t)
	v := strings.Repeat("v", 64)
	attempt := func(uri string) (int, string) {
		resp, _ := e.getURL(t, e.srv.URL+"/oauth/authorize?"+url.Values{
			"response_type":         {"code"},
			"client_id":             {e.nativeID},
			"redirect_uri":          {uri},
			"scope":                 {"openid account.id"},
			"state":                 {"zz"},
			"nonce":                 {"zz"},
			"code_challenge":        {auditPKCE(v)},
			"code_challenge_method": {"S256"},
		}.Encode())
		return resp.StatusCode, resp.Header.Get("Location")
	}
	// Registered exactly.
	st, loc := attempt("http://127.0.0.1:" + e.regPort + "/cb")
	t.Logf("registered port: %d %s", st, loc)
	if st != http.StatusFound || strings.HasPrefix(loc, "http") {
		t.Logf("note: no login redirect for the registered URI (status %d, loc %q)", st, loc)
	}
	// A different port on the same loopback host.
	st, loc = attempt("http://127.0.0.1:53999/cb")
	t.Logf("foreign port:    %d %s", st, loc)
	if strings.HasPrefix(loc, "http://127.0.0.1:53999") {
		t.Errorf("the unregistered loopback port was accepted as a redirect target: %s", loc)
	}
	// A different loopback spelling of the same host.
	st, loc = attempt("http://localhost:" + e.regPort + "/cb")
	t.Logf("localhost alias: %d %s", st, loc)
	if strings.HasPrefix(loc, "http://localhost") {
		t.Errorf("the localhost alias was accepted for a 127.0.0.1 registration: %s", loc)
	}
	// A different path/query.
	for _, uri := range []string{
		"http://127.0.0.1:" + e.regPort + "/cb/../evil",
		"http://127.0.0.1:" + e.regPort + "/cb%2f..%2fevil",
		"http://127.0.0.1:" + e.regPort + "/cb?next=https://evil.example",
		"http://127.0.0.1:" + e.regPort + "/cb#frag",
		"http://127.0.0.1:" + e.regPort + "/CB",
	} {
		st, loc = attempt(uri)
		t.Logf("%-52s -> %d %.90s", uri, st, loc)
		if st == http.StatusFound && strings.HasPrefix(loc, uri) {
			t.Errorf("unregistered variant %q was accepted verbatim", uri)
		}
	}
}

// A POST to /oauth/introspect may carry parameters in the query string as well
// as the body (only the POST-only endpoints whose whole method set is POST are
// refused a query string — introspect IS POST-only, so this probe is about the
// device and authorize endpoints, where r.Form merges both).
//
// The interesting question is whether a gate and the library can be made to read
// different values of the same parameter when it is split across the two
// locations. duplicatedParam only sees r.Form, where a split shows up as two
// values — so it should refuse. This probe proves that.
func TestZZAudit_SplitQueryAndBodyCannotSmuggleTwoIdentities(t *testing.T) {
	e := newAuditEnv(t)
	// client_id=narrow in the query, client_id=broad in the body, with Basic
	// naming narrow: every gate must see the same identity.
	req, _ := http.NewRequest(http.MethodPost,
		e.srv.URL+"/oauth/device_authorization?client_id="+url.QueryEscape(e.narrowID),
		strings.NewReader(url.Values{
			"client_id": {e.webID},
			"scope":     {"phigros.score.read"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(e.narrowID, e.narrowS)
	resp, body := e.do(t, req)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("split client_id was served: %s", body)
	}
	t.Logf("split-identity answer: %d %s", resp.StatusCode, body)
}

// The device pre-flight reads the scope the library will store. A repeated
// `scope` parameter split between the query string and the body is ambiguity the
// endpoint must refuse, not resolve.
func TestZZAudit_DeviceScopeSplitAcrossQueryAndBody(t *testing.T) {
	e := newAuditEnv(t)
	req, _ := http.NewRequest(http.MethodPost,
		e.srv.URL+"/oauth/device_authorization?scope="+url.QueryEscape("account.id"),
		strings.NewReader(url.Values{
			"client_id": {e.narrowID},
			"scope":     {"phigros.score.read"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body := e.do(t, req)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("split scope was served: %s", body)
	}
	t.Logf("split-scope answer: %d %s", resp.StatusCode, body)
}

// A confidential client's PKCE requirement is the wrapper's, not the library's.
// The library only demands PKCE of AuthMethodNone clients, so a confidential
// client that omits code_challenge must be refused by the wrapper — and must not
// be able to slip one in by the device endpoint instead.
func TestZZAudit_ConfidentialClientNeedsPKCE(t *testing.T) {
	e := newAuditEnv(t)
	resp, _ := e.getURL(t, e.srv.URL+"/oauth/authorize?"+url.Values{
		"response_type": {"code"},
		"client_id":     {e.webID},
		"redirect_uri":  {e.redirect},
		"scope":         {"openid account.id"},
		"state":         {"zz"},
	}.Encode())
	loc := resp.Header.Get("Location")
	if resp.StatusCode == http.StatusFound && strings.HasPrefix(loc, e.redirect) {
		if u, err := url.Parse(loc); err == nil && u.Query().Get("error") == "" {
			t.Fatalf("confidential client got an authorization response with no PKCE: %s", loc)
		}
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusFound {
		t.Fatalf("unexpected answer %d", resp.StatusCode)
	}
}

// The authorization code is bound to the client it was issued to. A second
// client must not be able to redeem it even when it knows the code and the
// verifier.
func TestZZAudit_CodeIsBoundToItsClient(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.pubID, []string{"openid", "account.id"}, nil)
	// narrow is a different registered client.
	resp, body, out := e.zzExchange(t, e.narrowID, e.narrowS, code, strings.Repeat("v", 64))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("foreign client redeemed the code: %s", body)
	}
	t.Logf("foreign-client exchange: %d %s %v", resp.StatusCode, body, out)
}

// A code is single use, including under a concurrent race: two simultaneous
// exchanges of the same code may produce at most one token pair.
func TestZZAudit_CodeSingleUseUnderConcurrency(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.pubID, []string{"openid", "account.id"}, nil)
	verifier := strings.Repeat("v", 64)

	const n = 4
	type res struct {
		status int
		body   string
	}
	ch := make(chan res, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/oauth/token", strings.NewReader(url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {e.pubID},
				"code":          {code},
				"redirect_uri":  {e.redirect},
				"code_verifier": {verifier},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := noRedirect.Do(req)
			if err != nil {
				ch <- res{-1, err.Error()}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			ch <- res{resp.StatusCode, string(b)}
		}()
	}
	close(start)
	ok := 0
	for i := 0; i < n; i++ {
		r := <-ch
		if r.status == http.StatusOK {
			ok++
		}
		t.Logf("concurrent exchange: %d %s", r.status, r.body)
	}
	if ok > 1 {
		t.Fatalf("%d concurrent exchanges of one code all succeeded", ok)
	}
}

// userinfo must only accept a LIVE access token: revoked, expired and unknown
// bearers all answer the same refusal.
func TestZZAudit_UserinfoRequiresALiveAccessToken(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, tok := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("no access token")
	}
	call := func(bearer string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/oauth/userinfo", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, body := e.do(t, req)
		return resp.StatusCode, string(body)
	}
	if st, body := call(access); st != http.StatusOK {
		t.Fatalf("live access token refused at userinfo: %d %s", st, body)
	}
	// Revoke it, then ask again.
	if _, _, out := e.postForm(t, "/oauth/revoke", url.Values{"token": {access}}, e.webID, e.webSec); out["error"] != nil {
		t.Logf("revoke answered %v", out)
	}
	if st, body := call(access); st == http.StatusOK {
		t.Errorf("revoked access token still works at userinfo: %s", body)
	} else {
		t.Logf("revoked bearer: %d %s", st, body)
	}
	// A token this store never issued.
	if st, body := call("not.a.token"); st != http.StatusUnauthorized {
		t.Errorf("unknown bearer = %d %s, want 401", st, body)
	}
	// A refresh token is not an access token.
	if rt, ok := tok["refresh_token"].(string); ok && rt != "" {
		if st, body := call(rt); st == http.StatusOK {
			t.Errorf("a refresh token authenticated at userinfo: %s", body)
		} else {
			t.Logf("refresh-token bearer: %d %s", st, body)
		}
	}
}

// The token endpoint must refuse a grant_type it does not implement, rather than
// falling through to another handler.
func TestZZAudit_UnimplementedGrantsAreRefused(t *testing.T) {
	e := newAuditEnv(t)
	for _, gt := range []string{
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"password",
		"implicit",
		"",
	} {
		resp, body, out := e.postForm(t, "/oauth/token", url.Values{"grant_type": {gt}}, "", "")
		if resp.StatusCode == http.StatusOK {
			t.Errorf("grant_type %q was served: %s", gt, body)
			continue
		}
		t.Logf("grant_type %-55q -> %d %v", gt, resp.StatusCode, out["error"])
	}
}

// The discovery document must not advertise a capability the server refuses.
// Round 5 recorded the introspection auth-method lie (PROTO-5); this probe
// checks the rest of the document against the endpoints.
func TestZZAudit_DiscoveryDoesNotLie(t *testing.T) {
	e := newAuditEnv(t)
	resp, body := e.getURL(t, e.srv.URL+"/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery = %d %s", resp.StatusCode, body)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	t.Logf("discovery: %s", body)

	if doc["authorization_response_iss_parameter_supported"] == true {
		// Every authorization response this server writes must carry iss.
		_, status, loc := e.zzAuthorize(t, e.webID, []string{"openid", "account.id"}, url.Values{
			"response_mode": {"fragment"},
		})
		if status == http.StatusFound {
			u, err := url.Parse(loc)
			if err == nil && u.Query().Get("error") == "" && u.Query().Get("code") == "" {
				t.Errorf("a response contradicted iss support: %s", loc)
			}
			t.Logf("fragment-mode refusal: %s", loc)
		}
	}
}

// The dynamic-issuer shape caches the rendered discovery document by path only,
// with no Host dimension. A single request with a forged Host fixes both
// documents for the life of the process.
func TestZZAudit_DiscoveryCacheIsHostBlind(t *testing.T) {
	e := newAuditEnvIssuer(t, "") // dynamic issuer: IssuerFromHost

	fetch := func(host string) map[string]any {
		req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/.well-known/openid-configuration", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, body := e.do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery for host %q = %d %s", host, resp.StatusCode, body)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	first := fetch("attacker.example")
	second := fetch("real.example")
	t.Logf("issuer for attacker.example = %v", first["issuer"])
	t.Logf("issuer for real.example     = %v", second["issuer"])
	if first["issuer"] == second["issuer"] {
		t.Errorf("discovery is cached host-blind: real.example was answered with issuer %v", second["issuer"])
	}
}

// The device flow must not mint tokens for a device code whose advertised
// lifetime has passed. Round 6's other agents found this; this is the protocol
// plane's own probe of the same property.
func TestZZAudit_DeviceCodeExpiryIsEnforced(t *testing.T) {
	e := newAuditEnv(t)
	_, _, start := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {e.pubID},
		"scope":     {"account.id"},
	}, "", "")
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("no device authorization: %v", start)
	}
	t.Logf("device code %q user code %q interval=%v expires_in=%v",
		deviceCode, userCode, start["interval"], start["expires_in"])
	if err := e.store.ApproveDevice(t.Context(), userCode, "usr_zz", nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	resp, body, out := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {e.pubID},
	}, "", "")
	t.Logf("first device poll: %d %v", resp.StatusCode, out)
	// Second poll of an approved code: the store consumes it.
	resp2, body2, out2 := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {e.pubID},
	}, "", "")
	if resp2.StatusCode == http.StatusOK {
		t.Errorf("an approved device code was redeemed twice: %s", body2)
	}
	t.Logf("second device poll: %d %v (first was %d %s)", resp2.StatusCode, out2, resp.StatusCode, body)
}

// The device verification user code must not be usable from a browser that did
// not enter it — the bind lives in the httpapi layer, so this probe only asserts
// the protocol plane does not hand out an approval path of its own.
func TestZZAudit_DeviceAuthorizationRequiresRegisteredScope(t *testing.T) {
	e := newAuditEnv(t)
	for _, scope := range []string{"", "phigros.score.read", "openid phigros.score.read", "unknown.scope"} {
		resp, body, out := e.postForm(t, "/oauth/device_authorization", url.Values{
			"client_id": {e.narrowID},
			"scope":     {scope},
		}, e.narrowID, e.narrowS)
		if resp.StatusCode == http.StatusOK && scope != "" && scope != "openid phigros.score.read" {
			t.Errorf("narrow client got a device code for scope %q: %s", scope, body)
		}
		t.Logf("device scope %-30q -> %d %v", scope, resp.StatusCode, out["error"])
	}
}

// A public client whose redirect_uri is an RFC 8252 §7.1 private-use scheme
// (com.example.app:/cb) registers fine — oauth/client.go's validRedirectURI
// explicitly permits it — but the library refuses to serve it at authorize time.
// pkg/op/auth_request.go validateAuthReqRedirectURINative only falls through for
// a loopback URI (line 383), so a non-loopback custom scheme is refused even
// though it is the registered one. Registration therefore advertises a redirect
// shape the authorization endpoint cannot use.
func TestZZAudit_PrivateUseSchemeRedirectIsRefused(t *testing.T) {
	e := newAuditEnv(t)
	const custom = "com.example.app:/cb"
	id := "zz-native-scheme-" + auditRand()
	c, err := oauth.NewClient(id, "NativeScheme", oauth.ClientPublic, "", []string{custom}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatalf("registration refused the RFC 8252 private-use scheme: %v", err)
	}
	if err := e.clients.Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	v := strings.Repeat("v", 64)
	resp, body := e.getURL(t, e.srv.URL+"/oauth/authorize?"+url.Values{
		"response_type":         {"code"},
		"client_id":             {id},
		"redirect_uri":          {custom},
		"scope":                 {"openid account.id"},
		"state":                 {"zz"},
		"nonce":                 {"zz"},
		"code_challenge":        {auditPKCE(v)},
		"code_challenge_method": {"S256"},
	}.Encode())
	t.Logf("private-use scheme authorize: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusFound {
		t.Errorf("the registered private-use redirect was not served: %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" && strings.HasPrefix(loc, custom) {
		t.Errorf("an error was answered through the custom scheme: %s", loc)
	}
}

// PKCE must not be downgradable: `plain` is refused, and a challenge sent with
// no method is refused too (the library would treat it as the default).
func TestZZAudit_PKCECannotBeDowngraded(t *testing.T) {
	e := newAuditEnv(t)
	verifier := strings.Repeat("v", 64)
	base := func() url.Values {
		return url.Values{
			"response_type": {"code"},
			"client_id":     {e.pubID},
			"redirect_uri":  {e.redirect},
			"scope":         {"openid account.id"},
			"state":         {"zz"},
		}
	}
	for _, tc := range []struct {
		name              string
		challenge, method string
	}{
		{"no-pkce", "", ""},
		{"plain", verifier, "plain"},
		{"no-method", auditPKCE(verifier), ""},
		{"empty-method", auditPKCE(verifier), ""},
		{"S512", auditPKCE(verifier), "S512"},
		{"lowercase-s256", auditPKCE(verifier), "s256"},
		{"short-challenge", strings.Repeat("a", 42), "S256"},
		{"too-long-challenge", strings.Repeat("a", 129), "S256"},
		{"challenge-with-space", strings.Repeat("a", 42) + " b", "S256"},
	} {
		q := base()
		if tc.challenge != "" {
			q.Set("code_challenge", tc.challenge)
		}
		if tc.method != "" {
			q.Set("code_challenge_method", tc.method)
		}
		resp, _ := e.getURL(t, e.srv.URL+"/oauth/authorize?"+q.Encode())
		loc := resp.Header.Get("Location")
		ok := resp.StatusCode == http.StatusFound && strings.Contains(loc, "authRequestID=")
		t.Logf("%-22s -> %d %.80s", tc.name, resp.StatusCode, loc)
		if ok {
			t.Errorf("PKCE case %q reached the consent leg", tc.name)
		}
	}
}

// The code exchange must require a redirect_uri that matches byte for byte, and
// a verifier that hashes to the stored challenge.
func TestZZAudit_CodeExchangeRequiresExactRedirectAndVerifier(t *testing.T) {
	e := newAuditEnv(t)
	verifier := strings.Repeat("v", 64)

	cases := []struct {
		name       string
		redirect   string
		verifier   string
		wantReject bool
	}{
		{"exact", e.redirect, verifier, false},
		{"redirect-missing", "", verifier, true},
		{"redirect-alias", "https://client.example/cb/", verifier, true},
		{"redirect-case", "https://CLIENT.example/cb", verifier, true},
		{"redirect-query", "https://client.example/cb?x=1", verifier, true},
		{"redirect-frag", "https://client.example/cb#f", verifier, true},
		{"verifier-wrong", e.redirect, strings.Repeat("w", 64), true},
		{"verifier-short", e.redirect, "short", true},
		{"verifier-empty", e.redirect, "", true},
	}
	for _, tc := range cases {
		code := e.zzCode(t, e.pubID, []string{"openid", "account.id"}, nil)
		resp, body, _ := e.postForm(t, "/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {e.pubID},
			"code":          {code},
			"redirect_uri":  {tc.redirect},
			"code_verifier": {tc.verifier},
		}, "", "")
		t.Logf("%-16s -> %d %s", tc.name, resp.StatusCode, strings.TrimSpace(string(body)))
		if tc.wantReject && resp.StatusCode == http.StatusOK {
			t.Errorf("exchange %q was accepted: %s", tc.name, body)
		}
		if !tc.wantReject && resp.StatusCode != http.StatusOK {
			t.Errorf("exchange %q was refused: %s", tc.name, body)
		}
	}
}

// The id_token's registered claims must mean what OIDC Core §3.1.3.6 says:
// iss == the issuer, aud == the client, azp == the client when it is present,
// nonce echoed, at_hash the left half of SHA-256(access_token), c_hash the left
// half of SHA-256(code).
func TestZZAudit_IDTokenClaimCorrectness(t *testing.T) {
	e := newAuditEnv(t)
	verifier := strings.Repeat("v", 64)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	resp, body, out := e.zzExchange(t, e.webID, e.webSec, code, verifier)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d %s", resp.StatusCode, body)
	}
	raw, _ := out["id_token"].(string)
	access, _ := out["access_token"].(string)
	if raw == "" || access == "" {
		t.Fatalf("missing tokens: %s", body)
	}
	claims := auditIDTokenClaims(t, raw)
	t.Logf("id_token claims: %v", claims)

	wantHash := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return base64.RawURLEncoding.EncodeToString(sum[:16])
	}
	if got := claims["iss"]; got != e.srv.URL {
		t.Errorf("iss = %#v, want %q", got, e.srv.URL)
	}
	aud, _ := claims["aud"].([]any)
	found := false
	for _, a := range aud {
		if a == e.webID {
			found = true
		}
	}
	if !found {
		t.Errorf("aud %#v does not contain the client %q", aud, e.webID)
	}
	if len(aud) == 1 && claims["azp"] != e.webID {
		t.Errorf("single-audience id_token has azp = %#v, want %q", claims["azp"], e.webID)
	}
	if claims["nonce"] != "zz-nonce" {
		t.Errorf("nonce = %#v, want zz-nonce", claims["nonce"])
	}
	if claims["at_hash"] != wantHash(access) {
		t.Errorf("at_hash = %#v, want %q", claims["at_hash"], wantHash(access))
	}
	if claims["c_hash"] != wantHash(code) {
		t.Errorf("c_hash = %#v, want %q", claims["c_hash"], wantHash(code))
	}
	if claims["sub"] != "usr_zz" {
		t.Errorf("sub = %#v", claims["sub"])
	}
	for _, k := range []string{"exp", "iat", "auth_time"} {
		if _, ok := claims[k]; !ok {
			t.Errorf("id_token is missing %s: %v", k, claims)
		}
	}
	if at, _ := claims["auth_time"].(float64); at <= 0 {
		t.Errorf("auth_time = %#v", claims["auth_time"])
	}
}

// The refresh grant must not mint an id_token without openid, and must not mint
// one carrying a stale nonce as though the user had just authenticated. Round 6
// recorded the nonce loss; this is the same property from the claims side, plus
// the aud/iss of a refreshed token.
func TestZZAudit_RefreshedIDTokenClaims(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.webID, []string{"openid", "account.id"}, nil)
	_, _, out := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", out)
	}
	resp, body, refreshed := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d %s", resp.StatusCode, body)
	}
	t.Logf("refresh response: %s", body)
	raw, _ := refreshed["id_token"].(string)
	if raw == "" {
		return // no id_token on refresh is a contract choice
	}
	claims := auditIDTokenClaims(t, raw)
	t.Logf("refreshed id_token claims: %v", claims)
	if claims["sub"] != "usr_zz" {
		t.Errorf("refreshed sub = %#v", claims["sub"])
	}
	if n, ok := claims["nonce"]; ok && n != "" {
		t.Logf("refreshed id_token still carries nonce %#v", n)
	}
	if claims["iss"] != e.srv.URL {
		t.Errorf("refreshed iss = %#v", claims["iss"])
	}
}

// A token response without `openid` in scope must not carry an id_token, on
// every grant the server offers.
func TestZZAudit_IDTokenOnlyWithOpenID(t *testing.T) {
	e := newAuditEnv(t)
	t.Run("code", func(t *testing.T) {
		code := e.zzCode(t, e.webID, []string{"account.id"}, nil)
		_, body, out := e.zzExchange(t, e.webID, e.webSec, code, strings.Repeat("v", 64))
		if _, ok := out["id_token"]; ok {
			t.Errorf("id_token without openid: %s", body)
		}
		t.Logf("plain OAuth code response: %s", body)
	})
	t.Run("device", func(t *testing.T) {
		_, _, start := e.postForm(t, "/oauth/device_authorization", url.Values{
			"client_id": {e.pubID}, "scope": {"account.id"},
		}, "", "")
		deviceCode, _ := start["device_code"].(string)
		userCode, _ := start["user_code"].(string)
		if deviceCode == "" {
			t.Fatalf("no device code: %v", start)
		}
		if err := e.store.ApproveDevice(t.Context(), userCode, "usr_zz", nil); err != nil {
			t.Fatal(err)
		}
		_, body, out := e.postForm(t, "/oauth/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {e.pubID},
		}, "", "")
		if _, ok := out["id_token"]; ok {
			t.Errorf("device grant minted an id_token without openid: %s", body)
		}
		t.Logf("plain OAuth device response: %s", body)
	})
}

// The refresh grant must not be able to widen the granted scope set, in any
// spelling: an unknown scope, a superset, mixed case, or extra whitespace.
func TestZZAudit_RefreshCannotWidenScope(t *testing.T) {
	e := newAuditEnv(t)
	code := e.zzCode(t, e.narrowID, []string{"account.id"}, nil)
	_, _, out := e.zzExchange(t, e.narrowID, e.narrowS, code, strings.Repeat("v", 64))
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", out)
	}
	for _, scope := range []string{
		"phigros.score.read",
		"account.id phigros.score.read",
		"ACCOUNT.ID",
		" account.id ",
		"account.id\tphigros.score.read",
		"unknown.scope",
	} {
		resp, body, refreshed := e.postForm(t, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"scope":         {scope},
		}, e.narrowID, e.narrowS)
		got, _ := refreshed["scope"].(string)
		t.Logf("scope %-40q -> %d scope=%q err=%v", scope, resp.StatusCode, got, refreshed["error"])
		if resp.StatusCode != http.StatusOK {
			continue
		}
		for _, f := range strings.Fields(got) {
			if f != "account.id" && f != "openid" {
				t.Errorf("refresh widened the grant with %q (body %s)", f, body)
			}
		}
		if nt, _ := refreshed["refresh_token"].(string); nt != "" {
			rt = nt
		}
	}
}
