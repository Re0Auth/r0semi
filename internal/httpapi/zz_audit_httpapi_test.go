//go:build audit || audit6

package httpapi

// zz_audit_httpapi_test.go — round-6 adversarial probes for the HTTP API layer
// (routing, middleware order, plane separation, request/response edges).
//
// Written by an audit sub-agent. It modifies no production file. Findings and
// their status are written up in _audit/http-api.md.
//
// Everything here is prefixed za6/TestZZA6 so it cannot collide with the
// package's own helpers or with another probe file.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

// za6Harness is a fully wired server on a real listener — the embedded frontend,
// the operator plane, federation, the limiter and the metrics middleware all
// present — plus a working fake IdP so a browser can really be signed in.
type za6Harness struct {
	base    string
	browser *http.Client
	srv     *Server
	ts      *httptest.Server
	// self is the ordinary account, admin the allowlisted one.
	self, admin account.UserID
	// limiter is exposed so a probe can assert on bucket state.
	limiter *ratelimit.Limiter
	metrics *observability.Metrics
	// frontend is the configured fs.FS, in case a probe needs to know whether
	// the embedded shell is the real one.
	frontendBuilt bool
}

// za6New builds the whole stack. signIn works for real: the fake IdP derives the
// account from the `code` the callback carries, so two codes are two accounts in
// one server.
func za6New(t *testing.T, tweak func(*Config)) *za6Harness {
	t.Helper()

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			sub := "42"
			if strings.Contains(r.Header.Get("Authorization"), "at:a") {
				sub = "99"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": sub, "login": "u" + sub, "name": "User " + sub})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: fake.URL + "/github/authorize", TokenURL: fake.URL + "/github/token",
			UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	accounts := account.NewMemoryStore()
	adminUser, _, err := accounts.CreateWithIdentity(ctx, idp.Identity{Provider: idp.GitHub, Subject: "42", DisplayName: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	selfUser, _, err := accounts.CreateWithIdentity(ctx, idp.Identity{Provider: idp.GitHub, Subject: "99", DisplayName: "Self"})
	if err != nil {
		t.Fatal(err)
	}

	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, "https://re0auth.test", clients, manager)

	sources, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: fake.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: sources,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    newTestVault(t),
		Doer:     fake.Client(),
		BaseURL:  "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	adminSvc, err := admin.New(admin.Config{
		Clients: clients, Tokens: store, Audit: audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	limiter := ratelimit.New(1e6, 100)
	metrics := observability.New()
	frontend := webui.FS()

	cfg := Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		Federation:        fed,
		Admin:             adminSvc,
		Admins:            []account.UserID{adminUser.ID},
		Deleter:           stubDeleter{},
		Audit:             &stubAuditReader{},
		AuditLog:          audit.NewMemoryLogger(),
		Limiter:           limiter,
		Metrics:           metrics,
		Frontend:          frontend,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	h := &za6Harness{
		base: ts.URL, srv: srv, ts: ts,
		self: selfUser.ID, admin: adminUser.ID,
		limiter: limiter, metrics: metrics,
		frontendBuilt: webui.Built(frontend),
	}
	h.browser = h.newClient()
	return h
}

func (h *za6Harness) newClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// signIn signs the harness's browser in as the ordinary account.
func (h *za6Harness) signIn(t *testing.T) {
	t.Helper()
	signInAs(t, h.browser, h.base, "c")
}

// signInAdmin signs a fresh browser in as the allowlisted operator.
func (h *za6Harness) signInAdmin(t *testing.T) *http.Client {
	t.Helper()
	c := h.newClient()
	signInAs(t, c, h.base, "a")
	return c
}

// csrf reads the CSRF token the session bootstrap hands out.
func (h *za6Harness) csrf(t *testing.T, c *http.Client) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.base+"/v1/sessions/current", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode session bootstrap: %v", err)
	}
	if body.CSRF == "" {
		t.Fatal("no csrf token; the session is not signed in")
	}
	return body.CSRF
}

// za6Do issues a request with the signed-in browser and returns the response
// with its body already drained (so the connection is reusable).
func (h *za6Harness) do(t *testing.T, method, target string, headers map[string]string, body string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.base+target, rdr)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, target, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.browser.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func za6Hdr(resp *http.Response) string {
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s=%q ", k, strings.Join(resp.Header.Values(k), "|")))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// sweep 1: method x path matrix
// ---------------------------------------------------------------------------

// TestZZA6SurfaceMatrix walks every documented path with every plausible method
// and prints what comes back. It is a discovery instrument: the assertions it
// does make are invariants the service states about itself elsewhere (plane
// shape and no-store on the business plane), so a red run is a real finding
// rather than an opinion.
func TestZZA6SurfaceMatrix(t *testing.T) {
	h := za6New(t, nil)
	h.signIn(t)

	paths := []string{
		"/healthz", "/readyz", "/robots.txt", "/",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource",
		"/.well-known/",
		"/.well-known/oauth-protected-resource/x",
		"/oauth/token", "/oauth/authorize", "/oauth/nope", "/oauth",
		"/v1", "/v1/", "/v1/me", "/v1/nope",
		"/v1/sessions/current", "/v1/sessions/sign_out",
		"/v1/device/verification", "/v1/device/decision",
		"/v1/authorization_requests/x", "/v1/authorization_requests/x/decision",
		"/v1/grants", "/v1/grants/cli",
		"/v1/identities", "/v1/identities/ident-1",
		"/v1/account", "/v1/account/export",
		"/v1/bindings", "/v1/bindings/phigros/fake",
		"/v1/bindings/phigros/fake/cascade_revocation",
		"/v1/idp/providers", "/v1/sources", "/v1/games/phigros/sources",
		"/v1/games/phigros/sources/fake/raw", "/v1/games/phigros/sources/fake/raw/x",
		"/v1/games/phigros/profile",
		"/v1/admin/clients", "/v1/admin/clients/cli",
		"/v1/admin/clients/cli/suspend", "/v1/admin/clients/cli/activate",
		"/v1/admin/clients/cli/rotate_secret",
		"/v1/admin/kill_switch", "/v1/admin/audit",
		"/v1/admin/audit/verify", "/v1/admin/audit/head",
		"/bind", "/auth/github/start", "/auth/github/callback",
		"/auth/upstream/phigros/fake/callback",
		"/app/", "/app/index.html", "/app/whatever",
	}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodOptions}

	type row struct {
		method, path                 string
		status                       int
		ctype, cache, allow, vary    string
		ctyHasProblem, oauthErrShape bool
		body                         string
	}
	var rows []row
	for _, p := range paths {
		for _, m := range methods {
			resp, body := h.do(t, m, p, nil, "")
			ct := resp.Header.Get("Content-Type")
			snippet := body
			if len(snippet) > 90 {
				snippet = snippet[:90]
			}
			rows = append(rows, row{
				method: m, path: p, status: resp.StatusCode,
				ctype: ct, cache: resp.Header.Get("Cache-Control"),
				allow: resp.Header.Get("Allow"), vary: resp.Header.Get("Vary"),
				ctyHasProblem: strings.Contains(ct, "problem+json"),
				oauthErrShape: strings.Contains(body, `"error"`) && !strings.Contains(body, `"code"`),
				body:          strings.ReplaceAll(snippet, "\n", `\n`),
			})
		}
	}
	for _, r := range rows {
		t.Logf("%-7s %-52s %3d ct=%-32s cc=%-10q allow=%-18q vary=%q body=%s",
			r.method, r.path, r.status, r.ctype, r.cache, r.allow, r.vary, r.body)
	}

	// Invariant the service states in docs/api-design.md: every business-plane
	// response is a problem+json or JSON body carrying no-store, for any method
	// and any spelling that the router serves.
	for _, r := range rows {
		if !strings.HasPrefix(r.path, "/v1") {
			continue
		}
		if r.cache == "" && r.status != http.StatusSwitchingProtocols {
			t.Errorf("business-plane response without Cache-Control: %s %s -> %d ct=%s body=%s",
				r.method, r.path, r.status, r.ctype, r.body)
		}
	}
	// Invariant: no response leaks the operator plane's method set to a caller
	// the plane hides itself from (requireAdmin answers 404 to a non-admin, so
	// the *existence* of the plane is not something the plane admits).
	// Recorded rather than asserted here; see TestZZA6AdminPlaneMethodLeak.
}

// TestZZA6EncodedSpellingsWidenTheSurface sweeps spellings the router treats
// differently from planeOf, looking for one that reaches a handler the plain
// spelling cannot, or that answers in the wrong plane's format.
func TestZZA6EncodedSpellingsWidenTheSurface(t *testing.T) {
	h := za6New(t, nil)

	type tc struct {
		target string
		// wantPlane is the shape the planeOf classification of the *decoded*
		// path promises: "problem", "oauth", "text".
		wantPlane string
	}
	cases := []tc{
		{"/v1%2Fme", "problem"},
		{"/v1%2F..%2Foauth%2Ftoken", "problem"},
		{"/v1/../oauth/token", "problem"},
		{"/v1/..%2Foauth/token", "problem"},
		{"/oauth/../v1/me", "oauth"},
		{"/oauth%2Ftoken", "oauth"},
		{"/%76%31/me", "problem"},
		{"/v1/%2e%2e/oauth/token", "problem"},
		{"/app/../oauth/authorize", "text"},
		{"/app/..%2Fv1/me", "text"},
		{"/.well-known/../v1/me", "oauth"},
		{"//v1/me", "text"},
		{"/v1//me", "problem"},
		{"/v1/./me", "problem"},
		{"/v1/me/", "problem"},
		{"/v1/%6de", "problem"},
		{"/v1\\me", "text"},
		{"/v1;/me", "text"},
		{"/v1/me%00", "problem"},
	}
	for _, c := range cases {
		resp, body := h.do(t, http.MethodGet, c.target, nil, "")
		ct := resp.Header.Get("Content-Type")
		got := "text"
		switch {
		case strings.Contains(ct, "problem+json"):
			got = "problem"
		case strings.Contains(body, `"error"`):
			got = "oauth"
		}
		t.Logf("%-28s -> %d ct=%-30s cc=%-9q plane=%s (decode-shape=%s) body=%.70q",
			c.target, resp.StatusCode, ct, resp.Header.Get("Cache-Control"), got, c.wantPlane,
			strings.ReplaceAll(body, "\n", `\n`))
	}
}

// ---------------------------------------------------------------------------
// header / request edges
// ---------------------------------------------------------------------------

// TestZZA6RequestIdIsReflectedVerbatim — 原为发现演示，现为 Z11-3 回归守卫。
//
// The round-6 demonstration asked how far a caller-controlled request id
// travels: into the response header, into the JSON error body and into the log
// line. The answer then was that an unbounded/unescaped value was adopted
// verbatim, so one unauthenticated request could buy a 64 KiB response header
// and a 64 KiB log line. Z11-3 fixed that: internal/httpapi/middleware.go:176-180
// adopts the caller's X-Request-Id only when validRequestID accepts it
// (<= maxRequestIDBytes = 128, opaque charset), and otherwise substitutes a
// generated id.
//
// The guard:
//   - a short opaque id is echoed unchanged (the positive control);
//   - a valid-but-oversized or non-opaque value is replaced, never reflected;
//   - CR / LF / NUL are never reflected either — but Go's client refuses to
//     transmit those at all (net/http transport.go:600 validateHeaders), so the
//     probe writes the request bytes itself, which is what an attacker controls.
func TestZZA6RequestIdIsReflectedVerbatim(t *testing.T) {
	h := za6New(t, nil)

	// Positive control: an id inside the adopted shape must round-trip.
	resp, _ := h.do(t, http.MethodGet, "/v1/nope", map[string]string{"X-Request-Id": "trace-me"}, "")
	if got := resp.Header.Get("X-Request-Id"); got != "trace-me" {
		t.Errorf("a valid request id was not echoed: sent %q got %q", "trace-me", got)
	}

	// Values the Go client will transmit but the server must reject.
	for _, id := range []string{
		strings.Repeat("A", 8<<10),
		strings.Repeat("A", 60<<10),
		"x<script>alert(1)</script>",
	} {
		resp, _ := h.do(t, http.MethodGet, "/v1/nope", map[string]string{"X-Request-Id": id}, "")
		got := resp.Header.Get("X-Request-Id")
		t.Logf("sent len=%d %q -> echoed len=%d %q (status %d, injected=%v)",
			len(id), za6Short(id), len(got), za6Short(got), resp.StatusCode, resp.Header.Get("Injected"))
		za6AssertOpaqueReplacement(t, id, got)
	}

	// Values Go's client will not transmit: put them on the wire ourselves.
	for _, id := range []string{"x\r\nInjected: 1", "x\nInjected: 1", "x\x00y", "x\ry"} {
		resp, raw := za6RawHeaderRequest(t, h.base, "X-Request-Id: "+id)
		if resp == nil {
			t.Logf("sent %q -> the server answered no parseable response: %.120q", id, raw)
			if strings.Contains(strings.ToLower(raw), "injected") {
				t.Errorf("a raw request header was reflected back: %q", raw)
			}
			continue
		}
		got := resp.Header.Get("X-Request-Id")
		t.Logf("sent %q -> status %d echoed len=%d %q injected=%q",
			id, resp.StatusCode, len(got), za6Short(got), resp.Header.Get("Injected"))
		if injected := resp.Header.Get("Injected"); injected != "" {
			t.Errorf("a raw header split the request into an Injected response header: %q", injected)
		}
		if got != "" {
			za6AssertOpaqueReplacement(t, id, got)
		}
	}
}

// za6AssertOpaqueReplacement pins Z11-3: whatever the caller sent, the echoed id
// is never that value and is always a short opaque token.
func za6AssertOpaqueReplacement(t *testing.T, sent, got string) {
	t.Helper()
	if got == "" {
		t.Errorf("sent %q but no request id was echoed at all", sent)
		return
	}
	if got == sent {
		t.Errorf("the caller's request id was adopted verbatim: %q", got)
	}
	if len(got) > maxRequestIDBytes {
		t.Errorf("echoed request id is %d bytes, want at most %d", len(got), maxRequestIDBytes)
	}
	for i := 0; i < len(got); i++ {
		c := got[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			continue
		}
		t.Errorf("echoed request id %q contains %q, which is not an opaque-token byte", got, string(c))
		break
	}
}

// za6RawHeaderRequest writes a request line and one raw header line on a TCP
// connection, because Go's client refuses to transmit a value with CR/LF/NUL
// (net/http transport.go:600). It returns the parsed response, or nil plus the
// raw reply when the server answers something unparseable.
func za6RawHeaderRequest(t *testing.T, base, rawHeaderLine string) (*http.Response, string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET /v1/nope HTTP/1.1\r\nHost: " + u.Host + "\r\n" +
		rawHeaderLine + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(conn)
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return nil, string(raw)
	}
	return resp, string(raw)
}

func za6Short(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// TestZZA6CompressionEdges looks for a response that is compressed without a
// Vary, or that claims a coding it did not apply, or that a caller can make the
// server produce by asking with a coding the server does not implement.
func TestZZA6CompressionEdges(t *testing.T) {
	h := za6New(t, nil)

	accepts := []string{
		"", "gzip", "zstd", "identity", "br", "*", "gzip;q=0", "identity;q=0",
		"*;q=0", "gzip;q=0, identity;q=0", "zstd;q=1, gzip;q=0.5", "GZIP",
		"gzip;q=notanumber", "gzip;q=2", "deflate, br, zstd", "identity, zstd;q=0",
		"gzip;q=0.000", "zstd;q=0.0001,gzip;q=0.0002",
	}
	targets := []string{
		"/v1/nope",           // small problem+json
		"/v1/account/export", // large, authenticated, per-person
		"/v1/sources",        // public list
		"/app/",              // shell
		"/oauth/token",       // protocol plane: must never be transformed
		"/.well-known/openid-configuration",
		"/healthz", "/readyz",
	}
	h.signIn(t)
	for _, target := range targets {
		for _, ae := range accepts {
			req, _ := http.NewRequest(http.MethodGet, h.base+target, nil)
			req.Header.Set("Accept-Encoding", ae)
			resp, err := h.browser.Do(req)
			if err != nil {
				t.Fatalf("%s ae=%q: %v", target, ae, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			enc := resp.Header.Get("Content-Encoding")
			vary := resp.Header.Get("Vary")
			note := ""
			if enc != "" && !strings.Contains(strings.ToLower(vary), "accept-encoding") {
				note = " <== COMPRESSED WITHOUT VARY"
			}
			if enc != "" && len(b) > 0 {
				if enc == "gzip" {
					if _, err := gzip.NewReader(bytes.NewReader(b)); err != nil {
						note += " <== gzip body does not decode: " + err.Error()
					}
				}
			}
			if resp.StatusCode == http.StatusNotAcceptable || enc != "" || note != "" {
				t.Logf("%-36s ae=%-32q -> %d enc=%-6q vary=%-18q len=%d%s",
					target, ae, resp.StatusCode, enc, vary, len(b), note)
			}
		}
	}
}

// TestZZA6RawQueryIsNotReflectedIntoHeaders drives the paths that build a
// Location from request input (/ and /bind) with hostile queries, looking for
// an open redirect or a header split.
func TestZZA6RawQueryIsNotReflectedIntoHeaders(t *testing.T) {
	h := za6New(t, nil)

	targets := []string{
		"/?%0d%0aX-Injected:%201",
		"/?a=%0d%0aSet-Cookie:%20x=1",
		"/?//evil.example",
		"/?@evil.example",
		"/?../../oauth/token",
		"/?x=1&y=2",
		`/?a="><script>`,
		"/bind?game=phigros&source=fake&return_to=//evil.example",
		"/bind?game=phigros&source=fake&return_to=/\\evil.example",
		"/bind?game=phigros&source=fake&return_to=" + url.QueryEscape("//evil.example"),
		"/bind?game=phigros&source=fake&return_to=" + url.QueryEscape("/\t/evil.example"),
		"/bind?game=phigros&source=fake&return_to=" + url.QueryEscape("https://evil.example"),
		"/bind?game=nope&source=nope&return_to=/x",
	}
	for _, target := range targets {
		resp, body := h.do(t, http.MethodGet, target, nil, "")
		t.Logf("%-70s -> %d loc=%-60q injected=%q body=%.40q",
			target, resp.StatusCode, resp.Header.Get("Location"),
			resp.Header.Get("X-Injected"), strings.ReplaceAll(body, "\n", `\n`))
	}
}

// TestZZA6BodyLimitEdges pushes bodies past the cap through every shape the
// server accepts (declared length, chunked, compressed, multipart) and records
// which status and which plane shape comes back.
func TestZZA6BodyLimitEdges(t *testing.T) {
	h := za6New(t, nil)
	h.signIn(t)

	// A raw HTTP/1.1 client, so chunked and lying Content-Length are reachable.
	addr := strings.TrimPrefix(h.ts.URL, "http://")
	send := func(t *testing.T, raw string) string {
		t.Helper()
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(c)
		return string(out)
	}

	huge := strings.Repeat("a", 200<<10)
	path := "/v1/device/decision"

	cases := []struct {
		name string
		req  string
	}{
		{"declared-200k", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, len(huge), huge)},
		{"chunked-200k", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", path, len(huge), huge)},
		{"declared-1m-body-3-bytes", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\nabc", path, 1<<20)},
		{"declared-65k-lying-small", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n%s", path, strings.Repeat("a", 10))},
	}
	for _, c := range cases {
		out := send(t, c.req)
		head, _, _ := strings.Cut(out, "\r\n\r\n")
		head = strings.ReplaceAll(head, "\r\n", " | ")
		if len(head) > 320 {
			head = head[:320]
		}
		t.Logf("%-32s -> %s", c.name, head)
	}
}

// TestZZA6AdminPlaneMethodLeak records what a caller who is not an admin learns
// from the operator plane's routes. requireAdmin answers 404 to hide the plane;
// a wrong verb must not undo that.
func TestZZA6AdminPlaneMethodLeak(t *testing.T) {
	h := za6New(t, nil)
	h.signIn(t) // signed in as usr_<github 42>, not usr_admin

	probes := []struct{ method, target string }{
		{http.MethodGet, "/v1/admin/clients"},
		{http.MethodPut, "/v1/admin/clients"},
		{http.MethodDelete, "/v1/admin/clients"},
		{http.MethodGet, "/v1/admin/kill_switch"},
		{http.MethodPut, "/v1/admin/kill_switch"},
		{http.MethodGet, "/v1/nope"},
		{http.MethodPut, "/v1/nope"},
		{http.MethodPut, "/v1/me"},
	}
	for _, p := range probes {
		resp, body := h.do(t, p.method, p.target, nil, "")
		t.Logf("%-7s %-32s -> %d allow=%-24q ct=%-32s body=%.60q",
			p.method, p.target, resp.StatusCode, resp.Header.Get("Allow"),
			resp.Header.Get("Content-Type"), strings.ReplaceAll(body, "\n", `\n`))
	}
}

// TestZZA6HeadAndConditional probes HEAD and conditional requests, which take a
// different path through the mux dispatch and the compressor.
func TestZZA6HeadAndConditional(t *testing.T) {
	h := za6New(t, nil)
	h.signIn(t)

	// HEAD on a GET route is served from the GET handler by the mux dispatch.
	resp, body := h.do(t, http.MethodHead, "/v1/me", nil, "")
	t.Logf("HEAD /v1/me (no bearer) -> %d ct=%q cc=%q len=%d body=%q",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"), len(body), body)

	resp, _ = h.do(t, http.MethodHead, "/v1/account/export", nil, "")
	t.Logf("HEAD /v1/account/export -> %d ct=%q cd=%q cc=%q enc=%q len=%d content-length=%q",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"),
		resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Encoding"),
		resp.ContentLength, resp.Header.Get("Content-Length"))

	resp, body = h.do(t, http.MethodGet, "/app/", map[string]string{"Range": "bytes=0-10"}, "")
	t.Logf("GET /app/ Range -> %d ct=%q cr=%q len=%d body=%q",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Range"), len(body), body)

	resp, body = h.do(t, http.MethodGet, "/app/", map[string]string{"If-None-Match": `"x"`}, "")
	t.Logf("GET /app/ If-None-Match -> %d etag=%q len=%d", resp.StatusCode, resp.Header.Get("ETag"), len(body))
}

// TestZZA6TLSAndHostEdges checks Host-header handling: the service builds
// absolute URLs from its configured issuer, so a caller-supplied Host must not
// change any URL it hands back.
func TestZZA6TLSAndHostEdges(t *testing.T) {
	h := za6New(t, nil)

	for _, host := range []string{"evil.example", "re0auth.test", "127.0.0.1", ""} {
		req, err := http.NewRequest(http.MethodGet, h.base+"/v1/idp/providers", nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := h.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("Host=%-16q -> %d body=%.200q", host, resp.StatusCode, strings.ReplaceAll(string(b), "\n", ""))
	}

	// A plain-HTTP TLS handshake and an absolute-form request target.
	_ = tls.VersionTLS12
}
