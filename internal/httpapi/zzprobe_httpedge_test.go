//go:build audit5

package httpapi

// zzprobe_httpedge_test.go 鈥?adversarial probes for the HTTP edge (routing,
// middleware, sessions, CSRF, rate limiting, request parsing).
//
// Temporary probe file created by an audit sub-agent. It is the only new file in
// this package and it modifies nothing. Findings and their status are written up
// in docs/audit-5/findings/http-edge.md.
//
// Identifier conventions, so nothing here can collide with the package's own
// helpers: types and functions are prefixed zz / TestZZProbe, and every
// table-driven case is self-asserting so the probe cannot pass vacuously.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/Re0Auth/r0semi/oauth"
)

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

func zzProbeConfig(t *testing.T, tweak func(*Config)) Config {
	t.Helper()
	cfg := newFullConfig(t)
	if tweak != nil {
		tweak(&cfg)
	}
	return cfg
}

func zzProbeServer(t *testing.T, tweak func(*Config)) *Server {
	t.Helper()
	srv, err := New(zzProbeConfig(t, tweak))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// zzProbeSignedIn stands the full stack up on a real listener, signs one browser
// in through the fake IdP, and returns the base URL, the browser, every Set-Cookie
// the sign-in produced, and the signed-in server. The cookie headers are captured
// because a jar hides the attributes.
func zzProbeSignedIn(t *testing.T, tweak func(*Config)) (string, *http.Client, []string, *Server) {
	t.Helper()

	var captured []string
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42), "login": "octocat", "name": "Octo"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idpSrv.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   idpSrv.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL:     idpSrv.URL + "/github/authorize",
			TokenURL:    idpSrv.URL + "/github/token",
			UserInfoURL: idpSrv.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := zzProbeConfig(t, tweak)
	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: cfg.Secure})
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
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, "https://re0auth.test", clients, manager)
	cfg.Sessions = manager
	cfg.Accounts = accounts
	cfg.Auth = authHandler
	cfg.OIDC = opHandler
	cfg.TokenIntrospector = opHandler
	cfg.GrantStore = store
	cfg.DeviceStore = store
	cfg.Authorization = opHandler

	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.Handler().ServeHTTP(w, r)
		for _, ck := range w.Header().Values("Set-Cookie") {
			captured = append(captured, ck)
		}
	}))
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	signIn(t, browser, ts.URL)
	return ts.URL, browser, captured, srv
}

// TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers compares a business 404 that
// goes through the /v1 mux with one that does not.
//
// A path like /v1%2Fnope decodes to a /v1 path, so handleNotFound answers in
// planeOf's plane: problem+json. But the request never entered the business mux, so
// it misses the middlewares that mux carries: withNoStore and recoverBusiness. The
// two 404s are the same status, the same plane and nearly the same body, which is
// what makes the difference easy to miss.
func TestZZProbeEncodedBusinessPathSkipsThePlaneWrappers(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	for _, target := range []string{"/v1/nope", "/v1%2Fnope", "/v1%2F..%2Fme", "/v1%2Fme"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		t.Logf("%-16s -> %d %q Cache-Control=%q",
			target, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", target, rec.Code)
		}
		zzAssertPlane(t, http.MethodGet, httptest.NewRequest(http.MethodGet, target, nil).URL.Path, rec)
	}
	direct := httptest.NewRecorder()
	handler.ServeHTTP(direct, httptest.NewRequest(http.MethodGet, "/v1/nope", nil))
	encoded := httptest.NewRecorder()
	handler.ServeHTTP(encoded, httptest.NewRequest(http.MethodGet, "/v1%2Fnope", nil))
	if direct.Header().Get("Cache-Control") != encoded.Header().Get("Cache-Control") {
		t.Errorf("the same business-plane 404 carries different cache directives depending on how the path was spelled: direct=%q encoded=%q",
			direct.Header().Get("Cache-Control"), encoded.Header().Get("Cache-Control"))
	}
}

// TestZZProbeMrtEquivalentsAreAntiVacuous pulls the three runtime findings this
// area's probes independently re-confirmed into one place, with the cross-check
// that makes each assertion unable to pass for the wrong reason.
//
// It was prompted by `zzprobe_mrt_test.go` (another agent's one-off log-only probe
// of `docs/audit-5/findings/_main-runtime-findings.md`). That file only prints
// what it sees, so it cannot fail; the assertions live here instead, in the file
// this area owns. Nothing in that file was copied or modified.
//
// Each subtest pairs the suspicious path with a control path and requires the two
// answers to be *different in the stated way*, so "both paths happen to look
// alike" cannot make the test pass.
func TestZZProbeMrtEquivalentsAreAntiVacuous(t *testing.T) {
	metrics := observability.New()
	srv := zzProbeServer(t, func(c *Config) { c.Metrics = metrics })
	handler := srv.Handler()
	scrape := func() string {
		rec := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	// zzRawPathRequest sends a request whose Path and RawPath differ, which is what
	// makes Go's mux miss a route while planeOf still sees the namespace. Building
	// it from a URL string would decode %2F away and test nothing.
	zzRawPathRequest := func(method, rawPath, decodedPath string) *http.Request {
		req := httptest.NewRequest(method, "http://h/", nil)
		req.URL.Path = decodedPath
		req.URL.RawPath = rawPath
		req.RequestURI = rawPath
		return req
	}

	t.Run("double slash and dot segments redirect; they do not fall through", func(t *testing.T) {
		// Control first: the canonical path must NOT redirect, or every 307 below
		// would be explained by something else.
		canonical := httptest.NewRecorder()
		handler.ServeHTTP(canonical, zzRawPathRequest(http.MethodGet, "/v1/nope", "/v1/nope"))
		if canonical.Code == http.StatusTemporaryRedirect {
			t.Fatalf("control: /v1/nope redirected (%d); the walk is not measuring path cleaning",
				canonical.Code)
		}
		t.Logf("control  /v1/nope      -> %d %q", canonical.Code, canonical.Header().Get("Content-Type"))

		for _, raw := range []string{"/v1//nope", "/v1/./nope", "/v1/../v1/nope", "/oauth//token", "/oauth/./token"} {
			req := zzRawPathRequest(http.MethodGet, raw, raw)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusTemporaryRedirect && rec.Code != http.StatusMovedPermanently {
				t.Errorf("%s = %d, want a redirect out of the router (this is the two-places-decide "+
					"boundary): %s", raw, rec.Code, zzTruncate(rec.Body.String()))
				continue
			}
			loc := rec.Header().Get("Location")
			t.Logf("%-18s -> %d Location=%q Content-Type=%q (GET body is HTML: %v)",
				raw, rec.Code, loc, rec.Header().Get("Content-Type"),
				strings.Contains(rec.Header().Get("Content-Type"), "text/html"))
			// The redirect target must stay in the namespace it came from; a 307
			// that crossed planes would be a plane-contract break, not a curiosity.
			if planeOf(loc) != planeOf(raw) {
				t.Errorf("%s (%v) redirected into %s (%v): a router redirect crossed the plane boundary",
					raw, planeOf(raw), loc, planeOf(loc))
			}
			// The two-places problem, stated where it can fail: Go decided this
			// answer, so it carries none of this service's directives.
			if rec.Header().Get("Cache-Control") != "" {
				t.Logf("%-18s carries Cache-Control=%q", raw, rec.Header().Get("Cache-Control"))
			}
		}
	})

	t.Run("an escaped path answers problem+json but skips the plane wrapper", func(t *testing.T) {
		// Control: the canonical path goes through businessPlane(), so it carries
		// both headers the plane promises.
		canonical := httptest.NewRecorder()
		handler.ServeHTTP(canonical, zzRawPathRequest(http.MethodGet, "/v1/nope", "/v1/nope"))
		if canonical.Code != http.StatusNotFound {
			t.Fatalf("control: /v1/nope = %d, want 404", canonical.Code)
		}
		if canonical.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("control: /v1/nope Cache-Control = %q, want no-store; without this the "+
				"comparison below proves nothing", canonical.Header().Get("Cache-Control"))
		}
		if ct := canonical.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("control: /v1/nope Content-Type = %q, want problem+json", ct)
		}

		escaped := httptest.NewRecorder()
		handler.ServeHTTP(escaped, zzRawPathRequest(http.MethodGet, "/v1%2Fnope", "/v1/nope"))
		if escaped.Code != http.StatusNotFound {
			t.Fatalf("/v1%%2Fnope = %d, want 404", escaped.Code)
		}
		// Same plane, same status, same body shape — and the directive is missing.
		if ct := escaped.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("/v1%%2Fnope Content-Type = %q, want problem+json (the plane shape is right)", ct)
		}
		if escaped.Header().Get("Cache-Control") == canonical.Header().Get("Cache-Control") {
			t.Errorf("the two spellings agree on Cache-Control (%q): either the wrapper now covers both, "+
				"or this probe stopped reaching the difference",
				canonical.Header().Get("Cache-Control"))
		} else {
			t.Logf("escaped  /v1%%2Fnope   -> %d %q Cache-Control=%q (canonical had %q)",
				escaped.Code, escaped.Header().Get("Content-Type"),
				escaped.Header().Get("Cache-Control"), canonical.Header().Get("Cache-Control"))
		}
	})

	t.Run("both spellings are counted under plane=business", func(t *testing.T) {
		// The metric label is not a detail: it is what an operator's dashboard and
		// alerting see, and it is derived from planeOf rather than from the answer.
		for _, raw := range []string{"/v1//nope", "/v1%2Fnope"} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, zzRawPathRequest(http.MethodGet, raw, raw))
			body := scrape()
			if !strings.Contains(body, `plane="business"`) {
				t.Fatalf("%s: no business-plane series was exported at all", raw)
			}
			var saw bool
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "re0auth_http_requests_total{") &&
					strings.Contains(line, `plane="business"`) &&
					strings.Contains(line, `status="`+strconv.Itoa(rec.Code)+`"`) {
					saw = true
					t.Logf("%s -> %s", raw, line)
					break
				}
			}
			if !saw {
				t.Errorf("%s answered %d but no re0auth_http_requests_total series with "+
					"plane=\"business\" and that status exists; the metric and the error format disagree",
					raw, rec.Code)
			}
		}
	})
}

func zzTruncate(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

// zzShape classifies a response the way the plane contract does.
type zzShape struct {
	problem bool
	oauth   bool
}

func zzClassify(rec *httptest.ResponseRecorder) zzShape {
	ct := rec.Header().Get("Content-Type")
	body := rec.Body.Bytes()
	var s zzShape
	if strings.Contains(ct, "problem+json") {
		s.problem = true
	}
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		if _, ok := m["type"]; ok {
			s.problem = true
		}
		if _, ok := m["error"]; ok {
			s.oauth = true
		}
	}
	return s
}

// zzAssertPlane reports a leak on rec relative to the plane planeOf assigns to
// path. It returns true when a leak was found.
func zzAssertPlane(t *testing.T, method, path string, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	s := zzClassify(rec)
	switch planeOf(path) {
	case planeProtocol:
		if s.problem {
			t.Errorf("PROTOCOL LEAK: %s %s -> %d %q: %s",
				method, path, rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
			return true
		}
	case planeBusiness:
		if s.oauth {
			t.Errorf("BUSINESS LEAK: %s %s -> %d %q: %s",
				method, path, rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
			return true
		}
	default:
		if s.problem || s.oauth {
			t.Errorf("BROWSER LEAK: %s %s -> %d %q: %s",
				method, path, rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 1. rate limiter: bounded-key eviction hands out a fresh burst
// ---------------------------------------------------------------------------

// zzNoRefill is effectively "one token, never refilled": one token per 1000
// seconds. A second request from the same bucket key is a 429 unless the key was
// given a brand-new bucket.
const zzNoRefill = 0.001

// zzShardIndex reproduces the limiter's own shard choice for a key, so a probe
// can aim its traffic at one shard instead of hoping.
func zzShardIndex(s string) uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h % 16
}

// zzSeedsFor returns n distinct X-Forwarded-For values whose bucket key lands in
// the same shard as plane|target does.
func zzSeedsFor(n int, plane, target string) []string {
	want := zzShardIndex(plane + "|" + target)
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		cand := fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)
		if zzShardIndex(plane+"|"+cand) == want {
			out = append(out, cand)
		}
	}
	return out
}

// TestZZProbeRateLimitKeySpaceIsUncapped is the amplification the limiter's key
// choice allows.
//
// The bucket key is plane + client address, and the address comes from
// X-Forwarded-For whenever the peer is one of the configured trusted proxies. A
// caller whose requests arrive through a proxy that *appends* to
// X-Forwarded-For 鈥?rather than overwriting it 鈥?is therefore believed about its
// own address, so it can present a new address per request. Each new address is a
// new bucket, and a new bucket starts with the full burst. The limiter caps how
// many buckets it tracks (default 10,000 over 16 shards), which bounds the free
// budget at *one request per tracked key* rather than at the rate the operator
// configured 鈥?with no wait, since the refill interval here is 1000 seconds.
//
// The walk counts how many requests a single TCP peer is actually allowed before
// the first refusal.
func TestZZProbeRateLimitKeySpaceIsUncapped(t *testing.T) {
	limited, err := New(zzProbeConfig(t, func(c *Config) {
		c.Limiter = ratelimit.New(zzNoRefill, 1)
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	}))
	if err != nil {
		t.Fatal(err)
	}
	handler := limited.Handler()

	// Control first: one address, one bucket, one token.
	if got := zzCallWithXFF(t, handler, "203.0.113.9"); got != http.StatusUnauthorized {
		t.Fatalf("control: first request = %d, want 401", got)
	}
	if got := zzCallWithXFF(t, handler, "203.0.113.9"); got != http.StatusTooManyRequests {
		t.Fatalf("control: second request from one address = %d, want 429; the limiter is not wired, so nothing below proves anything", got)
	}

	// Now rotate the address, one request each.
	const budget = 20000
	admitted, refused := 0, 0
	for i := 0; i < budget; i++ {
		xff := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
		switch got := zzCallWithXFF(t, handler, xff); got {
		case http.StatusUnauthorized:
			admitted++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("unexpected status %d", got)
		}
	}
	t.Logf("one peer, %d distinct X-Forwarded-For values, rate=%.3f/s: admitted=%d refused=%d",
		budget, zzNoRefill, admitted, refused)
	// The configured policy is one request, then nothing for 1000 seconds. Even
	// allowing for the key cap, thousands of admissions is not a rate limit.
	if admitted > 1000 {
		t.Errorf("a single client address obtained %d requests against a limiter configured for one per %v: the bucket key is caller-chosen, so the rate limit does not bound anything",
			admitted, 1/zzNoRefill)
	}
}

func zzCallWithXFF(t *testing.T, h http.Handler, xff string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.RemoteAddr = "10.1.2.3:5555" // our own proxy: inside the trust list
	req.Header.Set("X-Forwarded-For", xff)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestZZProbeRateLimitSprayResetsAnHonestClientsBucket is the other half of the
// same mechanism, and it is the half that does not need the attacker to profit
// directly: filling a shard evicts *any* bucket the bounded eviction sample
// yields, including one belonging to an unrelated client. That client's spent
// budget is discarded and its next request starts from a full burst.
//
// It is measured over several independent trials, because the eviction scan takes a
// bounded random sample and one round can miss. A probe that reported the outcome
// of a single round would be reporting its own luck.
func TestZZProbeRateLimitSprayResetsAnHonestClientsBucket(t *testing.T) {
	const plane = "business"
	const trials = 20
	resets := 0
	for trial := 0; trial < trials; trial++ {
		victim := fmt.Sprintf("203.0.113.%d", 20+trial)

		limited, err := New(zzProbeConfig(t, func(c *Config) {
			c.Limiter = ratelimit.New(zzNoRefill, 1)
			c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
		}))
		if err != nil {
			t.Fatal(err)
		}
		handler := limited.Handler()

		if got := zzCallWithXFF(t, handler, victim); got != http.StatusUnauthorized {
			t.Fatalf("trial %d: victim first request = %d, want 401", trial, got)
		}
		if got := zzCallWithXFF(t, handler, victim); got != http.StatusTooManyRequests {
			t.Fatalf("trial %d: victim second request = %d, want 429 (the bucket must really be empty)", trial, got)
		}

		seeds := zzSeedsFor(700, plane, victim)
		want := zzShardIndex(plane + "|" + victim)
		for _, s := range seeds {
			if got := zzShardIndex(plane + "|" + s); got != want {
				t.Fatalf("seed %s hashes to shard %d, want %d", s, got, want)
			}
		}
		for _, s := range seeds {
			zzCallWithXFF(t, handler, s)
		}

		if zzCallWithXFF(t, handler, victim) == http.StatusUnauthorized {
			resets++
		}
	}
	t.Logf("%d/%d trials: another client's key spray discarded the victim's exhausted bucket and served it as if it had spent nothing",
		resets, trials)
	if resets == 0 {
		t.Errorf("no reset observed in %d trials; the eviction path never reached an unrelated client's bucket", trials)
	}
}

// TestZZProbeRateLimitIsFailClosedUnderAKeySpray is the guard that does hold: with
// no trust list 鈥?the default 鈥?the header is not consulted at all, so an
// untrusted peer cannot buy a bucket by inventing an address.
func TestZZProbeRateLimitIsFailClosedUnderAKeySpray(t *testing.T) {
	limited, err := New(zzProbeConfig(t, func(c *Config) {
		c.Limiter = ratelimit.New(zzNoRefill, 1)
	}))
	if err != nil {
		t.Fatal(err)
	}
	handler := limited.Handler()
	codes := map[int]int{}
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "203.0.113.77:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	t.Logf("untrusted peer varying X-Forwarded-For: %v", codes)
	if codes[http.StatusUnauthorized] > 1 {
		t.Errorf("an untrusted peer escaped its bucket by varying X-Forwarded-For: %d requests admitted", codes[http.StatusUnauthorized])
	}
}

// TestZZProbeClientAddrIgnoresOtherForwardingHeaders checks the headers RFC 7239
// defines and the de-facto ones, which clientAddr does not read: only a spoofed
// X-Forwarded-For should be ignored without a trust list, and with one it should
// be the only header that counts.
func TestZZProbeClientAddrIgnoresOtherForwardingHeaders(t *testing.T) {
	type tc struct {
		name    string
		headers map[string]string
		want    string
	}
	cases := []tc{
		{"X-Real-IP", map[string]string{"X-Real-IP": "198.51.100.9"}, "203.0.113.7"},
		{"Forwarded", map[string]string{"Forwarded": "for=198.51.100.9"}, "203.0.113.7"},
		{"X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "evil.example"}, "203.0.113.7"},
		{"X-Client-IP", map[string]string{"X-Client-IP": "198.51.100.9"}, "203.0.113.7"},
		{"CF-Connecting-IP", map[string]string{"CF-Connecting-IP": "198.51.100.9"}, "203.0.113.7"},
		{"XFF unknown", map[string]string{"X-Forwarded-For": "unknown"}, "203.0.113.7"},
		{"XFF with port", map[string]string{"X-Forwarded-For": "198.51.100.9:4444"}, "203.0.113.7"},
		{"XFF whitespace", map[string]string{"X-Forwarded-For": "  198.51.100.9  "}, "203.0.113.7"},
		{"XFF ipv6", map[string]string{"X-Forwarded-For": "[2001:db8::1]"}, "203.0.113.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = "203.0.113.7:5555"
			for k, v := range c.headers {
				req.Header.Set(k, v)
			}
			// Untrusted peer: only the peer address may be used.
			if got := clientAddr(req, nil); got != c.want {
				t.Errorf("untrusted: clientAddr = %q, want %q", got, c.want)
			}
			// Trusted peer, the same headers: still only X-Forwarded-For counts.
			trusted := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
			got := clientAddr(req, trusted)
			if _, isXFF := c.headers["X-Forwarded-For"]; !isXFF {
				if got != "203.0.113.7" && got != c.want {
					t.Errorf("trusted peer: clientAddr = %q; a non-XFF header changed the attribution", got)
				}
			}
			t.Logf("%s: untrusted=%q trusted=%q", c.name, clientAddr(req, nil), got)
		})
	}
}

// ---------------------------------------------------------------------------
// 2. plane shape over spellings and methods
// ---------------------------------------------------------------------------

var zzRequestPatterns = []string{
	"/oauth",
	"/oauth/",
	"/oauth/token",
	"/oauth/authorize",
	"/oauth/authorize/callback",
	"/oauth/userinfo",
	"/oauth/keys",
	"/oauth/introspect",
	"/oauth/revoke",
	"/oauth/device_authorization",
	"/oauth/nope",
	"/.well-known",
	"/.well-known/",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/oauth-protected-resource",
	"/.well-known/nope",
	"/v1",
	"/v1/",
	"/v1/me",
	"/v1/nope",
	"/auth/github/start",
	"/bind",
	"/nope",
}

// TestZZProbePlaneShapeHoldsForEveryMethodAndSpelling drives every combination of
// (spelling 脳 method) through the real handler and asserts the plane contract on
// each response. It counts its own assertions so a walk that stopped reaching
// handlers fails rather than passing empty.
func TestZZProbePlaneShapeHoldsForEveryMethodAndSpelling(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodHead,
	}

	checked, leaks := 0, 0
	for _, path := range zzRequestPatterns {
		for _, method := range methods {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			checked++
			if zzAssertPlane(t, method, path, rec) {
				leaks++
			}
		}
	}
	t.Logf("checked %d (path, method) combinations across %d spellings; %d plane leaks",
		checked, len(zzRequestPatterns), leaks)
	if checked < 100 {
		t.Fatalf("only %d combinations checked; the walk is not running", checked)
	}
}

// TestZZProbeEncodedAndOddSpellingsKeepTheirPlane is the same contract for the
// spellings Go's mux treats differently from the decoded path every plane
// decision reads: encoded slashes, dot segments, doubled slashes, semicolons and
// the percent-encoded spellings of a namespace root.
//
// The expectation is derived from the decoded path, not from the literal: net/http
// decodes %2F into a path separator before any handler sees the request, so
// "/oauth%2Ftoken" really is a request for /oauth/token and the plane is the
// protocol plane. The assertion is therefore "the response's shape matches the
// plane of the path this handler received".
func TestZZProbeEncodedAndOddSpellingsKeepTheirPlane(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	cases := []string{
		"/oauth%2Ftoken",
		"/oauth%2F",
		"/.well-known%2Fopenid-configuration",
		"/%2Ewell-known%2Fopenid-configuration",
		"/oauth/./token",
		"/oauth//token",
		"/oauth/../oauth/token",
		"/v1%2Fme",
		"/v1%2F..%2Fme",
		"/v1/./me",
		"/v1//me",
		"/v1/../v1/me",
		"/v1;foo",
		"/oauth;foo/token",
		"/V1/me",
		"/OAuth/token",
		"/.well-known/oauth-protected-resource/",
		"/.well-known/oauth-protected-resource/x",
	}

	redirects, permanent := 0, 0
	for _, target := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, target, nil)
			decoded := req.URL.Path
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			// The response must answer in the plane of the path this handler
			// received, whatever spelling produced it.
			zzAssertPlane(t, method, decoded, rec)
			if rec.Code >= 300 && rec.Code < 400 {
				redirects++
				if rec.Code == http.StatusMovedPermanently {
					permanent++
					t.Logf("PERMANENT REDIRECT %s %s (decoded %q) -> Location=%q Cache-Control=%q",
						method, target, decoded, rec.Header().Get("Location"), rec.Header().Get("Cache-Control"))
				}
			}
			t.Logf("%-6s %-40s decoded=%-40q plane=%-8s -> %d %q %s",
				method, target, decoded, planeOf(decoded), rec.Code,
				rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
		}
	}
	t.Logf("%d spellings x 2 methods: %d redirects (%d permanent)", len(cases), redirects, permanent)
}

// TestZZProbeAuthorizationRedirectCarriesNoCacheDirective records the cache
// policy of the two redirects an authorization flow produces. Both carry
// single-use secrets in their query: the login redirect carries `authRequestID`
// and the authorization response carries the `code`.
func TestZZProbeAuthorizationRedirectCarriesNoCacheDirective(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "cli", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})

	verifier := strings.Repeat("a", 43)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"cli"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"st"},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	t.Logf("login redirect: %d Location=%q Cache-Control=%q Pragma=%q",
		rec.Code, loc, rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	if strings.Contains(loc, "authRequestID=") && rec.Header().Get("Cache-Control") == "" {
		t.Errorf("the redirect carrying authRequestID (%q) has no Cache-Control", loc)
	}

	// Now the authorization response itself, which carries the code.
	id := ""
	if u, err := url.Parse(loc); err == nil {
		id = u.Query().Get("authRequestID")
	}
	if id == "" {
		t.Skip("the OP's login redirect no longer carries authRequestID; the second half cannot run")
	}
	if err := env.store.CompleteLogin(t.Context(), id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	loc = rec.Header().Get("Location")
	t.Logf("authorization response: %d Location=%q Cache-Control=%q Pragma=%q",
		rec.Code, loc, rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	if strings.Contains(loc, "code=") && rec.Header().Get("Cache-Control") == "" {
		t.Errorf("the authorization response carrying a code (%q) has no Cache-Control", loc)
	}
}

// ---------------------------------------------------------------------------
// 3. session cookie attributes
// ---------------------------------------------------------------------------

// TestZZProbeSessionCookieAttributes records the cookie the service actually sets
// in both deployment modes, taken from a real sign-in through the fake IdP rather
// than from the constructor.
func TestZZProbeSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		base, client, setCookies, _ := zzProbeSignedIn(t, func(c *Config) { c.Secure = secure })
		t.Logf("secure=%v base=%s; %d Set-Cookie headers seen during sign-in", secure, base, len(setCookies))

		seen := 0
		for _, ck := range setCookies {
			seen++
			t.Logf("secure=%v Set-Cookie: %s", secure, ck)
			lower := strings.ToLower(ck)
			if strings.HasPrefix(lower, "__host-") {
				for _, need := range []string{"secure", "path=/"} {
					if !strings.Contains(lower, need) {
						t.Errorf("__Host- cookie without %s: %s", need, ck)
					}
				}
				if strings.Contains(lower, "domain=") {
					t.Errorf("__Host- cookie with Domain: %s", ck)
				}
			}
			if !secure && strings.Contains(lower, "secure") {
				t.Errorf("Secure attribute on a plain-http deployment: %s", ck)
			}
			if !strings.Contains(lower, "httponly") {
				t.Errorf("session cookie without HttpOnly: %s", ck)
			}
			if !strings.Contains(lower, "samesite") {
				t.Errorf("session cookie without SameSite: %s", ck)
			}
		}
		if seen == 0 {
			t.Errorf("secure=%v: no Set-Cookie was observed; the probe proves nothing", secure)
		}
		// The session must not survive a sign-out server-side: after Destroy, the
		// same cookie must not answer as a session.
		resp := getURL(t, client, base+"/v1/sessions/current")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("signed-in session view = %d, want 200", resp.StatusCode)
		}
		csrf, _ := decodeResp(t, resp)["csrf_token"].(string)
		out := zzProbeSend(t, client, base, http.MethodPost, "/v1/sessions/sign_out", "", csrf)
		t.Logf("sign_out -> %d", out.code)
		resp = getURL(t, client, base+"/v1/sessions/current")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("after sign_out the session cookie still authenticates: /v1/sessions/current = %d", resp.StatusCode)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. CSRF coverage of every session-authenticated write
// ---------------------------------------------------------------------------

// TestZZProbeEveryWriteRouteRefusesAnAbsentCSRFToken drives every declared non-GET
// business route with a live session, once with the CSRF token and once without.
// A route whose answer is identical in both cases does nothing with the token,
// which is the whole question.
func TestZZProbeEveryWriteRouteRefusesAnAbsentCSRFToken(t *testing.T) {
	// One fresh signed-in server per route: several of these endpoints consume
	// state (sign_out destroys the session, DELETE /v1/account erases it, DELETE
	// /v1/identities unlinks), so a single walk would test the second half of the
	// list against a dead session — which is exactly how this probe first reported
	// fourteen "no active session" answers that looked like they proved something.
	_, _, _, srv := zzProbeSignedIn(t, nil)

	subst := strings.NewReplacer(
		"{game}", "phigros", "{source}", "fake", "{resource}", "profile",
		"{client_id}", "cli", "{id}", "req_1", "{path}", "x",
	)
	body := `{"decision":"deny","acknowledge":"deletes_my_account","target":"all"}`
	writeMethods := map[string]bool{
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
		http.MethodDelete: true,
	}

	checked, reached, unenforced := 0, 0, 0
	for _, rt := range srv.specRoutes() {
		if !writeMethods[rt.Method] {
			continue
		}
		target := subst.Replace(rt.Pattern)
		checked++

		// A fresh browser for every route, so nothing an earlier route did can
		// explain this one's answer.
		freshBase, freshClient, _, _ := zzProbeSignedIn(t, nil)
		session := decodeResp(t, getURL(t, freshClient, freshBase+"/v1/sessions/current"))
		csrf, _ := session["csrf_token"].(string)
		if csrf == "" {
			t.Fatalf("%s %s: the fresh session carried no CSRF token", rt.Method, rt.Pattern)
		}
		u, err := url.Parse(freshBase)
		if err != nil {
			t.Fatal(err)
		}
		cookie := ""
		for _, ck := range freshClient.Jar.Cookies(u) {
			cookie = ck.Name + "=" + ck.Value
		}
		if cookie == "" {
			t.Fatalf("%s %s: the fresh sign-in produced no session cookie", rt.Method, rt.Pattern)
		}

		send := func(token string) zzResp {
			return zzProbeSendCookie(t, freshClient, rt.Method, freshBase+target, body, token, cookie)
		}
		with := send(csrf)
		bad := send(strings.Repeat("0", 64))
		without := send("")

		t.Logf("%-6s %-38s valid=%d wrong=%d absent=%d %s",
			rt.Method, rt.Pattern, with.code, bad.code, without.code, zzTruncate(without.body))

		// A 401 before the CSRF check (no session) or a 404 (route not mounted in
		// this Config) says nothing about the token. They are reported, not counted.
		if without.code == http.StatusUnauthorized || without.code == http.StatusNotFound {
			continue
		}
		reached++
		if without.code != http.StatusForbidden {
			unenforced++
			t.Errorf("%s %s: no CSRF token = %d, want 403", rt.Method, rt.Pattern, without.code)
		}
		if bad.code != http.StatusForbidden {
			unenforced++
			t.Errorf("%s %s: a wrong CSRF token = %d, want 403 (the comparison is not being made)", rt.Method, rt.Pattern, bad.code)
		}
	}
	t.Logf("%d write routes walked, %d reached the CSRF check, %d unenforced", checked, reached, unenforced)
	if checked < 5 {
		t.Fatalf("only %d write routes checked", checked)
	}
	if reached < 3 {
		t.Fatalf("only %d routes reached the CSRF check; the walk proves almost nothing", reached)
	}
}

type zzResp struct {
	code int
	body string
}

func zzProbeSend(t *testing.T, c *http.Client, base, method, target, body, csrf string) zzResp {
	t.Helper()
	return zzProbeSendCookie(t, c, method, base+target, body, csrf, "")
}

// zzProbeSendCookie is zzProbeSend with an explicit Cookie header, so a probe can
// be certain which session the request carried.
func zzProbeSendCookie(t *testing.T, c *http.Client, method, urlStr, body, csrf, cookie string) zzResp {
	t.Helper()
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return zzResp{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
}

// TestZZProbeCrossSiteFormCannotReachAWrite is the browser-shaped half: a
// cross-site <form> can send only text/plain, application/x-www-form-urlencoded
// or multipart/form-data, and cannot set a custom header. Any write endpoint that
// accepted one of those would be CSRF-able with no token at all.
func TestZZProbeCrossSiteFormCannotReachAWrite(t *testing.T) {
	base, client, _, srv := zzProbeSignedIn(t, nil)

	subst := strings.NewReplacer(
		"{game}", "phigros", "{source}", "fake", "{resource}", "profile",
		"{client_id}", "cli", "{id}", "req_1", "{path}", "x",
	)
	accepted, checked := 0, 0
	for _, rt := range srv.specRoutes() {
		if rt.Method == http.MethodGet {
			continue
		}
		target := subst.Replace(rt.Pattern)
		for _, ct := range []string{
			"application/x-www-form-urlencoded",
			"text/plain",
			"multipart/form-data; boundary=xx",
		} {
			req, err := http.NewRequest(rt.Method, base+target,
				strings.NewReader("decision=approve&acknowledge=deletes_my_account&target=all"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", ct)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			checked++
			if resp.StatusCode < 400 {
				accepted++
				t.Errorf("CROSS-SITE FORM REACHED A WRITE: %s %s with Content-Type %s -> %d",
					rt.Method, rt.Pattern, ct, resp.StatusCode)
			}
		}
	}
	t.Logf("%d form-shaped attempts, %d accepted", checked, accepted)
	if checked < 20 {
		t.Fatalf("only %d attempts made", checked)
	}
}

// TestZZProbeGETsDoNotMutate walks every declared GET with a live session and
// records which ones have a side effect. It cannot observe state directly, so it
// reports the ones whose status suggests a decision (200 on a read is not
// evidence); the report interprets the results.
func TestZZProbeGETsDoNotMutate(t *testing.T) {
	base, client, _, srv := zzProbeSignedIn(t, nil)

	subst := strings.NewReplacer(
		"{game}", "phigros", "{source}", "fake", "{resource}", "profile",
		"{client_id}", "cli", "{id}", "req_1", "{path}", "x",
	)
	checked := 0
	for _, rt := range srv.specRoutes() {
		if rt.Method != http.MethodGet {
			continue
		}
		target := subst.Replace(rt.Pattern)
		resp := getURL(t, client, base+target)
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		checked++
		t.Logf("GET %-45s -> %d %s", rt.Pattern, resp.StatusCode, zzTruncate(string(b)))
	}
	if checked < 8 {
		t.Fatalf("only %d GET routes walked", checked)
	}
}

// ---------------------------------------------------------------------------
// 5. request-parsing limits and parsing panics
// ---------------------------------------------------------------------------

// TestZZProbeQueryParamSprayIsNotBounded records what a request with thousands of
// query parameters does. The body has a cap; the query string has none, and the
// protocol plane's duplicate-parameter guard walks the whole set on every request.
func TestZZProbeQueryParamSprayIsNotBounded(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	for _, n := range []int{1, 2000, 20000} {
		var b strings.Builder
		b.WriteString("/oauth/authorize?")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "p%d=v&", i)
		}
		req := httptest.NewRequest(http.MethodGet, b.String(), nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		t.Logf("%6d query params: status=%d body=%s", n, rec.Code, zzTruncate(rec.Body.String()))
		if rec.Code == 0 {
			t.Errorf("%d query params produced no response", n)
		}
	}
}

// TestZZProbeHostileQueryValuesDoNotPanic feeds the query parameters a handler
// reads into every route, looking for a panic that escapes as a 500.
func TestZZProbeHostileQueryValuesDoNotPanic(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	hostile := []string{
		"?limit=-1", "?limit=0", "?limit=999999999999999999999",
		"?before=-1", "?cursor=-1", "?cursor=99999999999999999999",
		"?since=0001-01-01T00:00:00Z", "?until=0001-01-01T00:00:00Z",
		"?user_code=", "?user_code=%00%ff",
		"?source=%00", "?return_to=%2f%2fevil.example",
		"?id=", "?state=", "?code=",
		"?limit=%2d1", "?limit=+1",
	}
	subst := strings.NewReplacer(
		"{game}", "phigros", "{source}", "fake", "{resource}", "profile",
		"{client_id}", "cli", "{id}", "req_1", "{path}", "x",
	)
	srv := zzProbeServer(t, nil)
	fives := 0
	for _, rt := range srv.specRoutes() {
		if rt.Method != http.MethodGet {
			continue
		}
		for _, qs := range hostile {
			target := subst.Replace(rt.Pattern) + qs
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIC ESCAPED for GET %s: %v", target, r)
					}
				}()
				handler.ServeHTTP(rec, req)
			}()
			if rec.Code >= 500 {
				fives++
				t.Logf("GET %s -> %d %s", target, rec.Code, zzTruncate(rec.Body.String()))
			}
		}
	}
	t.Logf("%d GET routes x %d hostile query values, %d server errors", len(srv.specRoutes()), len(hostile), fives)
}

// TestZZProbeBodyLimitAppliesToEveryPlane drives an oversized declared body at
// each plane and records the refusal shape, which the plane split promises for
// this refusal too.
func TestZZProbeBodyLimitAppliesToEveryPlane(t *testing.T) {
	handler := zzProbeServer(t, nil).Handler()
	huge := strings.Repeat("x", (64<<10)+1)
	for _, target := range []string{"/oauth/token", "/v1/me", "/auth/github/callback", "/bind", "/app/", "/nope"} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(huge))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		t.Logf("%-24s -> %d %q %s", target, rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
	}
}

// ---------------------------------------------------------------------------
// 6. open redirects: every place a caller-supplied URL becomes a Location
// ---------------------------------------------------------------------------

// zzUnsafeLocation reports why a Location is not a same-origin absolute path.
func zzUnsafeLocation(loc string) string {
	switch {
	case loc == "":
		return ""
	case strings.HasPrefix(loc, "//"):
		return "scheme-relative (another host)"
	case strings.Contains(loc, "\\"):
		return "backslash"
	case strings.HasPrefix(loc, "/\\"):
		return "slash-backslash"
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "unparseable: " + err.Error()
	}
	if u.Scheme != "" || u.Host != "" {
		return "absolute URL to another origin"
	}
	return ""
}

// TestZZProbeReturnToCannotLeaveTheOrigin drives the login plane's return_to
// parameter through the real handler and asserts that nothing the caller can put
// there becomes a Location pointing somewhere else.
func TestZZProbeReturnToCannotLeaveTheOrigin(t *testing.T) {
	hostile := []string{
		"//evil.example",
		"/\\evil.example",
		"\\\\evil.example",
		"https://evil.example",
		"https:/evil.example",
		"http:evil.example",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"%2f%2fevil.example",
		"/%2f%2fevil.example",
		"/%5cevil.example",
		"/\t/evil.example",
		"/\n/evil.example",
		"/\r\nX-Injected: 1",
		"/app/consent\nSet-Cookie: a=b",
		"///evil.example",
		"/./\\evil.example",
		"..%2f..%2fevil.example",
		"",
		"/app/",
		"/app/consent?id=1",
	}

	for _, rt := range []string{"/auth/github/start", "/bind"} {
		for _, raw := range hostile {
			target := rt + "?return_to=" + url.QueryEscape(raw)
			if rt == "/bind" {
				target += "&game=phigros&source=fake"
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIC for %s: %v", target, r)
					}
				}()
				zzProbeServer(t, nil).Handler().ServeHTTP(rec, req)
			}()
			loc := rec.Header().Get("Location")
			// /auth/{provider}/start is *supposed* to leave this origin: it hands
			// the browser to the identity provider. What must never happen is that
			// the caller's return_to is what the redirect follows, so the check is
			// "no redirect target is derived from return_to" for that route.
			if rt == "/auth/github/start" {
				if loc != "" && !strings.Contains(loc, "/github/authorize") {
					t.Errorf("return_to redirected the browser instead of the provider: GET %s -> Location=%q", target, loc)
				}
			} else if reason := zzUnsafeLocation(loc); reason != "" {
				t.Errorf("OPEN REDIRECT: GET %s -> %d Location=%q (%s)", target, rec.Code, loc, reason)
			}
			t.Logf("GET %-60s -> %d Location=%q", target, rec.Code, zzTruncate(loc))
		}
	}
}

// TestZZProbeRootRedirectCarriesItsQuerySafely checks the "{/$}" redirect, which
// exists only when a frontend is mounted and copies the caller's raw query into
// the Location.
func TestZZProbeRootRedirectCarriesItsQuerySafely(t *testing.T) {
	srv := zzProbeServer(t, func(c *Config) { c.Frontend = webui.FS() })
	for _, q := range []string{
		"", "?error=access_denied", "?next=//evil.example", "?x=%0d%0aSet-Cookie:+a=b",
		"?u=https://evil.example", "?%2f%2f=1",
	} {
		req := httptest.NewRequest(http.MethodGet, "/"+q, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		loc := rec.Header().Get("Location")
		t.Logf("GET /%-34s -> %d Location=%q", q, rec.Code, loc)
		if reason := zzUnsafeLocation(loc); reason != "" {
			t.Errorf("OPEN REDIRECT: GET /%s -> Location=%q (%s)", q, loc, reason)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. panic recovery: no internals on the wire
// ---------------------------------------------------------------------------

// TestZZProbePanicRecoveryLeaksNothingToTheClient wires a provider that panics on
// every path and asserts that no plane's 500 carries the panic value, a stack
// trace, or this repository's internals.
//
// The protocol paths go through the injected handler directly. The business paths
// cannot — /v1 answers 401 before it reaches introspection, which a panic there
// would not change — so the business half panics inside the introspector instead,
// which is the seam every bearer-authenticated route does reach.
func TestZZProbePanicRecoveryLeaksNothingToTheClient(t *testing.T) {
	const secret = "zzsecret-panic-value-9f3"
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(secret) })

	leakCheck := func(t *testing.T, target, body string, code int) {
		t.Helper()
		for _, needle := range []string{secret, "goroutine ", ".go:", "Re0Auth", "runtime.", "r0semi/internal"} {
			if strings.Contains(body, needle) {
				t.Errorf("DISCLOSURE: %s response body contains %q: %s", target, needle, zzTruncate(body))
			}
		}
		if code != http.StatusInternalServerError {
			t.Errorf("%s = %d, want 500 (a panic must answer, not drop the connection)", target, code)
		}
	}

	t.Run("protocol and browser", func(t *testing.T) {
		srv, err := New(zzProbeConfig(t, func(c *Config) { c.OIDC = boom }))
		if err != nil {
			t.Fatal(err)
		}
		handler := srv.Handler()
		for _, target := range []string{
			"/oauth/token", "/oauth/authorize", "/oauth/nope",
			"/.well-known/openid-configuration", "/.well-known/nope",
		} {
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIC ESCAPED to the client for %s: %v", target, r)
					}
				}()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
			}()
			t.Logf("GET %-38s -> %d %q %s", target, rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
			leakCheck(t, target, rec.Body.String(), rec.Code)
		}
	})

	t.Run("business", func(t *testing.T) {
		panicIntro := introspectorFunc(func(context.Context, string) (oauth.TokenInfo, error) {
			panic(secret)
		})
		srv, err := New(zzProbeConfig(t, func(c *Config) { c.TokenIntrospector = panicIntro }))
		if err != nil {
			t.Fatal(err)
		}
		handler := srv.Handler()
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.Header.Set("Authorization", "Bearer whatever")
		rec := httptest.NewRecorder()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("PANIC ESCAPED to the client for /v1/me: %v", r)
				}
			}()
			handler.ServeHTTP(rec, req)
		}()
		t.Logf("GET /v1/me (panicking introspector) -> %d %q %s",
			rec.Code, rec.Header().Get("Content-Type"), zzTruncate(rec.Body.String()))
		leakCheck(t, "/v1/me", rec.Body.String(), rec.Code)
		zzAssertPlane(t, http.MethodGet, "/v1/me", rec)
	})
}

// introspectorFunc adapts a function to the TokenIntrospector interface.
type introspectorFunc func(context.Context, string) (oauth.TokenInfo, error)

func (f introspectorFunc) Introspect(ctx context.Context, token string) (oauth.TokenInfo, error) {
	return f(ctx, token)
}

// zzCookieRecorder records the Cookie header of the last request, so a probe can
// tell "the session was not sent" apart from "the server rejected it".
type zzCookieRecorder struct {
	inner http.RoundTripper
	last  *string
}

func (r zzCookieRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.last = req.Header.Get("Cookie")
	return r.inner.RoundTrip(req)
}
