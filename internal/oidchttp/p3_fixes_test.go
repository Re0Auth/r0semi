package oidchttp

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// S02-6: RFC 9110 §15.5.6 requires a 405 to carry Allow. G-24 routed every
// protocol-plane refusal through methodNotAllowed, which sets it from the same
// endpointMethods table that refused the request; this pins the header on the
// discovery branches (which are reached before serveOAuth) and on a POST-only
// /oauth endpoint.
func TestP3S02_6MethodNotAllowedCarriesAllow(t *testing.T) {
	f := newFixture(t)

	cases := []struct {
		method, path, wantAllow string
	}{
		{http.MethodGet, "/oauth/token", "POST"},
		{http.MethodPut, "/oauth/token", "POST"},
		{http.MethodGet, "/oauth/introspect", "POST"},
		{http.MethodPost, "/oauth/keys", "GET, HEAD"},
		{http.MethodPost, OIDCDiscoveryPath, "GET, HEAD"},
		{http.MethodPut, RFC8414Path, "GET, HEAD"},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, f.server.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d, want 405", tc.method, tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != tc.wantAllow {
			t.Fatalf("%s %s Allow = %q, want %q", tc.method, tc.path, got, tc.wantAllow)
		}
	}
}

// S02-7: serveDiscovery rewrites URL.Path to the OIDC document but left RawPath
// as the escaped spelling the request arrived with. go-chi routes on RawPath when
// it is non-empty, so a percent-encoded discovery URL 404'd before the document
// was rendered. Each case uses a fresh handler and asks the escaped spelling
// FIRST, so the render (not the cache) is what answers.
func TestP3S02_7PercentEncodedDiscoveryPathsServeTheDocument(t *testing.T) {
	for _, path := range []string{
		"/.well-known/openid%2Dconfiguration",
		"/.well-known/oauth%2Dauthorization-server",
	} {
		f := newFixture(t)
		resp, err := http.Get(f.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, resp.StatusCode, body)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("GET %s is not the discovery document: %s", path, body)
		}
		if issuer, _ := doc["issuer"].(string); issuer == "" {
			t.Fatalf("GET %s served a document without an issuer: %s", path, body)
		}
		if endpoint, _ := doc["authorization_endpoint"].(string); !strings.HasSuffix(endpoint, "/oauth/authorize") {
			t.Fatalf("GET %s authorization_endpoint = %q", path, endpoint)
		}
	}
}

// panicOnKeysStorage answers the JWKS read with a panic, so a request reaches
// the provider (which runs after serveOAuth has pooled its writer) and then blows
// up inside it.
type panicOnKeysStorage struct{ op.Storage }

func (panicOnKeysStorage) KeySet(context.Context) ([]op.Key, error) {
	panic("probe: storage panic")
}

// S14-11: serveOAuth pooled a bufferedWriter and released it only on the normal
// path, so a panic inside the provider leaked it. The pool is made unable to
// manufacture a writer and drained, so "Get returns non-nil" afterwards is
// exactly "the handler put its writer back".
// serveOAuthBody returns the parsed body of (*Handler).serveOAuth, so a guard can
// state an invariant about the code path without observing it at run time.
func serveOAuthBody(t *testing.T) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "oidchttp.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serveOAuth" {
			continue
		}
		var out bytes.Buffer
		if err := printer.Fprint(&out, fset, fn.Body); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	t.Fatal("serveOAuth was not found in oidchttp.go")
	return ""
}

// S14-11: the pooled capture writer has to come back even when the provider
// panics, or every panic leaks one writer.
//
// This is pinned as a source guard rather than by reading sync.Pool afterwards:
// sync.Pool is explicitly allowed to drop entries (a GC between Put and Get does
// exactly that), so a "Get returns non-nil" assertion is flaky under -race. The
// invariant the release depends on is that serveOAuth defers the one and only
// release, so that is what is asserted.
func TestP3S14_11ServeOAuthReleasesBufferedWriterOnPanic(t *testing.T) {
	body := serveOAuthBody(t)
	if !strings.Contains(body, "acquireBufferedWriter()") {
		t.Fatal("serveOAuth no longer acquires a buffered writer")
	}
	if !strings.Contains(body, "defer releaseBufferedWriter(") {
		t.Fatal("serveOAuth no longer defers the buffered-writer release: a panicking provider leaks a pooled writer (S14-11)")
	}
	if n := strings.Count(body, "releaseBufferedWriter("); n != 1 {
		t.Fatalf("serveOAuth releases the buffered writer %d times; the deferred release must be the only one", n)
	}
}

// S02-5 / P-03 (PROTO-8): the discovery cache is keyed by path only, while the
// dynamic-issuer shape derives the issuer — and every advertised endpoint URL —
// from the request Host. The first caller therefore fixed the document for the
// life of the process. This uses the dynamic shape (production requires a
// configured issuer) with two forged Hosts.
func TestP3S02_5AndP03DiscoveryCacheIsNotHostBlind(t *testing.T) {
	f := newFixture(t) // Config.Issuer empty: IssuerFromHost

	fetch := func(host string) map[string]any {
		req, err := http.NewRequest(http.MethodGet, f.server.URL+OIDCDiscoveryPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery for %q = %d: %s", host, resp.StatusCode, body)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}

	attacker := fetch("attacker.example")
	real := fetch("real.example")
	if attacker["issuer"] == real["issuer"] {
		t.Fatalf("discovery is cached host-blind: real.example got issuer %v", real["issuer"])
	}
	if got, _ := real["issuer"].(string); !strings.Contains(got, "real.example") {
		t.Fatalf("real.example issuer = %v, want its own host", got)
	}
	if got, _ := attacker["issuer"].(string); !strings.Contains(got, "attacker.example") {
		t.Fatalf("attacker.example issuer = %v", got)
	}
}

// S02-9: the token endpoint is the busiest protocol path and every 200 was
// JSON-decoded into a map and (whenever offline_access was present) re-marshalled.
// A body that cannot contain anything to strip is returned untouched: zero
// allocations, provably no change.
func TestP3S02_9SanitizeTokenResponseSkipsCleanBodies(t *testing.T) {
	clean := []byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"account.id"}`)
	if out := sanitizeTokenResponse(clean); !bytes.Equal(out, clean) {
		t.Fatalf("a clean body was rewritten: %s", out)
	}
	if allocs := testing.AllocsPerRun(200, func() { _ = sanitizeTokenResponse(clean) }); allocs != 0 {
		t.Fatalf("sanitizeTokenResponse allocated %v times for a body with nothing to strip, want 0", allocs)
	}

	// The rules still fire when the field names are present.
	out := sanitizeTokenResponse([]byte(`{"access_token":"a","scope":"account.id","id_token":"jws"}`))
	if bytes.Contains(out, []byte("id_token")) {
		t.Fatalf("id_token survived without openid: %s", out)
	}
	out = sanitizeTokenResponse([]byte(`{"access_token":"a","scope":"account.id offline_access"}`))
	if bytes.Contains(out, []byte("offline_access")) {
		t.Fatalf("offline_access survived: %s", out)
	}
}

// S02-10: `state` and `nonce` are caller-chosen and were unbounded at the
// authorize entrance, unlike PKCE, request ids and handle ids. The library
// persists them verbatim (state on the auth request, nonce into every id_token
// derived from the grant), so one GET could push ~60 KB into storage and every
// later response. The refusal goes through the registered redirect, like the
// PKCE refusals.
func TestP3S02_10AuthorizeStateAndNonceAreLengthCapped(t *testing.T) {
	f := newFixture(t)

	base := func() url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {f.webID},
			"redirect_uri":          {"https://client.example/cb"},
			"scope":                 {"account.id"},
			"code_challenge":        {strings.Repeat("a", 64)},
			"code_challenge_method": {"S256"},
		}
	}

	// Baseline: a value at the cap is still served (redirect to the login plane).
	// The lengths are literals, not the constant, so the probe pins the bound and
	// cannot be made vacuous by widening it.
	for _, name := range []string{"state", "nonce"} {
		q := base()
		q.Set(name, strings.Repeat("x", 512))
		resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusFound ||
			!strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
			t.Fatalf("%s at the 512-byte cap was refused: %d %q",
				name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// Over the cap: refused through the registered redirect, never persisted.
	for _, name := range []string{"state", "nonce"} {
		q := base()
		q.Set(name, strings.Repeat("x", 513))
		resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("%s over the cap = %d, want 302", name, resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Host != "client.example" {
			t.Fatalf("%s over the cap reached %q, want the client redirect",
				name, resp.Header.Get("Location"))
		}
		if got := loc.Query().Get("error"); got != "invalid_request" {
			t.Fatalf("%s over the cap error = %q, want invalid_request", name, got)
		}
	}
}
