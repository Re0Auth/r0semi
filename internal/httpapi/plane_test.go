package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// browserPaths are the paths that belong to no plane: a person reaches them by
// navigating with a browser. Before this was decided the shared middleware handed
// them the business plane's error shape by accident, so an operator tuning the
// rate limit also changed the wire contract of a login page.
var browserPaths = []string{
	"/auth/github/start",
	"/auth/login",
	"/auth",
	"/bind",
	"/consent",
	"/foo",
	"/v2/me",
}

// protocolPaths are the protocol-plane URLs a caller can construct.
//
// The two bare namespace roots are here on purpose: they are what somebody types,
// and a rejection at `/oauth` or `/.well-known` must answer in the protocol
// plane's shape like every other URL under them. They are also the URLs where the
// two prefix tests disagreed.
var protocolPaths = []string{
	"/oauth/authorize",
	"/oauth/token",
	"/oauth/revoke",
	"/oauth/introspect",
	"/oauth/userinfo",
	"/oauth/keys",
	"/oauth/device_authorization",
	"/oauth",
	"/oauth/not-a-real-endpoint",
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-protected-resource",
	"/.well-known",
}

// protocolAnyMethod names the endpoints the library serves without a method
// constraint: it reads `r.Form`, which a GET's query string satisfies just as a
// POST body does. The walk reaches each of these by both methods, because the
// wrapper's contract has to hold for the request the library actually accepts.
//
// A POST-only assumption is not cosmetic: it is exactly how the token endpoint's
// response sanitising (no `id_token` without `openid`, `Cache-Control: no-store`)
// and the device endpoint's scope pre-flight were each skipped on a reachable
// path, so the walk that used the "expected" method could not see either.
var protocolAnyMethod = map[string]bool{
	"/oauth/authorize":            true,
	"/oauth/token":                true,
	"/oauth/revoke":               true,
	"/oauth/introspect":           true,
	"/oauth/device_authorization": true,
}

// The two planes promise different error formats, and that promise is the whole
// reason they are split: a standard OAuth client has to be able to parse every
// /oauth failure, and a JSON client every /v1 one. Keeping it true for the
// handlers somebody thought about is easy; keeping it true for the next handler is
// not, which is why this is a property over the whole surface rather than a test
// per endpoint.
//
// Every route the server declares, plus every protocol-plane path, is answered
// without credentials. Each failure must be in its own plane's shape. A new route
// that answers in the wrong shape fails here without anyone remembering to extend
// a list — the failure mode a per-endpoint test cannot catch.
//
// Only the failure shape is asserted. A 405 from the router, or a 401 whose body
// this service does not specify, is not a plane leak; the invariant is what the
// body is *never* allowed to be.
func TestErrorFormatNeverCrossesPlanes(t *testing.T) {
	srv := newFullEnv(t)
	handler := srv.Handler()

	// Path parameters replaced with values that reach a handler rather than the
	// router's own 404.
	subst := strings.NewReplacer(
		"{game}", "phigros",
		"{resource}", "profile",
		"{source}", "fake",
		"{client_id}", "cli",
		"{path}", "x",
		"{id}", "req_1",
	)

	// Count what actually asserted a failure. Routing that silently stopped
	// reaching a handler — a renamed pattern, a route that began answering 200
	// without a credential — would otherwise leave this test passing while
	// checking nothing.
	asserted := struct{ business, protocol int }{}

	for _, rt := range srv.specRoutes() {
		t.Run("v1 "+rt.Method+" "+rt.Pattern, func(t *testing.T) {
			rec := httptest.NewRecorder()
			// No bearer, no session, no CSRF: the point is the failure shape.
			handler.ServeHTTP(rec, httptest.NewRequest(rt.Method, subst.Replace(rt.Pattern), nil))
			if rec.Code < 400 {
				return // public, or satisfied without credentials
			}
			assertProblemPlane(t, rec)
			asserted.business++
		})
	}

	// Each endpoint is asked the way a client would reach it — and the ones the
	// library serves without a method constraint (see protocolAnyMethod) by both
	// methods. `POST /oauth/authorize` is in this walk on purpose: the library
	// registers that endpoint without a method constraint and reads `r.Form`, so a
	// walk that issued only GETs would not notice a pre-flight that only ran for
	// GET — which is exactly the gap that let a confidential client obtain a code
	// with no PKCE and let an unknown client answer in the library's plain-text
	// shape.
	type attempt struct{ method, path string }
	attempts := make([]attempt, 0, len(protocolPaths)*2)
	for _, p := range protocolPaths {
		attempts = append(attempts, attempt{http.MethodGet, p})
		if protocolAnyMethod[p] {
			attempts = append(attempts, attempt{http.MethodPost, p})
		}
	}

	for _, a := range attempts {
		t.Run("oauth "+a.method+" "+a.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(a.method, a.path, nil))
			if rec.Code < 400 {
				return
			}
			assertOAuthPlane(t, rec)
			asserted.protocol++
		})
	}

	// Floors, not exact counts: the point is that the walk is doing work, and a
	// route may legitimately become public. Well below the current figures on
	// purpose.
	if asserted.business < 15 {
		t.Fatalf("only %d business routes produced a failure; the walk is not reaching handlers", asserted.business)
	}
	if asserted.protocol < 5 {
		t.Fatalf("only %d protocol paths produced a failure; the walk is not reaching the provider", asserted.protocol)
	}
}

// Compression can refuse a request without ever calling the handler, and it picks
// its error writer with the same predicate the plane split uses. A client that
// refuses every coding must not be handed the wrong plane's shape — and on the
// protocol plane the request must not be negotiated at all, since those bodies
// must never be transformed. The existing walk cannot reach any of this: it never
// sets Accept-Encoding.
func TestProtocolPlaneIsNeverCompressedNorRefused(t *testing.T) {
	srv := newFullEnv(t)
	handler := srv.Handler()

	for _, path := range protocolPaths {
		t.Run(path, func(t *testing.T) {
			for _, ae := range []string{"identity;q=0", "*;q=0", "gzip;q=0, identity;q=0"} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Accept-Encoding", ae)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code == http.StatusNotAcceptable {
					t.Fatalf("Accept-Encoding %q answered 406: a protocol-plane URL is not negotiated for a coding", ae)
				}
				if enc := rec.Header().Get("Content-Encoding"); enc != "" {
					t.Fatalf("Accept-Encoding %q was compressed (%s): the protocol plane must not be transformed", ae, enc)
				}
				if rec.Code >= 400 {
					assertOAuthPlane(t, rec)
				}
			}
		})
	}

	// The business plane is still negotiated, and its refusal keeps its own shape.
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Accept-Encoding", "identity;q=0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("business refusal = %d, want 406", rec.Code)
	}
	assertProblemPlane(t, rec)
}

// assertBrowserPlane checks the browser plane's promise: neither plane's error
// shape. It is deliberately not "must be text/plain" — a redirect has no body at
// all, and forcing a content type onto one would be the same mistake in reverse.
func assertBrowserPlane(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "problem+json") {
		t.Fatalf("browser plane answered %d with problem+json — body: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body == nil {
		return
	}
	if _, ok := body["type"]; ok {
		t.Fatalf("browser plane leaked a problem+json object: %s", rec.Body.String())
	}
	if _, ok := body["error"]; ok {
		t.Fatalf("browser plane leaked an OAuth error object: %s", rec.Body.String())
	}
}

func TestBrowserPlaneNeverAnswersWithAPlaneError(t *testing.T) {
	handler := newFullEnv(t).Handler()

	t.Run("router", func(t *testing.T) {
		failed := 0
		for _, path := range browserPaths {
			t.Run(path, func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				assertBrowserPlane(t, rec)
				if rec.Code >= 400 {
					failed++
				}
			})
		}
		// Anti-vacuous: a redirect asserts nothing about a failure shape, so the
		// walk has to have produced real failures for this to mean anything.
		if failed < 4 {
			t.Fatalf("only %d of %d browser paths produced a failure; the walk is not reaching handlers",
				failed, len(browserPaths))
		}
	})

	// The limiter is *why* this needed deciding: it is the middleware whose
	// configuration an operator changes, and it used to change the shape too.
	t.Run("limiter", func(t *testing.T) {
		for _, path := range browserPaths {
			t.Run(path, func(t *testing.T) {
				env := newTestEnv(t)
				limited, err := New(Config{
					Issuer:            testIssuer,
					OIDC:              env.handler,
					TokenIntrospector: env.handler,
					GrantStore:        env.store,
					DeviceStore:       env.store,
					Limiter:           ratelimit.New(0.001, 1),
				})
				if err != nil {
					t.Fatal(err)
				}
				do := func() *httptest.ResponseRecorder {
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.RemoteAddr = "203.0.113.9:1234"
					rec := httptest.NewRecorder()
					limited.Handler().ServeHTTP(rec, req)
					return rec
				}
				do() // spend the single token
				rec := do()
				if rec.Code != http.StatusTooManyRequests {
					t.Fatalf("second request = %d, want 429", rec.Code)
				}
				assertBrowserPlane(t, rec)
			})
		}
	})

	// The compressor can answer before any handler runs, so it too has to choose
	// the plane's shape. It used to borrow writeProblem for every path, which gave
	// a browser navigation a problem+json 406.
	t.Run("compression", func(t *testing.T) {
		handler := newFullEnv(t).Handler()
		for _, path := range browserPaths {
			t.Run(path, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Accept-Encoding", "identity;q=0")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotAcceptable {
					t.Fatalf("status = %d, want 406", rec.Code)
				}
				assertBrowserPlane(t, rec)
			})
		}
	})
}

// assertProblemPlane checks a business-plane failure: problem+json, with a
// machine code — and never an OAuth error object.
func assertProblemPlane(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("business plane answered %d with Content-Type %q, want application/problem+json — body: %s",
			rec.Code, ct, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body == nil {
		t.Fatalf("business plane body is not a JSON object: %s", rec.Body.String())
	}
	if _, ok := body["error"]; ok {
		t.Fatalf("business plane leaked an OAuth error object: %s", rec.Body.String())
	}
	if _, ok := body["error_description"]; ok {
		t.Fatalf("business plane leaked an OAuth error_description: %s", rec.Body.String())
	}
	if code, _ := body["code"].(string); code == "" {
		t.Fatalf("business-plane problem has no machine code: %s", rec.Body.String())
	}
}

// assertOAuthPlane checks a protocol-plane failure: an OAuth error body, and never
// problem+json.
//
// A non-JSON body is a failure, not something to tolerate. OAuth clients parse
// `{error, error_description}`; a plain-text 400 from the library is the plane
// contract leaking, and it is what an unknown client used to get on the POST
// authorize path because the pre-flight did not run there.
func assertOAuthPlane(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	if strings.Contains(ct, "problem+json") {
		t.Fatalf("protocol plane answered %d with %q — body: %s", rec.Code, ct, rec.Body.String())
	}
	if rec.Code < 400 {
		return
	}
	body := decodeBody(t, rec)
	if body == nil {
		t.Fatalf("protocol plane answered %d with Content-Type %q and a non-JSON body: %s",
			rec.Code, ct, rec.Body.String())
	}
	if _, ok := body["type"]; ok {
		t.Fatalf("protocol plane leaked a problem+json object: %s", rec.Body.String())
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("protocol-plane failure carries no `error` field: %s", rec.Body.String())
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return nil
	}
	return body
}
