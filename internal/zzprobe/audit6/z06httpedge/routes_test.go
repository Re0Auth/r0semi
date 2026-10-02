//go:build audit6

// Routing, path-spelling and verb-matrix probes for zone 06 (round 6).
//
// What these attack:
//   - the b35f893 canonical-path guard (cross-plane spellings must be refused
//     in the plane of the path as sent, never redirected) — regression check,
//     plus spellings the round-5 guard tests did not list;
//   - the verb matrix on every /.well-known endpoint, not just the two
//     discovery documents the fix covered;
//   - percent-encoded slashes inside path parameters (the {path...} wildcard
//     unescapes them), and whether that can smuggle a raw path past the
//     router's own cleaning rules.
package z06httpedge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ06CrossPlaneSpellingsAreRefusedInTheOriginalPlane is the regression half
// of b35f893's guard: any spelling whose cleaned form lands in another plane
// must be answered with a 4xx in the ORIGINAL plane's shape, never with the
// router's own redirect. The product's own guard test lists three spellings;
// this walks a wider matrix, including encoded dot-dots, trailing slashes and
// multi-level climbs.
func TestZ06CrossPlaneSpellingsAreRefusedInTheOriginalPlane(t *testing.T) {
	h := edgeServer(t, nil).Handler()

	cases := []struct {
		target string
		plane  string // the plane of the path AS SENT
	}{
		// business -> protocol
		{"/v1/../oauth/token", "business"},
		{"/v1/%2e%2e/oauth/token", "business"},
		{"/v1/%2E%2E/oauth/token", "business"},
		{"/v1/../../oauth/token", "business"},
		{"/v1/x/../../oauth/token", "business"},
		{"/v1/../.well-known/openid-configuration", "business"},
		{"/v1/../oauth/token/", "business"},
		{"/v1/./../oauth/token", "business"},
		// protocol -> business
		{"/oauth/../v1/me", "protocol"},
		{"/oauth/%2e%2e/v1/me", "protocol"},
		{"/oauth/x/../../v1/me", "protocol"},
		{"/.well-known/../v1/me", "protocol"},
		{"/.well-known/%2e%2e/v1/me", "protocol"},
		// business -> browser
		{"/v1/..", "business"},
		{"/v1/%2e%2e", "business"},
		{"/v1/../..", "business"},
		{"/v1/x/../..", "business"},
		// ("/v1/me/.." cleans to /v1 — the SAME plane — so it is the
		// router's own same-plane 307, the residual already filed in round 5;
		// it is deliberately not in this cross-plane matrix.)
		// browser -> business/protocol
		{"/x/../v1/me", "browser"},
		{"/x/%2e%2e/oauth/token", "browser"},
		{"//v1/me", "browser"},
		{"//oauth/token", "browser"},
		{"//.well-known/openid-configuration", "browser"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			rec := edgeCall(t, h, http.MethodGet, tc.target, nil)
			if rec.Code >= 300 && rec.Code < 400 {
				t.Fatalf("%s answered %d Location=%q: a spelling must not be redirected across a plane",
					tc.target, rec.Code, rec.Header().Get("Location"))
			}
			if rec.Code < 400 {
				t.Fatalf("%s = %d, want a 4xx in the plane of the path as sent", tc.target, rec.Code)
			}
			assertPlaneShape(t, tc.plane, rec)
		})
	}
}

// assertPlaneShape checks a failure is in its plane's own shape (the product's
// plane_test has the canonical versions in-package; this is the copy for an
// external probe package).
func assertPlaneShape(t *testing.T, plane string, rec *httptest.ResponseRecorder) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	body := rec.Body.String()
	isProblem := strings.Contains(ct, "problem+json")
	isOAuthJSON := strings.Contains(ct, "application/json") && strings.Contains(body, `"error"`)
	switch plane {
	case "business":
		if !isProblem {
			t.Fatalf("business-plane path answered %d with Content-Type %q — body: %s", rec.Code, ct, body)
		}
		if strings.Contains(body, `"error_description"`) {
			t.Fatalf("business plane leaked an OAuth error object: %s", body)
		}
	case "protocol":
		if isProblem {
			t.Fatalf("protocol-plane path answered %d with problem+json — body: %s", rec.Code, body)
		}
		if !strings.Contains(ct, "json") {
			t.Fatalf("protocol-plane path answered %d with Content-Type %q — body: %s", rec.Code, ct, body)
		}
		if !strings.Contains(body, `"error"`) {
			t.Fatalf("protocol-plane failure carries no error field: %s", body)
		}
	default: // browser: neither plane's object
		if isProblem {
			t.Fatalf("browser-plane path answered %d with problem+json — body: %s", rec.Code, body)
		}
		if isOAuthJSON {
			t.Fatalf("browser-plane path answered %d with an OAuth error object — body: %s", rec.Code, body)
		}
	}
}

// TestZ06WellKnownVerbMatrixCoversEveryDocument: the round-5 gap was that the
// two discovery documents answered every verb with 200; b35f893 put them in
// endpointMethods. The third well-known endpoint, the RFC 9728
// oauth-protected-resource document, is served by httpapi's own root-mux
// handler and is NOT in that table. This probe asks what it answers for verbs
// it does not declare, against the CHANGELOG's own claim that every endpoint
// declares its verbs and unlisted ones answer 405.
func TestZ06WellKnownVerbMatrixCoversEveryDocument(t *testing.T) {
	clients := oauth.NewMemoryClientRegistry()
	op, _ := newRealOP(t, clients)
	h := edgeServer(t, func(c *httpapi.Config) { c.OIDC = op }).Handler()

	endpoints := []struct {
		path  string
		verbs []string
	}{
		{"/.well-known/openid-configuration", []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions}},
		{"/.well-known/oauth-authorization-server", []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions}},
		{"/.well-known/oauth-protected-resource", []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions}},
	}
	for _, ep := range endpoints {
		for _, verb := range ep.verbs {
			t.Run(verb+" "+ep.path, func(t *testing.T) {
				rec := edgeCall(t, h, verb, ep.path, nil)
				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("%s %s = %d (Content-Type %q), want 405 per the verb matrix: %s",
						verb, ep.path, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
				}
				if rec.Header().Get("Allow") == "" {
					t.Errorf("%s %s answered 405 with no Allow header", verb, ep.path)
				}
				assertPlaneShape(t, "protocol", rec)
			})
		}
	}
}

// TestZ06ProbeEndpointsOnlyAnswerGET pins the probe endpoints' own verb policy:
// they belong to no plane, so the answer for a wrong verb is recorded rather
// than asserted (the catch-all's 404, text/plain, not a plane object).
func TestZ06ProbeEndpointsOnlyAnswerGET(t *testing.T) {
	h := edgeServer(t, nil).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		for _, verb := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			t.Run(verb+" "+path, func(t *testing.T) {
				rec := edgeCall(t, h, verb, path, nil)
				if rec.Code >= 500 {
					t.Fatalf("%s %s = %d: a wrong verb on a probe must not be a server error", verb, path, rec.Code)
				}
				if rec.Code < 400 {
					t.Fatalf("%s %s = %d, want a refusal", verb, path, rec.Code)
				}
				assertPlaneShape(t, "browser", rec)
			})
		}
	}
}

// TestZ06EncodedSlashPathParamsStayInsideTheRawRoute probes what the router
// delivers to the raw passthrough when the path contains percent-encoded
// slashes and dot-dots: Go's mux matches on the escaped path (so "%2e%2e" is
// one segment), unescapes it for the handler, and the federation layer owns
// the escape guard. The attack is a spelling that reaches the source's base
// URL or a sibling path outside the raw subtree. The invariant measured here
// is the one that matters: no spelling makes the source answer for a path
// outside its configured raw base.
func TestZ06EncodedSlashPathParamsStayInsideTheRawRoute(t *testing.T) {
	h, token, hits := rawEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// Cases that must not reach the source at all: literal dot-dots are cleaned
	// by the router first (same-plane 307), encoded ones by the federation
	// guard (400 ErrRawPathEscapes).
	refused := []struct {
		target string
	}{
		{"/v1/games/phigros/sources/src/raw/../../secret"},
		{"/v1/games/phigros/sources/src/raw/..%2Fsecret"},
		{"/v1/games/phigros/sources/src/raw/%2e%2e%2fsecret"},
		{"/v1/games/phigros/sources/src/raw/x%2F..%2F..%2Fsecret"},
		{"/v1/games/phigros/sources/src/raw/.."},
		{"/v1/games/phigros/sources/src/raw/%2e%2e"},
	}
	for _, tc := range refused {
		t.Run(tc.target, func(t *testing.T) {
			before := len(*hits)
			rec := edgeCall(t, h, http.MethodGet, tc.target, map[string]string{
				"Authorization": "Bearer " + token,
			})
			if rec.Code == http.StatusOK {
				t.Fatalf("raw path %s = 200, want a refusal (307 from the router's clean or 400 from the federation guard)", tc.target)
			}
			if len(*hits) != before {
				t.Fatalf("raw path %s reached the source (%v)", tc.target, (*hits)[before:])
			}
		})
	}

	// Cases that may reach the source: the path they ask for must stay inside
	// the configured raw base (the source's /v1 subtree).
	allowed := []struct {
		target  string
		wantHit string
	}{
		// A leading encoded slash is normalized into the join, not an escape.
		{"/v1/games/phigros/sources/src/raw/%2Fetc%2Fpasswd", "/v1/etc/passwd"},
		// The clean spelling, end to end.
		{"/v1/games/phigros/sources/src/raw/scores?x=1", "/v1/scores"},
	}
	for _, tc := range allowed {
		t.Run(tc.target, func(t *testing.T) {
			before := len(*hits)
			rec := edgeCall(t, h, http.MethodGet, tc.target, map[string]string{
				"Authorization": "Bearer " + token,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("raw path %s = %d — body: %s", tc.target, rec.Code, rec.Body.String())
			}
			if len(*hits) != before+1 {
				t.Fatalf("raw path %s did not reach the source", tc.target)
			}
			if got := (*hits)[before]; got != tc.wantHit {
				t.Fatalf("raw path %s made the source answer %q, want %q (inside the raw base)", tc.target, got, tc.wantHit)
			}
		})
	}
}

// TestZ06GameAndSourceParamsCannotSmuggleARoute checks that percent-encoded
// slashes in the SINGLE-wildcard params (game, source, resource) cannot change
// which route answers: the value stays inside its parameter.
func TestZ06GameAndSourceParamsCannotSmuggleARoute(t *testing.T) {
	h, token, _ := rawEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	cases := []struct {
		target string
		want   int
	}{
		// game contains an encoded slash: it must not become two segments.
		{"/v1/games/phigros%2Fsources%2Fsrc/profile", http.StatusNotFound},
		// source with encoded traversal: still just a lookup miss.
		{"/v1/games/phigros/sources/src%2F..%2Fraw/profile", http.StatusNotFound},
		// resource with an encoded slash: not the profile route's resource.
		{"/v1/games/phigros/profile%2Fx", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			rec := edgeCall(t, h, http.MethodGet, tc.target, map[string]string{
				"Authorization": "Bearer " + token,
			})
			if rec.Code != tc.want {
				t.Fatalf("%s = %d, want %d — body: %s", tc.target, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent documents the known residual
// (round-5 V-2): the limiter keys on the UNCLEANED path, so an address holds
// one bucket per plane and a cross-plane spelling is throttled by the bucket of
// the plane it was sent to, before the canonical-path guard can refuse it.
// This is filed; the probes here pin the two SAFE halves — the spelling is
// never admitted as a fresh request, and every refusal stays in the plane of
// the path as sent.
//
// The protocol-plane half needs the REAL provider: the stub OIDC handler answers
// every method with 200, so it cannot show the verb matrix's 405 that proves the
// request was admitted rather than throttled.
func TestZ06LimiterKeyStaysOnThePlaneOfThePathAsSent(t *testing.T) {
	clients := oauth.NewMemoryClientRegistry()
	op, _ := newRealOP(t, clients)
	h := edgeServer(t, func(c *httpapi.Config) {
		c.OIDC = op
		c.Limiter = ratelimit.New(noRefill, 1)
	}).Handler()

	get := func(peer, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	spent := "203.0.113.7:5555"
	if rec := get(spent, "/v1/me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first /v1/me = %d, want 401", rec.Code)
	}
	if rec := get(spent, "/v1/me"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /v1/me = %d, want 429 (the bucket is spent)", rec.Code)
	}
	// With the business bucket spent, the cross-plane spelling is throttled by
	// that same bucket — the limiter sees the UNCLEANED path (the filed V-2
	// residual). What must still hold: the refusal is in the business plane's
	// shape, and the request never reaches the protocol plane's handler.
	rec := get(spent, "/v1/../oauth/token")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("/v1/../oauth/token with a spent business bucket = %d, want the limiter's 429 (the key is the uncleaned path)", rec.Code)
	}
	assertPlaneShape(t, "business", rec)

	// With a fresh bucket, the canonical-path guard refuses the spelling
	// itself, in the plane of the path as sent.
	fresh := "203.0.113.8:5555"
	rec = get(fresh, "/v1/../oauth/token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1/../oauth/token with a full bucket = %d, want the guard's 404", rec.Code)
	}
	assertPlaneShape(t, "business", rec)

	// And the protocol plane has its own bucket (documented design): the same
	// spent address is still admitted here and answered by the protocol plane's
	// own verb matrix, not by the limiter.
	if rec := get(fresh, "/oauth/token"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("first /oauth/token GET = %d, want 405 (own bucket, still admitted)", rec.Code)
	}
}
