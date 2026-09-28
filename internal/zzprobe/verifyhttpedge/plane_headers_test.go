//go:build audit5

package verifyhttpedge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// zzRec is one recorded response with the headers this area's findings turn on.
type zzRec struct {
	code     int
	ctype    string
	cache    string
	location string
	body     string
}

func zzDo(t *testing.T, srv *httpapi.Server, method, target, peer string) zzRec {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = peer
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return zzRec{
		code:     rec.Code,
		ctype:    rec.Header().Get("Content-Type"),
		cache:    rec.Header().Get("Cache-Control"),
		location: rec.Header().Get("Location"),
		body:     rec.Body.String(),
	}
}

// TestV_BusinessPlaneDirectiveIsNotAttachedToThePlane is the verifier's own
// reproduction of HE-4, done through the exported surface and WITHOUT the report's
// raw-path trick: httptest.NewRequest("/v1%2Fnope") already produces a request
// whose URL.Path is the decoded "/v1/nope" and whose EscapedPath is "/v1%2Fnope",
// which is what makes Go's mux miss the /v1/ pattern.
//
// It also asks the question the report does not: is the escaped path the ONLY
// business-plane answer that escapes withNoStore? Every request below gets its own
// peer, so one limiter serves the whole walk.
func TestV_BusinessPlaneDirectiveIsNotAttachedToThePlane(t *testing.T) {
	srv := zzServer(t)

	canonical := zzDo(t, srv, http.MethodGet, "/v1/nope", zzPeer())
	t.Logf("control  /v1/nope   -> %d %q Cache-Control=%q", canonical.code, canonical.ctype, canonical.cache)
	if canonical.code != http.StatusNotFound || canonical.ctype != "application/problem+json" || canonical.cache != "no-store" {
		t.Fatalf("control is not the shape the comparison needs: %d %q %q", canonical.code, canonical.ctype, canonical.cache)
	}

	escaped := zzDo(t, srv, http.MethodGet, "/v1%2Fnope", zzPeer())
	t.Logf("escaped  /v1%%2Fnope -> %d %q Cache-Control=%q body=%s", escaped.code, escaped.ctype, escaped.cache, escaped.body)
	if escaped.code != http.StatusNotFound {
		t.Fatalf("the escaped spelling answered %d, not the 404 this probe is about", escaped.code)
	}
	// HE-4 is fixed: the directive belongs to writeProblem itself now, so the
	// escaped spelling carries the same directive as the canonical one. This
	// assertion is inverted from the finding's original form — it fails if the two
	// spellings differ again, which is what a regression would look like.
	if escaped.cache != canonical.cache {
		t.Errorf("the escaped spelling carries Cache-Control=%q but the canonical one carries %q: "+
			"HE-4 regressed (the directive is no longer set by writeProblem itself)",
			escaped.cache, canonical.cache)
	}
	if escaped.cache != "no-store" {
		t.Errorf("the escaped business 404 Cache-Control = %q, want no-store", escaped.cache)
	}

	// What the escaped 404's body contains: the decoded path, which is
	// caller-supplied, reflected back.
	var prob map[string]any
	if err := json.Unmarshal([]byte(escaped.body), &prob); err != nil {
		t.Fatalf("escaped 404 body is not JSON: %v (%q)", err, escaped.body)
	}
	t.Logf("escaped 404 instance=%v (the decoded, caller-supplied path)", prob["instance"])

	// The question the report answers "no" to: a business-plane 429 is written by
	// withRateLimit, which sits OUTSIDE the /v1 mux and therefore outside
	// withNoStore. If it has no directive either, HE-4's root cause is not "the
	// router boundary" but "any writer reached from outside the plane wrapper".
	peer := zzPeer()
	first := zzDo(t, srv, http.MethodGet, "/v1/me", peer)
	second := zzDo(t, srv, http.MethodGet, "/v1/me", peer)
	t.Logf("admitted /v1/me    -> %d %q Cache-Control=%q", first.code, first.ctype, first.cache)
	t.Logf("refused  /v1/me    -> %d %q Cache-Control=%q body=%s", second.code, second.ctype, second.cache, second.body)
	if second.code != http.StatusTooManyRequests {
		t.Fatalf("the limiter did not refuse the second request (%d); this probe is not measuring the 429 path", second.code)
	}
	if second.cache == "" {
		t.Errorf("the business-plane 429 carries no cache directive either: HE-4's gap is not limited to escaped paths")
	}
}

// TestV_RouterRedirectsAndThePlaneBoundary records which mux-generated redirects
// carry which headers, and whether the mux's path cleaning can move a request from
// one plane to another. HE-7 asserts that no cross-plane redirect exists, and the
// report's own guard asserts planeOf(Location) == planeOf(raw); the spellings below
// are the ones that claim rests on.
func TestV_RouterRedirectsAndThePlaneBoundary(t *testing.T) {
	local := zzServerNoLimit(t)
	cases := []struct{ method, target string }{
		{http.MethodGet, "/v1//me"},
		{http.MethodPost, "/v1//me"},
		{http.MethodGet, "/oauth//token"},
		{http.MethodGet, "/v1/./me"},
		{http.MethodGet, "/.well-known/./openid-configuration"},
		{http.MethodGet, "/v1/../oauth/token"},
		{http.MethodGet, "/oauth/../v1/me"},
		{http.MethodGet, "/.well-known/../v1/me"},
	}
	for _, c := range cases {
		got := zzDo(t, local, c.method, c.target, zzPeer())
		t.Logf("inproc %-4s %-32s -> %d Location=%-20q Content-Type=%-24q Cache-Control=%q",
			c.method, c.target, got.code, got.location, got.ctype, got.cache)
		if got.code != http.StatusTemporaryRedirect {
			t.Logf("       (not a redirect: %s)", got.body)
			continue
		}
		raw, loc := planeOfZZ(c.target), planeOfZZ(got.location)
		if raw != loc {
			t.Errorf("CROSS-PLANE REDIRECT: %s (%s) -> %q (%s)", c.target, raw, got.location, loc)
		}
	}

	// The same two spellings over a real socket, because a path with dot segments
	// is only interesting if an actual client can send it.
	live := zzServerNoLimitReal(t)
	defer live.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, target := range []string{"/v1/../oauth/token", "/oauth/../v1/me"} {
		req, err := http.NewRequest(http.MethodGet, live.URL+target, nil)
		if err != nil {
			t.Fatalf("build %s: %v", target, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("live   %-32s -> %d Location=%q Content-Type=%q Cache-Control=%q body=%s",
			target, resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("Content-Type"),
			resp.Header.Get("Cache-Control"), zzCut(string(body)))
		if loc := resp.Header.Get("Location"); loc != "" {
			if a, b := planeOfZZ(target), planeOfZZ(loc); a != b {
				t.Errorf("CROSS-PLANE REDIRECT over a real socket: %s (%s) -> %q (%s)", target, a, loc, b)
			}
		}
	}
}

func zzCut(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

// TestV_UncleanedPathDecidesTheLimiterPlane shows the second consequence of the
// router/plane boundary: the limiter (middleware.go:349) and the metric label read
// planeOf(r.URL.Path) BEFORE the mux cleans the path, so a spelling the mux
// redirects into the protocol plane spends the PROTOCOL plane's bucket and gets the
// protocol plane's refusal — while the business bucket for the same peer is
// untouched.
func TestV_UncleanedPathDecidesTheLimiterPlane(t *testing.T) {
	srv := zzServer(t)
	peer := zzPeer()

	first := zzDo(t, srv, http.MethodGet, "/oauth/../v1/me", peer)
	second := zzDo(t, srv, http.MethodGet, "/oauth/../v1/me", peer)
	t.Logf("1st /oauth/../v1/me -> %d %q Location=%q", first.code, first.ctype, first.location)
	t.Logf("2nd /oauth/../v1/me -> %d %q body=%s", second.code, second.ctype, second.body)
	if second.code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429: the walked path is not the one being counted", second.code)
	}
	if !strings.Contains(second.body, `"error"`) {
		t.Errorf("the refusal for a /v1-bound spelling is not the protocol plane's shape: %s", second.body)
	}
	// The business bucket for the same peer has not been touched, although the
	// request's destination (/v1/me) is on the business plane.
	if got := zzDo(t, srv, http.MethodGet, "/v1/me", peer); got.code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me = %d, want 401: the business bucket was spent by the /oauth spelling", got.code)
	}
}

// planeOfZZ mirrors internal/httpapi's planeOf for the namespaces it names. It is
// used only to LABEL what the walk observed, never as the thing under test.
func planeOfZZ(p string) string {
	root := func(prefix string) bool {
		return p == prefix || (len(p) > len(prefix) && p[:len(prefix)] == prefix && p[len(prefix)] == '/')
	}
	switch {
	case root("/oauth"), root("/.well-known"):
		return "protocol"
	case root("/v1"):
		return "business"
	default:
		return "browser"
	}
}

var _ = fmt.Sprintf
