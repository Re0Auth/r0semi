//go:build audit5

package verifyhttpedge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// TestV_SpotCheckForwardingHeaders is one of the verifier's spot-checks of the
// report's "probed but not broken" list (item 5: clientAddr reads X-Forwarded-For
// and nothing else). A false negative there would be the most expensive kind of
// error, because it would mean a caller CAN choose its bucket through a header the
// report says is ignored.
//
// The control now runs in the only shape where the header is read at all: the
// deployment has declared `client_addr_header = "x-forwarded-for"`. The default
// reads no header, and that is asserted alongside.
func TestV_SpotCheckForwardingHeaders(t *testing.T) {
	h := zzServerMode(t, httpapi.ClientAddrXForwardedFor, "10.0.0.0/8").Handler()
	const peer = "10.1.2.3:5555"

	send := func(headers map[string]string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = peer
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Control: with a trust list AND a declared header, X-Forwarded-For IS the
	// bucket key, so a second request with a different value is admitted.
	if got := send(map[string]string{"X-Forwarded-For": "198.51.100.1"}); got == http.StatusTooManyRequests {
		t.Fatalf("control: the first request was already refused (%d)", got)
	}
	if got := send(map[string]string{"X-Forwarded-For": "198.51.100.2"}); got == http.StatusTooManyRequests {
		t.Errorf("control failed: X-Forwarded-For did not move the key (%d)", got)
	}

	// The same deployment WITHOUT the declaration: the header moves nothing.
	plain := zzServer(t, "10.0.0.0/8").Handler()
	plainSend := func(v string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", v)
		rec := httptest.NewRecorder()
		plain.ServeHTTP(rec, req)
		return rec.Code
	}
	if first := plainSend("198.51.100.1"); first == http.StatusTooManyRequests {
		t.Fatalf("control: the first request was already refused (%d)", first)
	}
	if second := plainSend("198.51.100.2"); second != http.StatusTooManyRequests {
		t.Errorf("an undeclared X-Forwarded-For moved the bucket key: second request answered %d, want 429", second)
	}

	// The claim under test: no other header moves it. Two requests, same peer,
	// different value in each header in turn; the second must be refused.
	for _, hdr := range []string{"X-Real-IP", "Forwarded", "X-Client-IP", "CF-Connecting-IP", "X-Forwarded-Host", "X-Forwarded-Proto", "True-Client-IP", "X-Originating-IP", "X-Envoy-External-Address"} {
		p := zzPeer()
		call := func(v string) int {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = p
			req.Header.Set(hdr, v)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code
		}
		if first := call("198.51.100.9"); first == http.StatusTooManyRequests {
			t.Fatalf("%s: first request refused (%d)", hdr, first)
		}
		if second := call("198.51.100.10"); second != http.StatusTooManyRequests {
			t.Errorf("%s moved the bucket key: second request answered %d, want 429", hdr, second)
		}
	}
	t.Logf("only a DECLARED X-Forwarded-For moved the key; 9 other client-address headers did not")
}

// TestV_SpotCheckBodyLimitPerPlane is the spot-check of "probed but not broken"
// item 9: a 413 is rendered in each plane's own shape. It also asks where that
// shape's cache directive went, which is the same question as HE-4.
func TestV_SpotCheckBodyLimitPerPlane(t *testing.T) {
	srv := zzServer(t)
	big := strings.Repeat("x", 100<<10) // over oauth.MaxFormBytes (64 KiB)

	cases := []struct{ target, wantCT string }{
		{"/oauth/token", "application/json"},
		{"/v1/me", "application/problem+json"},
		{"/nope", "text/plain; charset=utf-8"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, c.target, strings.NewReader(big))
		req.RemoteAddr = zzPeer()
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		body := rec.Body.String()
		if len(body) > 90 {
			body = body[:90] + "..."
		}
		t.Logf("POST %-14s -> %d %q Cache-Control=%q body=%s",
			c.target, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"), body)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s with a 100 KiB body = %d, want 413", c.target, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != c.wantCT {
			t.Errorf("POST %s 413 Content-Type = %q, want %q", c.target, got, c.wantCT)
		}
	}
}
