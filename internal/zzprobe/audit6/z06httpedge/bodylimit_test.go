//go:build audit6

// Request-body limit probes for zone 06 (round 6): the 413 coverage matrix
// (which planes, which shapes, which cache directives), a lying Content-Length,
// chunked bodies with no length, and a gzip-encoded request body (nothing in
// this service decompresses request bodies, so the cap is on the compressed
// bytes — the probe proves that with a decompression bomb that never
// decompresses anywhere).
package z06httpedge

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// realOPServer builds a server around the real OpenID Provider, so the
// body-limit probes observe the provider's own parsing rather than a stub's
// 200.
func realOPServer(t *testing.T) http.Handler {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	op, _ := newRealOP(t, clients)
	return edgeServer(t, func(c *httpapi.Config) { c.OIDC = op }).Handler()
}

// TestZ06BodyLimit413MatrixPerPlane: the cap is declared over the whole tree by
// httpapi's withBodyLimit, so every plane must refuse an oversized declared
// body in its own shape, with no-store on the two API planes.
func TestZ06BodyLimit413MatrixPerPlane(t *testing.T) {
	h := realOPServer(t)
	big := strings.Repeat("x", oauth.MaxFormBytes+1)

	cases := []struct {
		method, target string
		plane          string
	}{
		{http.MethodPost, "/oauth/token", "protocol"},
		{http.MethodPost, "/v1/device/decision", "business"},
		{http.MethodPost, "/auth/github/start", "browser"},
		{http.MethodPost, "/nope", "browser"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(big))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s %s with an oversized body = %d, want 413", tc.method, tc.target, rec.Code)
			}
			switch tc.plane {
			case "protocol", "business":
				if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
					t.Errorf("%s 413 Cache-Control = %q, want no-store", tc.plane, cc)
				}
			}
			assertPlaneShape(t, tc.plane, rec)
		})
	}
}

// TestZ06BodyLimitSurvivesALyingContentLength: the declared length is under the
// cap but the actual body is far over it. The read-side cap (MaxBytesReader)
// must stop the parse, and the handler must answer in its own terms — not 500,
// not a hang.
func TestZ06BodyLimitSurvivesALyingContentLength(t *testing.T) {
	h := realOPServer(t)

	// 1 declared, sent 100 KiB: the reader must cut it off.
	body := strings.NewReader(strings.Repeat("grant_type=x&", 9000))
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.ContentLength = 1 // the lie
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("lying Content-Length = %d, want a 4xx, not a server error: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("lying Content-Length = %d, want the handler's 400 (parameters could not be parsed): %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("protocol-plane refusal Cache-Control = %q, want no-store", cc)
	}
	assertPlaneShape(t, "protocol", rec)
}

// TestZ06BodyLimitHandlesChunkedAndGzipBodies: a chunked body declares no
// length, so the cap is enforced while reading; a gzip-encoded request body is
// never decompressed by this service, so a decompression bomb stays the bytes
// on the wire — bounded by the same cap — and cannot become memory.
func TestZ06BodyLimitHandlesChunkedAndGzipBodies(t *testing.T) {
	h := realOPServer(t)

	t.Run("chunked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader(strings.Repeat("x", oauth.MaxFormBytes+1)))
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("chunked oversized request = %d, want 400 from the parse failing mid-body: %s", rec.Code, rec.Body.String())
		}
		assertPlaneShape(t, "protocol", rec)
	})

	t.Run("gzip bomb", func(t *testing.T) {
		// ~64 KiB of a highly compressible payload, well inside the cap once
		// gzipped, that would expand to gigabytes if anything decompressed it.
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(bytes.Repeat([]byte("A"), 64<<10)); err != nil { // 64 KiB of zeros expands ~1000x
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if buf.Len() > oauth.MaxFormBytes {
			t.Fatalf("test bug: the gzipped bomb is %d bytes, over the cap; shrink the payload", buf.Len())
		}

		req := httptest.NewRequest(http.MethodPost, "/oauth/token", &buf)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("gzip-encoded body = %d, want a 4xx (nobody decompresses it): %s", rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("gzip-encoded body = %d, want the handler's 400: %s", rec.Code, rec.Body.String())
		}
		assertPlaneShape(t, "protocol", rec)

		// The same bomb against the business plane's JSON body.
		req2 := httptest.NewRequest(http.MethodPost, "/v1/device/decision",
			io.NopCloser(bytes.NewReader(buf.Bytes())))
		req2.ContentLength = int64(buf.Len())
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("Content-Encoding", "gzip")
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, req2)
		if rec2.Code >= 500 {
			t.Fatalf("gzip-encoded JSON body = %d, want a 4xx: %s", rec2.Code, rec2.Body.String())
		}
	})
}

// TestZ06BodyLimitIsInsideTheRateLimiter: a refused body must not spend a
// rate-limit token (shedding is cheaper than reading). The order is pinned by
// the composition: withBodyLimit runs inside withRateLimit.
func TestZ06BodyLimitIsInsideTheRateLimiter(t *testing.T) {
	h := edgeServer(t, func(c *httpapi.Config) {
		c.Limiter = ratelimit.New(noRefill, 1)
	}).Handler()

	peer := "203.0.113.7:5555"
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader(strings.Repeat("x", oauth.MaxFormBytes+1)))
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Each oversized POST is refused by the body limit only after the limiter
	// admitted it — so the SECOND request is the limiter's own refusal.
	if rec := post(); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("first oversized POST = %d, want 413", rec.Code)
	}
	if rec := post(); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second oversized POST = %d, want 429 (the body limit is inside the limiter, so it spent the token)", rec.Code)
	}
}
