package httpapi

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/klauspost/compress/zstd"

	"github.com/Re0Auth/r0semi/internal/webui"
)

// Compression is wired at the server level, not just available as a package:
// a real eligible response is negotiated and encoded, and the protocol plane is
// left alone.
func TestResponseCompressionIsWired(t *testing.T) {
	big := "<!doctype html><html><body>" + strings.Repeat("<p>hello</p>", 400) + "</body></html>"
	srv := withFrontend(t, fstest.MapFS{"index.html": {Data: []byte(big)}})
	h := srv.Handler()

	// Server preference: zstd when both are acceptable.
	req := httptest.NewRequest(http.MethodGet, webui.BasePath+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip, zstd")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q", rec.Header().Get("Vary"))
	}
	d, err := zstd.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("zstd: %v", err)
	}
	defer d.Close()
	out, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("zstd read: %v", err)
	}
	if string(out) != big {
		t.Fatalf("decompressed body differs (%d vs %d bytes)", len(out), len(big))
	}

	// gzip for a client that only understands gzip.
	req = httptest.NewRequest(http.MethodGet, webui.BasePath+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	gr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gr.Close()
	if out, _ := io.ReadAll(gr); string(out) != big {
		t.Fatalf("gzip round trip differs")
	}
}

// The token endpoint must never be transformed: it carries secrets and is
// no-store, which is exactly the BREACH shape. The eligibility predicate keeps
// the whole protocol plane out.
func TestProtocolPlaneIsNotCompressed(t *testing.T) {
	srv := newTestEnv(t).srv
	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=bogus&client_id=cli"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Encoding", "zstd, gzip")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none on the protocol plane", got)
	}
	if got := rec.Header().Get("Vary"); strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want no Accept-Encoding on the protocol plane", got)
	}
}
