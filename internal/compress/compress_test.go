package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func newTestCompressor(t *testing.T, cfg Config) *Compressor {
	t.Helper()
	if cfg.Encodings == nil {
		cfg.Encodings = Default()
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serve runs one request through the middleware. accept is the raw
// Accept-Encoding value; an empty string means the header is absent.
func serve(c *Compressor, method, target, accept, contentType string, extra map[string]string, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		for k, v := range extra {
			if strings.HasPrefix(k, "resp-") {
				w.Header().Set(strings.TrimPrefix(k, "resp-"), v)
			}
		}
		if body != nil {
			_, _ = w.Write(body)
		}
	})).ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, coding string, body []byte) []byte {
	t.Helper()
	switch coding {
	case "":
		return body
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("gzip read: %v", err)
		}
		return out
	case "zstd":
		d, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("zstd reader: %v", err)
		}
		defer d.Close()
		out, err := io.ReadAll(d)
		if err != nil {
			t.Fatalf("zstd read: %v", err)
		}
		return out
	default:
		t.Fatalf("unknown coding %q", coding)
		return nil
	}
}

func TestNegotiate(t *testing.T) {
	pref := []string{"zstd", "gzip"}
	cases := []struct {
		header     string
		wantCoding string
		wantOK     bool
	}{
		{"", "", true},                         // absent: identity
		{"gzip", "gzip", true},                 // explicit
		{"zstd", "zstd", true},                 // explicit
		{"gzip, zstd", "zstd", true},           // equal q: server preference
		{"zstd, gzip", "zstd", true},           // order of listing does not matter
		{"gzip;q=1, zstd;q=0.5", "gzip", true}, // client q wins
		{"zstd;q=0.5, gzip;q=1", "gzip", true},
		{"*", "zstd", true},                 // wildcard: server preference
		{"gzip;q=0, *;q=1", "zstd", true},   // gzip refused, wildcard allows zstd
		{"identity", "", true},              // only identity
		{"gzip;q=0", "", true},              // gzip refused, identity implied
		{"br", "", true},                    // unsupported, identity implied
		{"identity;q=0", "", false},         // nothing acceptable
		{"*;q=0", "", false},                // refuse everything including identity
		{"br;q=1, identity;q=0", "", false}, // unsupported coding + identity refused
		{"gzip;q=0.001", "gzip", true},      // tiny but positive
		{"gzip;q=0.0", "", true},            // zero means refused
	}
	for _, tc := range cases {
		coding, ok := negotiate(tc.header, pref)
		if coding != tc.wantCoding || ok != tc.wantOK {
			t.Errorf("negotiate(%q) = (%q, %v), want (%q, %v)", tc.header, coding, ok, tc.wantCoding, tc.wantOK)
		}
	}
}

func TestNoAcceptEncodingIsIdentity(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodGet, "/v1/thing", "", "application/json", nil, body)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if got := rec.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want none (nothing can vary)", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatal("body changed")
	}
}

func TestCompressesLargeBody(t *testing.T) {
	c := newTestCompressor(t, Config{})
	// Compressible-looking JSON, repeated so the coding has something to do.
	body := []byte("[" + strings.Repeat(`{"score":123456,"song":"x"},`, 200) + `{}]`)

	for _, coding := range []string{"gzip", "zstd"} {
		rec := serve(c, http.MethodGet, "/v1/thing", coding, "application/json", nil, body)
		if got := rec.Header().Get("Content-Encoding"); got != coding {
			t.Fatalf("%s: Content-Encoding = %q", coding, got)
		}
		if got := rec.Header().Get("Content-Length"); got != "" {
			t.Errorf("%s: Content-Length was not dropped (%q)", coding, got)
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: missing Vary: Accept-Encoding (%q)", coding, rec.Header().Get("Vary"))
		}
		out := decode(t, coding, rec.Body.Bytes())
		if !bytes.Equal(out, body) {
			t.Fatalf("%s: round trip differs", coding)
		}
		if len(rec.Body.Bytes()) >= len(body) {
			t.Errorf("%s: compressed size %d not smaller than %d", coding, rec.Body.Bytes(), len(body))
		}
	}
}

func TestClientQualityBeatsServerPreference(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("compress me "), 400)
	rec := serve(c, http.MethodGet, "/v1/thing", "zstd;q=0.1, gzip;q=1.0", "application/json", nil, body)
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}

func TestBelowThresholdIsIdentityButVaries(t *testing.T) {
	c := newTestCompressor(t, Config{MinSize: 1024})
	body := []byte(`{"small":true}`)
	rec := serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json", nil, body)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none below threshold", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding (a larger body would be compressed)", rec.Header().Get("Vary"))
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatal("body changed")
	}
}

func TestNonCompressibleTypeIsUntouched(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte{0x89, 'P', 'N', 'G'}, 1000)
	rec := serve(c, http.MethodGet, "/v1/thing", "gzip, zstd", "image/png", nil, body)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if got := rec.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want none (this type is never compressed)", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatal("body changed")
	}
}

func TestAlreadyEncodedIsNotDoubleEncoded(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json", map[string]string{"resp-Content-Encoding": "gzip"}, body)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want the handler's gzip", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatal("body was re-encoded")
	}
}

func TestEligiblePredicateDeniesRoute(t *testing.T) {
	c := newTestCompressor(t, Config{
		Eligible: func(r *http.Request) bool { return !strings.HasPrefix(r.URL.Path, "/oauth/") },
	})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodPost, "/oauth/token", "gzip, zstd", "application/json", nil, body)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none on a denied route", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatal("body changed on a denied route")
	}
}

func TestNotAcceptableWhenIdentityForbidden(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodGet, "/v1/thing", "br;q=1, identity;q=0", "application/json", nil, body)

	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want 406", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", rec.Header().Get("Vary"))
	}
	if !strings.Contains(rec.Body.String(), "not_acceptable") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestHeadAndNoContentBypass(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)

	rec := serve(c, http.MethodHead, "/v1/thing", "gzip", "application/json", nil, body)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("HEAD: Content-Encoding = %q", got)
	}

	// A 204 handler: no body, and the middleware must not wrap it.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("204: Content-Encoding = %q", got)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("204: status = %d", rec.Code)
	}
}

func TestContentRangeAndNoTransformBypass(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)

	rec := serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json",
		map[string]string{"resp-Content-Range": "bytes 0-9/10"}, body)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Range: Content-Encoding = %q", got)
	}

	rec = serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json",
		map[string]string{"resp-Cache-Control": "public, no-transform"}, body)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("no-transform: Content-Encoding = %q", got)
	}
}

func TestETagIsWeakenedWhenCompressed(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json",
		map[string]string{"resp-ETag": `"abc123"`}, body)
	if got := rec.Header().Get("ETag"); got != `W/"abc123"` {
		t.Fatalf("ETag = %q, want weakened", got)
	}
}

func TestVaryIsMergedNotDuplicated(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)
	rec := serve(c, http.MethodGet, "/v1/thing", "gzip", "application/json",
		map[string]string{"resp-Vary": "Origin"}, body)

	values := rec.Header().Values("Vary")
	joined := strings.Join(values, ", ")
	if !strings.Contains(joined, "Origin") || !strings.Contains(joined, "Accept-Encoding") {
		t.Fatalf("Vary = %v, want Origin and Accept-Encoding", values)
	}
}

// The pool must hand back writers that still work: reusing a closed gzip/zstd
// writer without a proper Reset is a classic source of truncated output.
func TestPoolReuseRoundTrips(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte(`{"score":123456},`), 200)

	for i := 0; i < 50; i++ {
		coding := "gzip"
		if i%2 == 0 {
			coding = "zstd"
		}
		rec := serve(c, http.MethodGet, "/v1/thing", coding, "application/json", nil, body)
		if got := rec.Header().Get("Content-Encoding"); got != coding {
			t.Fatalf("iteration %d: Content-Encoding = %q", i, got)
		}
		if out := decode(t, coding, rec.Body.Bytes()); !bytes.Equal(out, body) {
			t.Fatalf("iteration %d: round trip differs", i)
		}
	}
}

func TestFlushStartsCompressing(t *testing.T) {
	c := newTestCompressor(t, Config{MinSize: 1 << 20}) // high threshold: only Flush can trigger
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/stream", nil)
	req.Header.Set("Accept-Encoding", "zstd")

	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"first":`))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte(`"value"}`))
	})).ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd (Flush must commit)", got)
	}
	if out := decode(t, "zstd", rec.Body.Bytes()); string(out) != `{"first":"value"}` {
		t.Fatalf("body = %q", out)
	}
}
