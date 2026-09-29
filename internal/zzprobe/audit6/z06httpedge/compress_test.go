//go:build audit6

// Response-compression probes for zone 06 (round 6): negotiation (q-values,
// wildcard, malformed q, case, server preference vs client preference), Vary
// management, the interaction with no-store and already-encoded bodies, and the
// per-plane 406 shape. The fixtures mount a frontend with a big compressible
// document, because that is the one eligible, compressible surface every
// deployment has.
package z06httpedge

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/klauspost/compress/zstd"
)

// bigHTML is an eligible, compressible body well over the 1 KiB threshold.
var bigHTML = "<!doctype html><html><body>" + strings.Repeat("<p>hello</p>", 400) + "</body></html>"

// withFrontend mounts a served frontend on the probe server.
func withFrontendServer(t *testing.T, tweak func(*httpapi.Config)) http.Handler {
	t.Helper()
	cfg := edgeConfig()
	if tweak != nil {
		tweak(&cfg)
	}
	cfg.Frontend = fstest.MapFS{
		"index.html": {Data: []byte(bigHTML)},
		"small.txt":  {Data: []byte("a small text file, under the compression threshold")},
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return srv.Handler()
}

// get fetches a path with the given Accept-Encoding through the handler.
func fetch(t *testing.T, h http.Handler, target, acceptEncoding string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	out, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return out
}

func unzstd(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("zstd read: %v", err)
	}
	return out
}

// TestZ06NegotiationMatrix walks the Accept-Encoding shapes the RFC allows and
// the shapes an attacker can type. The rule under test: the client's q-value
// wins over the server's preference, the wildcard is honored, a refusal of
// every coding plus identity is a 406 in the caller's plane, and nothing is
// ever double-encoded.
func TestZ06NegotiationMatrix(t *testing.T) {
	h := withFrontendServer(t, nil)

	cases := []struct {
		name    string
		ae      string
		wantEnc string // "" for identity
	}{
		{"no header", "", ""},
		{"gzip only", "gzip", "gzip"},
		{"zstd only", "zstd", "zstd"},
		{"both, server prefers zstd", "gzip, zstd", "zstd"},
		{"both, client prefers gzip", "gzip;q=1.0, zstd;q=0.5", "gzip"},
		{"both, client prefers zstd", "zstd;q=1.0, gzip;q=0.5", "zstd"},
		{"case-insensitive names", "GZIP", "gzip"},
		{"whitespace", "  gzip  ,  zstd ", "zstd"},
		{"gzip refused", "gzip;q=0", ""},
		{"gzip refused but zstd kept", "gzip;q=0, zstd", "zstd"},
		{"wildcard allows zstd", "*, identity;q=0", "zstd"},
		{"wildstar refused with identity refused", "*;q=0, identity;q=0", "\x00406"},
		{"identity refused alone", "identity;q=0", "\x00406"},
		{"malformed q is zero for that coding", "gzip;q=abc, zstd", "zstd"},
		{"q above 1 clamps", "gzip;q=9", "gzip"},
		{"q below 0 clamps", "gzip;q=-1, zstd", "zstd"},
		{"unknown codings ignored", "br, gzip", "gzip"},
		{"unknown coding only", "br", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := fetch(t, h, webui.BasePath+"/", tc.ae)
			if tc.wantEnc == "\x00406" {
				if rec.Code != http.StatusNotAcceptable {
					t.Fatalf("Accept-Encoding %q = %d, want 406", tc.ae, rec.Code)
				}
				// The app shell is browser plane: text, not problem+json.
				if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "problem+json") {
					t.Fatalf("browser-plane 406 answered problem+json: %q", ct)
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("Accept-Encoding %q = %d: %s", tc.ae, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Encoding"); got != tc.wantEnc {
				t.Fatalf("Accept-Encoding %q: Content-Encoding = %q, want %q", tc.ae, got, tc.wantEnc)
			}
			// Whatever coding was chosen, the body must decode back to the document.
			var body []byte
			switch rec.Header().Get("Content-Encoding") {
			case "gzip":
				body = gunzip(t, rec.Body.Bytes())
			case "zstd":
				body = unzstd(t, rec.Body.Bytes())
			default:
				body = rec.Body.Bytes()
			}
			if string(body) != bigHTML {
				t.Fatalf("decoded body differs (%d bytes)", len(body))
			}
		})
	}
}

// TestZ06VaryMatrix: a compressible response must carry Vary: Accept-Encoding
// the moment it is negotiated; an ineligible route (the protocol plane) must
// carry none; a HEAD response must pass through untouched.
func TestZ06VaryMatrix(t *testing.T) {
	h := withFrontendServer(t, nil)

	t.Run("compressed carries vary", func(t *testing.T) {
		rec := fetch(t, h, webui.BasePath+"/", "gzip")
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Fatalf("Vary = %q, want Accept-Encoding on a compressed response", rec.Header().Get("Vary"))
		}
	})
	t.Run("below threshold still varies", func(t *testing.T) {
		// A small text file: under the 1 KiB threshold, so it is not
		// compressed — but its representation could be, so Vary is still
		// required on a compressible type.
		req := httptest.NewRequest(http.MethodGet, webui.BasePath+"/small.txt", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("small.txt = %d", rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("a small body was compressed: %q", got)
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Fatalf("a compressible-type response below the threshold carries no Vary: %q", rec.Header().Get("Vary"))
		}
	})
	t.Run("protocol plane never compressed nor varied", func(t *testing.T) {
		rec := fetch(t, h, "/.well-known/openid-configuration", "gzip")
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("protocol plane was compressed: %q", got)
		}
		if strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Fatalf("protocol plane carries Vary: Accept-Encoding: %q", rec.Header().Get("Vary"))
		}
	})
	t.Run("HEAD passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, webui.BasePath+"/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("HEAD was compressed: %q", got)
		}
		if strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Fatalf("HEAD carries Vary: Accept-Encoding — the representation cannot vary for a HEAD")
		}
	})
}

// TestZ06BusinessPlaneNoStoreSurvivesCompression: the business plane's
// no-store and compression must coexist — no-store on a problem+json refusal
// and on a compressed 200 alike. A cache directive is about storage, a content
// coding is about the wire; losing either one is a finding.
func TestZ06BusinessPlaneNoStoreSurvivesCompression(t *testing.T) {
	h := withFrontendServer(t, nil)

	rec := fetch(t, h, "/v1/me", "gzip")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/me = %d, want 401", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("/v1/me 401 Cache-Control = %q, want no-store", cc)
	}
	// The 401 body is under the compression threshold, so it must be verbatim.
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("a small problem body was compressed: %q", got)
	}
	// A 406 on the business plane keeps no-store and its own shape.
	rec = fetch(t, h, "/v1/me", "identity;q=0, *;q=0")
	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("/v1/me with everything refused = %d, want 406", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("business 406 Content-Type = %q, want problem+json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("business 406 Cache-Control = %q, want no-store", cc)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Errorf("the 406 carries no Vary: Accept-Encoding, though its shape depends on the header")
	}
}

// TestZ06AlreadyEncodedBodyIsNotRecompressed pins the CPU-amplification guard:
// a handler that already set Content-Encoding must never be compressed again.
// The reachable instance in production is the raw passthrough: a source that
// answers application/json with its own Content-Encoding. The double-encoded
// bytes would be unusable to every client, and the CPU spent re-compressing
// them is pure amplification.
func TestZ06AlreadyEncodedBodyIsNotRecompressed(t *testing.T) {
	var gzipped bytes.Buffer
	zw := gzip.NewWriter(&gzipped)
	payload := []byte(strings.Repeat(`{"k":"v"}`, 400))
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := gzipped.Bytes()

	h, token, _ := rawEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/games/phigros/sources/src/raw/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want the source's own gzip, not a second layer", got)
	}
	// One decompression must yield the source's payload. If the proxy had
	// re-compressed the already-gzipped body, one decompression would yield
	// the gzipped bytes instead.
	out := gunzip(t, rec.Body.Bytes())
	if !bytes.Equal(out, payload) {
		t.Fatalf("the body was double-encoded: %d bytes after one decompression, want the %d-byte payload", len(out), len(payload))
	}
}

// TestZ06CompressionRefusalOnEachPlane pins that the 406 the compressor writes
// alone (before any handler) is in the caller's plane's shape.
func TestZ06CompressionRefusalOnEachPlane(t *testing.T) {
	h := withFrontendServer(t, nil)
	cases := []struct {
		target string
		plane  string
	}{
		{"/v1/me", "business"},
		{"/consent", "browser"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			rec := fetch(t, h, tc.target, "identity;q=0, *;q=0")
			if rec.Code != http.StatusNotAcceptable {
				t.Fatalf("%s = %d, want 406", tc.target, rec.Code)
			}
			assertPlaneShape(t, tc.plane, rec)
		})
	}
}
