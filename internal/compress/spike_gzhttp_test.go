//go:build gzhttpspike

// SPIKE (experiment, not production): can github.com/klauspost/compress/gzhttp
// replace the hand-written framework in this package while preserving every
// behavior the existing suite pins?
//
// This file is build-tag gated (`gzhttpspike`) so it never joins the default
// suite. It drives the exact scenarios internal/compress/compress_test.go pins
// through three subjects:
//
//	project  — the current Compressor (sanity: must be all-PASS)
//	gzhttp   — gzhttp.NewWrapper with the closest option mapping
//	hybrid   — a thin project wrapper that keeps negotiation + the 406 +
//	           eligibility, then delegates encoding/Vary/ETag/pooling to gzhttp
//
// Run: RE0AUTH_GZHTTP_SPIKE=1 go test -tags gzhttpspike -count=1 -v ./internal/compress/
package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzhttp"
	"github.com/klauspost/compress/zstd"
)

// spikeGate keeps the experiment from being a red suite in its own right: without
// RE0AUTH_GZHTTP_SPIKE=1 this file is a no-op, so `go test -tags gzhttpspike`
// stays green while the measurement is still reproducible on demand. With it set
// the gzhttp and hybrid subjects fail on the behaviors listed in
// docs/dependencies.md §1 — that failure IS the evidence for not switching.
func spikeGate(t *testing.T) {
	t.Helper()
	if os.Getenv("RE0AUTH_GZHTTP_SPIKE") != "1" {
		t.Skip("experiment; set RE0AUTH_GZHTTP_SPIKE=1 to reproduce the gzhttp parity result (recorded in docs/dependencies.md)")
	}
}

// --- fixtures ---------------------------------------------------------------

var (
	spikeJSONBody = []byte("[" + strings.Repeat(`{"score":123456,"song":"x"},`, 200) + `{}]`)
	spikeXBody    = bytes.Repeat([]byte("x"), DefaultMinSize*2)
	spikePNGBody  = bytes.Repeat([]byte{0x89, 'P', 'N', 'G'}, 1000)
)

func spikeDecode(t *testing.T, coding string, body []byte) []byte {
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

type spikeReq struct {
	method string
	target string
	accept string
	extra  map[string]string // "resp-X" keys are response headers
}

type spikeScenario struct {
	name    string
	minSize int // 0 => DefaultMinSize
	req     spikeReq
	ct      string
	body    []byte
	// handler overrides the default handler entirely (204, chunked, ...).
	handler  func(w http.ResponseWriter, r *http.Request)
	eligible func(r *http.Request) bool
	check    func(t *testing.T, rec *httptest.ResponseRecorder)
}

func spikeDefaultHandler(s *spikeScenario) http.Handler {
	if s.handler != nil {
		return http.HandlerFunc(s.handler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ct != "" {
			w.Header().Set("Content-Type", s.ct)
		}
		for k, v := range s.req.extra {
			if strings.HasPrefix(k, "resp-") {
				w.Header().Set(strings.TrimPrefix(k, "resp-"), v)
			}
		}
		if s.body != nil {
			_, _ = w.Write(s.body)
		}
	})
}

func spikeServe(h http.Handler, req spikeReq) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(req.method, req.target, nil)
	if req.accept != "" {
		r.Header.Set("Accept-Encoding", req.accept)
	}
	for k, v := range req.extra {
		if !strings.HasPrefix(k, "resp-") {
			r.Header.Set(k, v)
		}
	}
	h.ServeHTTP(rec, r)
	return rec
}

// --- subjects ---------------------------------------------------------------

// spikeGzhttpWrap is the closest option mapping onto gzhttp v1.19.2.
func spikeGzhttpWrap(minSize int) func(http.Handler) http.Handler {
	w, err := gzhttp.NewWrapper(
		gzhttp.MinSize(minSize),
		gzhttp.EnableGzip(true),
		gzhttp.EnableZstd(true),
		gzhttp.PreferZstd(true),
		// project uses zstd.SpeedDefault; gzhttp defaults to SpeedFastest.
		gzhttp.ZstdCompressionLevel(int(zstd.SpeedDefault)),
		// the project never invents a Content-Type; gzhttp defaults to true.
		gzhttp.SetContentType(false),
		gzhttp.ContentTypeFilter(compressibleContentType),
	)
	if err != nil {
		panic("gzhttp.NewWrapper: " + err.Error())
	}
	return func(next http.Handler) http.Handler { return w(next) }
}

// spikeHybridWrap keeps the project's front half (eligibility, RFC 9110
// negotiation, the 406) and delegates the rest to gzhttp.
func spikeHybridWrap(c *Compressor) func(http.Handler) http.Handler {
	gz := spikeGzhttpWrap(c.minSize)
	return func(next http.Handler) http.Handler {
		gzh := gz(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead || !c.eligible(r) {
				next.ServeHTTP(w, r)
				return
			}
			coding, acceptable := negotiate(r.Header.Get("Accept-Encoding"), c.names)
			if !acceptable {
				addVary(w.Header(), "Accept-Encoding")
				c.notAccept(w, r)
				return
			}
			if coding == "" {
				next.ServeHTTP(w, r)
				return
			}
			// gzhttp re-negotiates from the header itself and has no wildcard,
			// so hand it the coding this wrapper already chose.
			r2 := r.Clone(r.Context())
			r2.Header.Set("Accept-Encoding", coding)
			gzh.ServeHTTP(w, r2)
		})
	}
}

type spikeSubject struct {
	name  string
	build func(t *testing.T, s *spikeScenario) http.Handler
}

func spikeSubjects() []spikeSubject {
	return []spikeSubject{
		{"project", func(t *testing.T, s *spikeScenario) http.Handler {
			cfg := Config{Encodings: Default(), Eligible: s.eligible}
			if s.minSize > 0 {
				cfg.MinSize = s.minSize
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			return c.Handler(spikeDefaultHandler(s))
		}},
		{"gzhttp", func(t *testing.T, s *spikeScenario) http.Handler {
			return spikeGzhttpWrap(spikeMin(s))(spikeDefaultHandler(s))
		}},
		{"hybrid", func(t *testing.T, s *spikeScenario) http.Handler {
			cfg := Config{Encodings: Default(), Eligible: s.eligible}
			if s.minSize > 0 {
				cfg.MinSize = s.minSize
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			return spikeHybridWrap(c)(spikeDefaultHandler(s))
		}},
	}
}

func spikeMin(s *spikeScenario) int {
	if s.minSize > 0 {
		return s.minSize
	}
	return DefaultMinSize
}

// --- checks -----------------------------------------------------------------

func wantCoding(want string) func(*testing.T, *httptest.ResponseRecorder) {
	return func(t *testing.T, rec *httptest.ResponseRecorder) {
		if got := rec.Header().Get("Content-Encoding"); got != want {
			t.Errorf("Content-Encoding = %q, want %q", got, want)
		}
	}
}

func wantVaryContains(token string) func(*testing.T, *httptest.ResponseRecorder) {
	return func(t *testing.T, rec *httptest.ResponseRecorder) {
		if !strings.Contains(strings.Join(rec.Header().Values("Vary"), ", "), token) {
			t.Errorf("Vary = %v, want %s", rec.Header().Values("Vary"), token)
		}
	}
}

func wantVaryAbsent(t *testing.T, rec *httptest.ResponseRecorder) {
	if got := rec.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q, want none", got)
	}
}

// --- the scenario matrix ----------------------------------------------------

func spikeScenarios() []spikeScenario {
	return []spikeScenario{
		{
			name: "no_accept_encoding_is_identity_no_vary",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: ""},
			ct:   "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				wantVaryAbsent(t, rec)
				if !bytes.Equal(rec.Body.Bytes(), spikeXBody) {
					t.Errorf("body changed (%d bytes)", rec.Body.Len())
				}
			},
		},
		{
			name: "compresses_large_body_gzip",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip"},
			ct:   "application/json", body: spikeJSONBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("gzip")(t, rec)
				if got := rec.Header().Get("Content-Length"); got != "" {
					t.Errorf("Content-Length not dropped (%q)", got)
				}
				wantVaryContains("Accept-Encoding")(t, rec)
				if out := spikeDecode(t, "gzip", rec.Body.Bytes()); !bytes.Equal(out, spikeJSONBody) {
					t.Errorf("round trip differs")
				}
				if rec.Body.Len() >= len(spikeJSONBody) {
					t.Errorf("compressed %d not smaller than %d", rec.Body.Len(), len(spikeJSONBody))
				}
			},
		},
		{
			name: "compresses_large_body_zstd",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "zstd"},
			ct:   "application/json", body: spikeJSONBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("zstd")(t, rec)
				if got := rec.Header().Get("Content-Length"); got != "" {
					t.Errorf("Content-Length not dropped (%q)", got)
				}
				wantVaryContains("Accept-Encoding")(t, rec)
				if out := spikeDecode(t, "zstd", rec.Body.Bytes()); !bytes.Equal(out, spikeJSONBody) {
					t.Errorf("round trip differs")
				}
				if rec.Body.Len() >= len(spikeJSONBody) {
					t.Errorf("compressed %d not smaller than %d", rec.Body.Len(), len(spikeJSONBody))
				}
			},
		},
		{
			name: "client_quality_beats_server_preference",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "zstd;q=0.1, gzip;q=1.0"},
			ct:   "application/json", body: bytes.Repeat([]byte("compress me "), 400),
			check: wantCoding("gzip"),
		},
		{
			name:    "below_threshold_identity_but_varies",
			minSize: 1024,
			req:     spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip"},
			ct:      "application/json", body: []byte(`{"small":true}`),
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				wantVaryContains("Accept-Encoding")(t, rec)
				if !bytes.Equal(rec.Body.Bytes(), []byte(`{"small":true}`)) {
					t.Errorf("body changed")
				}
			},
		},
		{
			name: "non_compressible_type_untouched_no_vary",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip, zstd"},
			ct:   "image/png", body: spikePNGBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				wantVaryAbsent(t, rec)
				if !bytes.Equal(rec.Body.Bytes(), spikePNGBody) {
					t.Errorf("body changed")
				}
			},
		},
		{
			name: "already_encoded_not_double_encoded",
			req: spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip",
				extra: map[string]string{"resp-Content-Encoding": "gzip"}},
			ct: "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("gzip")(t, rec)
				if !bytes.Equal(rec.Body.Bytes(), spikeXBody) {
					t.Errorf("body was re-encoded")
				}
			},
		},
		{
			// gzhttp has no eligibility predicate; the closest mapping is "always
			// eligible", so this documents the missing capability.
			name: "eligible_predicate_denies_route",
			req:  spikeReq{method: http.MethodPost, target: "/oauth/token", accept: "gzip, zstd"},
			ct:   "application/json", body: spikeXBody,
			eligible: func(r *http.Request) bool {
				return !strings.HasPrefix(r.URL.Path, "/oauth/")
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				if !bytes.Equal(rec.Body.Bytes(), spikeXBody) {
					t.Errorf("body changed on a denied route")
				}
			},
		},
		{
			name: "not_acceptable_406_when_identity_forbidden",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "br;q=1, identity;q=0"},
			ct:   "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusNotAcceptable {
					t.Errorf("status = %d, want 406", rec.Code)
				}
				wantVaryContains("Accept-Encoding")(t, rec)
				if !strings.Contains(rec.Body.String(), "not_acceptable") {
					t.Errorf("body = %q", rec.Body.String())
				}
			},
		},
		{
			name: "head_bypasses_and_has_no_vary",
			req:  spikeReq{method: http.MethodHead, target: "/v1/thing", accept: "gzip"},
			ct:   "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				wantVaryAbsent(t, rec)
			},
		},
		{
			name: "no_content_204_bypass",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNoContent)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				if rec.Code != http.StatusNoContent {
					t.Errorf("status = %d, want 204", rec.Code)
				}
			},
		},
		{
			name: "content_range_bypass",
			req: spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip",
				extra: map[string]string{"resp-Content-Range": "bytes 0-9/10"}},
			ct: "application/json", body: spikeXBody,
			check: wantCoding(""),
		},
		{
			name: "no_transform_bypass",
			req: spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip",
				extra: map[string]string{"resp-Cache-Control": "public, no-transform"}},
			ct: "application/json", body: spikeXBody,
			check: wantCoding(""),
		},
		{
			name: "etag_weakened_when_compressed",
			req: spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip",
				extra: map[string]string{"resp-ETag": `"abc123"`}},
			ct: "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if got := rec.Header().Get("ETag"); got != `W/"abc123"` {
					t.Errorf("ETag = %q, want weakened W/\"abc123\"", got)
				}
			},
		},
		{
			name: "vary_merged_not_duplicated",
			req: spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip",
				extra: map[string]string{"resp-Vary": "Origin"}},
			ct: "application/json", body: spikeXBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				joined := strings.Join(rec.Header().Values("Vary"), ", ")
				if !strings.Contains(joined, "Origin") || !strings.Contains(joined, "Accept-Encoding") {
					t.Errorf("Vary = %v, want Origin and Accept-Encoding", rec.Header().Values("Vary"))
				}
			},
		},
		{
			name: "wildcard_star_selects_server_preference",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "*"},
			ct:   "application/json", body: spikeJSONBody,
			check: wantCoding("zstd"),
		},
		{
			name: "gzip_refused_wildcard_allows_zstd",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip;q=0, *;q=1"},
			ct:   "application/json", body: spikeJSONBody,
			check: wantCoding("zstd"),
		},
		{
			name: "identity_and_wildcard_refused_is_406",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "*;q=0"},
			ct:   "application/json", body: spikeJSONBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusNotAcceptable {
					t.Errorf("status = %d, want 406", rec.Code)
				}
			},
		},
		{
			name: "gzip_refused_only_is_identity_no_vary",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip;q=0"},
			ct:   "application/json", body: spikeJSONBody,
			check: func(t *testing.T, rec *httptest.ResponseRecorder) {
				wantCoding("")(t, rec)
				wantVaryAbsent(t, rec)
			},
		},
		{
			name: "case_insensitive_and_whitespace",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "  GZIP  ,  ZSTD "},
			ct:   "application/json", body: spikeJSONBody,
			check: wantCoding("zstd"),
		},
		{
			name: "malformed_q_is_zero_for_that_coding",
			req:  spikeReq{method: http.MethodGet, target: "/v1/thing", accept: "gzip;q=abc, zstd"},
			ct:   "application/json", body: spikeJSONBody,
			check: wantCoding("zstd"),
		},
	}
}

func TestSpikeScenarioMatrix(t *testing.T) {
	spikeGate(t)
	subjects := spikeSubjects()
	for _, s := range spikeScenarios() {
		for _, sub := range subjects {
			t.Run(s.name+"/"+sub.name, func(t *testing.T) {
				h := sub.build(t, &s)
				rec := spikeServe(h, s.req)
				s.check(t, rec)
			})
		}
	}
}

// --- standalone scenarios that need more than one request -------------------

func TestSpikePoolReuseRoundTrips(t *testing.T) {
	spikeGate(t)
	body := bytes.Repeat([]byte(`{"score":123456},`), 200)
	for _, sub := range spikeSubjects() {
		sub := sub
		t.Run(sub.name, func(t *testing.T) {
			s := &spikeScenario{ct: "application/json", body: body}
			h := sub.build(t, s)
			for i := 0; i < 50; i++ {
				coding := "gzip"
				if i%2 == 0 {
					coding = "zstd"
				}
				rec := spikeServe(h, spikeReq{method: http.MethodGet, target: "/v1/thing", accept: coding})
				if got := rec.Header().Get("Content-Encoding"); got != coding {
					t.Fatalf("iteration %d: Content-Encoding = %q, want %q", i, got, coding)
				}
				if out := spikeDecode(t, coding, rec.Body.Bytes()); !bytes.Equal(out, body) {
					t.Fatalf("iteration %d: round trip differs", i)
				}
			}
		})
	}
}

func TestSpikeFlushStartsCompressing(t *testing.T) {
	spikeGate(t)
	for _, sub := range spikeSubjects() {
		sub := sub
		t.Run(sub.name, func(t *testing.T) {
			s := &spikeScenario{
				minSize: 1 << 20,
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"first":`))
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(`"value"}`))
				},
			}
			h := sub.build(t, s)
			rec := spikeServe(h, spikeReq{method: http.MethodGet, target: "/v1/stream", accept: "zstd"})
			if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
				t.Fatalf("Content-Encoding = %q, want zstd (Flush must commit)", got)
			}
			if out := spikeDecode(t, "zstd", rec.Body.Bytes()); string(out) != `{"first":"value"}` {
				t.Fatalf("body = %q", out)
			}
		})
	}
}

func TestSpikeSingleLargeWriteMatchesChunkedWrites(t *testing.T) {
	spikeGate(t)
	body := []byte("[" + strings.Repeat(`{"score":123456,"song":"x"},`, 500) + `{}]`)
	if len(body) < DefaultMinSize*4 {
		t.Fatalf("fixture too small: %d", len(body))
	}
	for _, sub := range spikeSubjects() {
		sub := sub
		t.Run(sub.name, func(t *testing.T) {
			one := sub.build(t, &spikeScenario{ct: "application/json", body: body})
			chunked := sub.build(t, &spikeScenario{
				ct:   "application/json",
				body: body,
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					for i := 0; i < len(body); i += DefaultMinSize / 4 {
						end := i + DefaultMinSize/4
						if end > len(body) {
							end = len(body)
						}
						if _, err := w.Write(body[i:end]); err != nil {
							t.Errorf("chunked write: %v", err)
							return
						}
					}
				},
			})
			for _, coding := range []string{"gzip", "zstd"} {
				r1 := spikeServe(one, spikeReq{method: http.MethodGet, target: "/v1/thing", accept: coding})
				r2 := spikeServe(chunked, spikeReq{method: http.MethodGet, target: "/v1/thing", accept: coding})
				if got := r1.Header().Get("Content-Encoding"); got != coding {
					t.Errorf("%s: single-write Content-Encoding = %q", coding, got)
				}
				if got := r2.Header().Get("Content-Encoding"); got != coding {
					t.Errorf("%s: chunked Content-Encoding = %q", coding, got)
				}
				if !bytes.Equal(r1.Body.Bytes(), r2.Body.Bytes()) {
					t.Errorf("%s: single large write and chunked writes differ (%d vs %d bytes)",
						coding, r1.Body.Len(), r2.Body.Len())
				}
				if out := spikeDecode(t, coding, r1.Body.Bytes()); !bytes.Equal(out, body) {
					t.Errorf("%s: single-write round trip differs", coding)
				}
			}
		})
	}
}
