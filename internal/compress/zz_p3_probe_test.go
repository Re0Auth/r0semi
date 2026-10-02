package compress

// P3-low probes for the compression middleware: S10-3 and Z15-4. S13-6's probe
// lives in zz_audit9_1xx_status_test.go, which it flips.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// --- S10-3: a handler panic must not strand the pooled encoder

// countingWriteCloser counts Close calls, so a probe can tell that an encoder went
// back to its pool. Close is the release seam, so a writer that is never closed was
// never pooled either.
type countingWriteCloser struct {
	WriteCloser
	closes *atomic.Int32
}

func (w *countingWriteCloser) Close() error {
	w.closes.Add(1)
	return w.WriteCloser.Close()
}

func countingEncoding(t *testing.T, closes *atomic.Int32) Encoding {
	t.Helper()
	return Encoding{
		Name: "counting",
		New: func() WriteCloser {
			gz, err := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			if err != nil {
				t.Fatalf("gzip: %v", err)
			}
			return &countingWriteCloser{WriteCloser: gz, closes: closes}
		},
	}
}

// TestCompressionWriterIsReleasedWhenTheHandlerPanics pins that an encoder acquired
// before a panic is closed and returned to the pool. Handler called finish() on the
// normal return path only, so a panic past startCompress left the writer checked out
// forever: every such panic allocated a fresh encoder and the pool never held one
// again (S10-3).
func TestCompressionWriterIsReleasedWhenTheHandlerPanics(t *testing.T) {
	var closes atomic.Int32
	c := newTestCompressor(t, Config{Encodings: []Encoding{countingEncoding(t, &closes)}, MinSize: 1})
	// New() probes the constructor once and closes that probe; measure the request.
	closes.Store(0)

	body := bytes.Repeat([]byte("x"), DefaultMinSize)
	h := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			t.Errorf("Write: %v", err)
		}
		panic("handler blew up after compression started")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "counting")
	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Fatal("the handler's panic did not propagate out of the middleware")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()

	if got := closes.Load(); got != 1 {
		t.Fatalf("encoder Close calls after a panic = %d, want 1: the pooled writer was never "+
			"closed or returned to the pool (S10-3)", got)
	}
}

// TestPanicBeforeCompressionLeavesTheErrorResponseAlone is the control: a panic that
// never started compressing must not make the middleware write a header or a body,
// because the recoverer outside it owns the error response.
func TestPanicBeforeCompressionLeavesTheErrorResponseAlone(t *testing.T) {
	var closes atomic.Int32
	c := newTestCompressor(t, Config{Encodings: []Encoding{countingEncoding(t, &closes)}, MinSize: DefaultMinSize})
	closes.Store(0)

	h := c.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler blew up before any write")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "counting")
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(rec, req)
	}()

	if rec.Body.Len() != 0 {
		t.Errorf("the middleware wrote %d bytes on the panic path: %q", rec.Body.Len(), rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q on the panic path, want none", got)
	}
	if got := closes.Load(); got != 0 {
		t.Errorf("an encoder was acquired and closed for a response that never compressed (%d closes)", got)
	}
}

// --- Z15-4: the negotiate fast path must split the header once

// TestNegotiateFastPathDoesNotRescanTheHeaderPerCoding pins that the fast path's
// allocation does not grow with the number of configured codings. It re-split the
// header inside a per-coding closure (compress.go:180-193), so a negotiation cost
// one []string per coding the server offers.
func TestNegotiateFastPathDoesNotRescanTheHeaderPerCoding(t *testing.T) {
	const runs = 200
	header := "gzip" // no ";" and no "*", so the fast path is taken
	one := []string{"br"}
	many := make([]string, 64)
	for i := range many {
		many[i] = fmt.Sprintf("coding%02d", i)
	}

	small := testing.AllocsPerRun(runs, func() { negotiate(header, one) })
	large := testing.AllocsPerRun(runs, func() { negotiate(header, many) })
	if large > small {
		t.Fatalf("negotiate allocated %.0f times with 64 configured codings and %.0f with 1: the "+
			"header is split once per configured coding, so negotiation's cost grows with the "+
			"server's configuration (Z15-4)", large, small)
	}
}
