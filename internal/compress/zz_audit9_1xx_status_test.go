package compress

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AUDIT9 / S13-6 (fixed) — an informational 1xx must not latch the response state.
//
// A handler may send 103 Early Hints (or 100/102) and then the real status. The
// response already had its status set on the FIRST WriteHeader whatever the code,
// so a 1xx latched: the final WriteHeader was swallowed, the recorded status stayed
// 103 and the "skip compression" decision was taken from it. A final 204 or 304
// therefore never reached the client at all.
//
// The probe drives the middleware with a writer that models net/http's own
// behaviour — a 1xx is sent without committing the response, and the first real
// status is the one the client sees — and requires the final 204 to arrive.

// infoAwareRecorder models net/http's 1xx handling. httptest.ResponseRecorder
// cannot: it latches the first WriteHeader, informational or not, so a fix that
// forwards the 1xx correctly would still look broken through it.
type infoAwareRecorder struct {
	header        http.Header
	informational []int
	status        int
	body          bytes.Buffer
}

func newInfoAwareRecorder() *infoAwareRecorder {
	return &infoAwareRecorder{header: make(http.Header)}
}

func (r *infoAwareRecorder) Header() http.Header { return r.header }

func (r *infoAwareRecorder) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		r.informational = append(r.informational, code)
		return
	}
	if r.status == 0 {
		r.status = code
	}
}

func (r *infoAwareRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}

func TestInformationalStatusDoesNotSwallowTheFinalStatus(t *testing.T) {
	c := newTestCompressor(t, Config{})

	rec := newInfoAwareRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusEarlyHints) // 103: informational
		w.WriteHeader(http.StatusNoContent)  // 204: the real answer
	})).ServeHTTP(rec, req)

	if len(rec.informational) != 1 || rec.informational[0] != http.StatusEarlyHints {
		t.Fatalf("informational statuses forwarded = %v, want [103]", rec.informational)
	}
	if rec.status != http.StatusNoContent {
		t.Fatalf("final status = %d, want %d: the 1xx latched the response state, so the real "+
			"status was swallowed (S13-6)", rec.status, http.StatusNoContent)
	}
}

// A 1xx followed by a body-bearing 200 is the shape 103 Early Hints was introduced
// for. It must still be compressed normally after the fix — the informational status
// is passed through, not treated as the response.
func TestInformationalStatusStillCompressesTheFinalResponse(t *testing.T) {
	c := newTestCompressor(t, Config{})
	body := bytes.Repeat([]byte("x"), DefaultMinSize*2)

	rec := newInfoAwareRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})).ServeHTTP(rec, req)

	if rec.status != http.StatusOK {
		t.Fatalf("final status = %d, want 200", rec.status)
	}
	if got := rec.header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip: a 1xx must not disable compression of the "+
			"response that follows", got)
	}
	if got := decode(t, "gzip", rec.body.Bytes()); !bytes.Equal(got, body) {
		t.Fatalf("body did not round-trip through gzip (%d bytes in, %d out)", len(body), len(got))
	}
}
