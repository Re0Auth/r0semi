package compress

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// AUDIT9 / S13-6 — a 1xx informational status latches wroteHeader, so the real
// status that follows is swallowed.
//
// responseWriter.WriteHeader sets wroteHeader on the FIRST call and, for a status
// below 200, sets skip (compress.go:327) and forwards it. A handler that emits an
// interim 1xx (103 Early Hints, or 100/102) and then the final 200 hits the
// `if w.wroteHeader { return }` guard at compress.go:319, so 200 is never
// forwarded: the client is left with the informational status.
//
// Guard: pins the swallow. It fails once 1xx is passed through without latching
// (the recommended fix), because the final status would be 200.
func TestAudit9InformationalStatusSwallowsTheFinalStatus(t *testing.T) {
	c := newTestCompressor(t, Config{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/thing", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusEarlyHints) // 103
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusEarlyHints {
		t.Fatalf("final status = %d, want %d: the 1xx no longer latches, so S13-6 appears "+
			"fixed — update this guard", rec.Code, http.StatusEarlyHints)
	}
	if rec.Code == http.StatusOK {
		t.Fatal("the final 200 reached the client; S13-6 appears fixed")
	}
}
