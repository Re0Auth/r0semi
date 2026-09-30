package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
)

// Z09V-1 (docs/issues/P2-medium.md): a binding whose credential the source keeps
// rejecting is shed as a temporary LOCAL condition. It must not borrow the
// host-breaker's vocabulary: the default 502 "upstream_unavailable" means "could
// not reach the source", and the source is fine — another binding on it is being
// served. The answer is the fail-closed shed shape the byte budget also uses, 503
// with a retry hint, and it names no subject.
func TestFederationBindingCooldownAnswersTemporarilyUnavailable(t *testing.T) {
	s := &Server{errorBase: "https://re0auth.dev/errors"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/games/phigros/profile", nil)
	s.writeFederationError(rec, req, &federation.BindingCooldownError{Game: "phigros", Source: "src"})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (a shed, not the source being unreachable)", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
	var body struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v (%s)", err, rec.Body.String())
	}
	if body.Code != "temporarily_unavailable" || body.Status != http.StatusServiceUnavailable {
		t.Errorf("body = %+v, want temporarily_unavailable/503", body)
	}
	if body.Detail == "" {
		t.Error("the response carries no detail explaining the shed")
	}
}
