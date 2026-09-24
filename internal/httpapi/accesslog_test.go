package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// captureHandler keeps the records written to the default logger, so a test can
// assert on them without parsing text.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) find(message string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == message {
			return r, true
		}
	}
	return slog.Record{}, false
}

// captureRecords swaps the default logger for a capturing one. The package has no
// parallel tests, so the swap is safe; the cleanup restores whatever was there.
func captureRecords(t *testing.T) *captureHandler {
	t.Helper()
	cap := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(cap))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return cap
}

func recordAttr(r slog.Record, key string) (slog.Value, bool) {
	var out slog.Value
	var found bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			out, found = a.Value, true
			return false
		}
		return true
	})
	return out, found
}

// render formats a record the way a text handler would, so an assertion can be
// made over the whole line rather than over the fields the test remembered to
// look at. A secret that leaks through a field nobody thought of is caught by
// this and not by a field-by-field check.
func render(t *testing.T, r slog.Record) string {
	t.Helper()
	var buf bytes.Buffer
	if err := slog.NewTextHandler(&buf, nil).Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The access log carries the request id — that is the middleware's whole purpose
// — and carries no part of the query string.
//
// The query is the case that matters: an authorization, bind callback or device
// verification URL arrives with a `code`, `state` or `user_code` in it, and a log
// line is a file that gets copied into tickets.
func TestAccessLogCarriesTheRequestIDAndNotTheQuery(t *testing.T) {
	cap := captureRecords(t)
	srv := newFullEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/me?code=SECRET-CODE&access_token=SECRET-TOKEN", nil)
	req.Header.Set("X-Request-Id", "req-from-caller")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	line, ok := cap.find("request")
	if !ok {
		t.Fatal("no access log line was written")
	}
	for key, want := range map[string]string{
		"method":     http.MethodGet,
		"path":       "/v1/me",
		"plane":      "business",
		"request_id": "req-from-caller",
	} {
		got, ok := recordAttr(line, key)
		if !ok {
			t.Errorf("the access log has no %q field", key)
			continue
		}
		if got.String() != want {
			t.Errorf("%s = %q, want %q", key, got.String(), want)
		}
	}
	if got, ok := recordAttr(line, "status"); !ok || got.Int64() != http.StatusUnauthorized {
		t.Errorf("status = %v, want %d", got, http.StatusUnauthorized)
	}

	text := render(t, line)
	for _, secret := range []string{"SECRET-CODE", "SECRET-TOKEN", "?"} {
		if strings.Contains(text, secret) {
			t.Errorf("the access log contains %q; the query string must not be logged: %s", secret, text)
		}
	}
}

// Probes are logged below the level a default deployment shows. An orchestrator
// polls them every few seconds for the life of the process; at info that is the
// log's steady state rather than a signal in it. The line is still written, so
// nothing is lost to somebody who turns the level down.
func TestProbeAccessLogIsWrittenAtDebug(t *testing.T) {
	cap := captureRecords(t)
	srv := newFullEnv(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	line, ok := cap.find("request")
	if !ok {
		t.Fatal("no access log line was written for /healthz")
	}
	if line.Level != slog.LevelDebug {
		t.Fatalf("level = %v, want debug", line.Level)
	}
}

// A request that never reaches a handler is still logged, and with the status it
// actually got. This is the case the middleware exists for as much as the
// successful one: a 429 is the response most likely to be reported, and it is
// produced by the limiter without any handler running.
func TestAccessLogRecordsRejectionsAwayFromAnyHandler(t *testing.T) {
	cap := captureRecords(t)
	srv := newFullEnv(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/does-not-exist", nil))

	line, ok := cap.find("request")
	if !ok {
		t.Fatal("no access log line was written for an unknown path")
	}
	if got, _ := recordAttr(line, "status"); got.Int64() != http.StatusNotFound {
		t.Fatalf("status = %v, want %d", got, http.StatusNotFound)
	}
}
