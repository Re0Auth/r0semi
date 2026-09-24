package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve drives one request through h without a server.
func serve(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// scrape returns the Prometheus exposition text for this Metrics set.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := serve(m.Handler(), "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// The four golden signals are the point of this package: traffic and errors
// (requests_total), latency (duration), and saturation (in_flight). If one of
// them is missing from the exposition, the dashboard it feeds has a hole.
func TestMiddlewareRecordsGoldenSignals(t *testing.T) {
	m := New()
	classify := func(r *http.Request) string {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			return "business"
		}
		return "browser"
	}
	handler := m.Middleware(classify, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// No explicit WriteHeader: this exercises the recorder's default-to-200
		// path, which is how most handlers on this service answer.
		_, _ = w.Write([]byte("ok"))
	}))

	serve(handler, "/v1/me")      // business 200
	serve(handler, "/v1/missing") // business 404
	serve(handler, "/index.html") // browser 200

	body := scrape(t, m)
	for _, want := range []string{
		`re0auth_http_requests_total{method="GET",plane="business",status="200"} 1`,
		`re0auth_http_requests_total{method="GET",plane="business",status="404"} 1`,
		`re0auth_http_requests_total{method="GET",plane="browser",status="200"} 1`,
		`re0auth_http_request_duration_seconds_count{method="GET",plane="business"} 2`,
		`re0auth_http_in_flight_requests{plane="business"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics are missing %q\n--- exposition ---\n%s", want, body)
		}
	}
}

// The runtime collectors answer questions that are not about requests at all — a
// goroutine leak, a GC cliff. A scrape that only had counters would be blind to
// exactly the incidents an operator reaches for /metrics during.
func TestMetricsIncludeRuntimeCollectors(t *testing.T) {
	body := scrape(t, New())
	for _, want := range []string{"go_goroutines", "go_gc_duration_seconds", "process_cpu_seconds_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition is missing the %s collector", want)
		}
	}
}

// A request that is still in flight must be visible as such, so the gauge is
// incremented for the duration of the handler rather than only at the end.
func TestInFlightIsVisibleWhileServing(t *testing.T) {
	m := New()
	var during string
	handler := m.Middleware(
		func(*http.Request) string { return "business" },
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			during = scrape(t, m)
		}),
	)
	serve(handler, "/v1/me")

	if !strings.Contains(during, `re0auth_http_in_flight_requests{plane="business"} 1`) {
		t.Errorf("in-flight gauge was not 1 during the request\n%s", during)
	}
	if after := scrape(t, m); !strings.Contains(after, `re0auth_http_in_flight_requests{plane="business"} 0`) {
		t.Errorf("in-flight gauge did not return to 0\n%s", after)
	}
}

// The internal surface serves both the scrape endpoint and the profiling
// handlers, and nothing else. It is what is bound to a private address.
func TestInternalHandlerServesMetricsAndPprof(t *testing.T) {
	h := New().InternalHandler()
	for _, path := range []string{
		"/metrics",
		"/debug/pprof/",
		"/debug/pprof/goroutine",
		"/debug/pprof/cmdline",
	} {
		if rec := serve(h, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

// The internal handler does not fall through to anything: a path it does not
// know is a 404, so the surface stays exactly what it claims to be.
func TestInternalHandlerRejectsUnknownPaths(t *testing.T) {
	h := New().InternalHandler()
	for _, path := range []string{"/", "/v1/me", "/debug", "/metrics/extra"} {
		if rec := serve(h, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}
