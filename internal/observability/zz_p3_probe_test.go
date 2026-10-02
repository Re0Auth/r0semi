package observability

// P3-low probes for the operational surface: S13-7 and S13-8.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- S13-7: the status label must not be settable from an upstream status

// TestUpstreamControlledStatusIsCollapsed pins that a status outside HTTP's own
// code space cannot mint a metric series. The raw-proxy federation route writes a
// source's status verbatim (internal/httpapi/federation_routes.go:320) and net/http
// accepts any code up to 999, so a source answering 900+n grew
// re0auth_http_requests_total by one series per n, forever.
func TestUpstreamControlledStatusIsCollapsed(t *testing.T) {
	m := New()
	h := m.Middleware(
		func(*http.Request) string { return "business" },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(999) // what a proxied source's status reaches
		}),
	)
	serve(h, "/v1/sources/raw")

	body := scrape(t, m)
	if strings.Contains(body, `status="999"`) {
		t.Errorf("a source-controlled 999 minted its own status series; the label is unbounded\n%s", body)
	}
	if !strings.Contains(body, `status="other"`) {
		t.Errorf("the out-of-space status was not collapsed into the bounded bucket\n%s", body)
	}

	// Control: the codes this service actually answers with keep their own series,
	// because the alerting rules match `status=~"5.."` (deploy/prometheus/re0auth.rules.yml).
	for _, code := range []int{200, 204, 304, 404, 500, 503} {
		mid := New()
		hh := mid.Middleware(
			func(*http.Request) string { return "business" },
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }),
		)
		serve(hh, "/v1/thing")
		if want := `status="` + strconv.Itoa(code) + `"`; !strings.Contains(scrape(t, mid), want) {
			t.Errorf("status %d lost its own series (want %s); the class the 5xx rules match on "+
				"must survive normalization", code, want)
		}
	}
}

// TestInformationalStatusIsNotReportedAsTheResponseStatus pins that the recorder
// does not latch a 1xx. net/http forwards an informational status and still expects
// the real one, so a 103 Early Hints became the status this metric reported for a
// response that answered 204.
func TestInformationalStatusIsNotReportedAsTheResponseStatus(t *testing.T) {
	m := New()
	h := m.Middleware(
		func(*http.Request) string { return "business" },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/thing", nil))

	body := scrape(t, m)
	if strings.Contains(body, `status="103"`) {
		t.Errorf("a 103 Early Hints was recorded as the response status\n%s", body)
	}
	if !strings.Contains(body, `status="204"`) {
		t.Errorf("the final 204 was not recorded\n%s", body)
	}
}

// --- S13-8: the profiling endpoints must be bounded

// TestPprofSecondsAreClamped pins that a caller-chosen window is clamped before the
// pprof handler sees it. Unclamped, `?seconds=100000` spent 100000 seconds of CPU
// and produced a body proportional to it.
func TestPprofSecondsAreClamped(t *testing.T) {
	cases := []struct {
		path       string
		maxSeconds int
	}{
		{"/debug/pprof/profile", maxProfileSeconds},
		{"/debug/pprof/trace", maxTraceSeconds},
	}
	for _, tc := range cases {
		gate := newProfileGate()
		var got string
		h := gate.guard(tc.maxSeconds, func(w http.ResponseWriter, r *http.Request) {
			got = r.URL.Query().Get("seconds")
			w.WriteHeader(http.StatusOK)
		})

		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path+"?seconds=100000", nil))
		if want := strconv.Itoa(tc.maxSeconds); got != want {
			t.Errorf("%s?seconds=100000 reached the handler as %q, want %q: the window is unbounded",
				tc.path, got, want)
		}

		// A window inside the cap is left alone, so the clamp is a ceiling and not
		// a rewrite.
		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path+"?seconds=1", nil))
		if got != "1" {
			t.Errorf("%s?seconds=1 reached the handler as %q, want it untouched", tc.path, got)
		}
	}
}

// TestPprofGateRefusesAConcurrentProfile pins the concurrency cap: while one
// profiling request holds the gate, the next is refused instead of queued.
func TestPprofGateRefusesAConcurrentProfile(t *testing.T) {
	gate := newProfileGate()
	entered := make(chan struct{})
	release := make(chan struct{})
	h := gate.guard(maxProfileSeconds, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	go h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/debug/pprof/profile", nil))
	<-entered

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/profile", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a second concurrent profile = %d, want %d: there is no concurrency cap",
			rec.Code, http.StatusServiceUnavailable)
	}
	close(release)
}

// TestProfileAndTraceRoutesAreBehindTheGate pins the wiring: exactly the two
// CPU-burning endpoints go through the gate, and the cheap ones stay reachable
// while a profile is running.
func TestProfileAndTraceRoutesAreBehindTheGate(t *testing.T) {
	gate := newProfileGate()
	mux := http.NewServeMux()
	registerPprof(mux, gate)

	gate.slot <- struct{}{} // one profiling request is running
	defer func() { <-gate.slot }()

	for _, path := range []string{"/debug/pprof/profile", "/debug/pprof/trace"} {
		if rec := serve(mux, path); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want %d while the gate is held: the endpoint is not wired "+
				"through the gate", path, rec.Code, http.StatusServiceUnavailable)
		}
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		if rec := serve(mux, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200: the cheap endpoints must stay reachable during a profile",
				path, rec.Code)
		}
	}
}

// TestConcurrentProfilesOnTheInternalHandlerAreRefused pins that a second profiling
// request is refused while one is running. Without a gate the runtime answers a
// second CPU profile with a 500 from inside pprof and creates another goroutine and
// buffer for it; with the gate it is a deliberate 503.
func TestConcurrentProfilesOnTheInternalHandlerAreRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a live CPU profile window")
	}
	h := New().InternalHandler()
	const path = "/debug/pprof/profile?seconds=1"

	done := make(chan int, 1)
	go func() { done <- serve(h, path).Code }()

	// Let the first request start its CPU profile (it holds the gate, and the
	// runtime profiler, for the whole window).
	time.Sleep(300 * time.Millisecond)
	second := serve(h, path).Code
	first := <-done

	if first != http.StatusOK {
		t.Fatalf("the first profile = %d, want 200", first)
	}
	if second == http.StatusOK {
		t.Fatal("a second CPU profile ran concurrently, so the endpoint is unbounded")
	}
	if second != http.StatusServiceUnavailable {
		t.Fatalf("a concurrent profile = %d, want %d: the endpoint has no concurrency cap, so the "+
			"refusal comes from the runtime as a 500 rather than from this surface (S13-8)",
			second, http.StatusServiceUnavailable)
	}
}
