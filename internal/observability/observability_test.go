package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// Every domain signal must reach the exposition with the labels its alerting
// rule matches on. A metric that is recorded but never exported is a dashboard
// panel that reads zero forever — the failure that looks identical to "nothing
// happened".
func TestDomainSignalsAreExported(t *testing.T) {
	m := New()
	m.ObserveLogin("github", LoginSuccess)
	m.ObserveTokenIssued("authorization_code")
	m.ObserveTokenError("refresh_token", "invalid_grant")
	m.ObserveDeviceDecision(DeviceApproved)
	m.ObserveRevocation(RevocationGrant)
	m.ObserveTokensRevoked(RevocationKillSwitch, 3)
	m.ObserveAdminAction(AdminKillSwitch)
	m.ObserveAuditVerify(VerifyOK)
	m.ObserveUpstreamFetch("phigros", "next-phi", UpstreamOK)
	m.ObserveUpstreamRefresh(RefreshRejected)
	m.ObserveVaultOperation("use", "ok", 2*time.Millisecond)

	body := scrape(t, m)
	for _, want := range []string{
		`re0auth_auth_logins_total{provider="github",result="success"} 1`,
		`re0auth_tokens_issued_total{grant_type="authorization_code"} 1`,
		`re0auth_token_errors_total{error="invalid_grant",grant_type="refresh_token"} 1`,
		`re0auth_device_decisions_total{decision="approved"} 1`,
		`re0auth_revocations_total{kind="grant"} 1`,
		`re0auth_tokens_revoked_total{kind="kill_switch"} 3`,
		`re0auth_admin_actions_total{action="kill_switch"} 1`,
		`re0auth_audit_verify_total{result="ok"} 1`,
		`re0auth_upstream_fetches_total{game="phigros",result="ok",source="next-phi"} 1`,
		`re0auth_upstream_refreshes_total{result="rejected"} 1`,
		`re0auth_vault_operations_total{operation="use",result="ok"} 1`,
		`re0auth_vault_operation_duration_seconds_count{operation="use"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition is missing %q\n--- exposition ---\n%s", want, body)
		}
	}
}

// A zero count must not create a series: a revocation that removed nothing is
// not activity, and a `tokens_revoked_total{kind="…"} 0` line would make an idle
// system look like a busy one.
func TestTokensRevokedIgnoresNonPositiveCounts(t *testing.T) {
	m := New()
	m.ObserveTokensRevoked(RevocationErasure, 0)
	m.ObserveTokensRevoked(RevocationErasure, -1)
	if body := scrape(t, m); strings.Contains(body, "re0auth_tokens_revoked_total") {
		t.Errorf("a non-positive count created a series\n%s", body)
	}
}

// The label budget is the whole reason the normalizers exist. Values that come
// from a request must not be able to grow the metric set, so an unknown
// grant_type, error code or HTTP method collapses into one bounded bucket rather
// than one time series per value an attacker invents.
func TestUnknownLabelValuesAreCollapsed(t *testing.T) {
	m := New()
	m.ObserveTokenIssued("invented_grant")
	m.ObserveTokenError("invented_grant", "invented_error")
	handler := m.Middleware(
		func(*http.Request) string { return "business" },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("FROBNICATE", "/v1/me", nil))

	body := scrape(t, m)
	for _, want := range []string{
		`re0auth_tokens_issued_total{grant_type="other"} 1`,
		`re0auth_token_errors_total{error="other",grant_type="other"} 1`,
		`re0auth_http_requests_total{method="other",plane="business",status="200"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition is missing %q\n--- exposition ---\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"invented_grant", "invented_error", "FROBNICATE"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("an unbounded label value %q reached the exposition\n%s", forbidden, body)
		}
	}
}

// The domain methods are called from paths that may not have been given
// instrumentation — an in-memory test deployment, for one — so a nil *Metrics
// must be inert rather than a panic in the middle of serving a request.
func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.ObserveLogin("github", LoginSuccess)
	m.ObserveTokenIssued("authorization_code")
	m.ObserveTokenError("refresh_token", "invalid_grant")
	m.ObserveDeviceDecision(DeviceDenied)
	m.ObserveRevocation(RevocationGrant)
	m.ObserveTokensRevoked(RevocationKillSwitch, 3)
	m.ObserveAdminAction(AdminSuspend)
	m.ObserveAuditVerify(VerifyFailed)
	m.ObserveUpstreamFetch("phigros", "next-phi", UpstreamDegraded)
	m.ObserveUpstreamRefresh(RefreshTransient)
	m.ObserveVaultOperation("use", "ok", time.Millisecond)
}
