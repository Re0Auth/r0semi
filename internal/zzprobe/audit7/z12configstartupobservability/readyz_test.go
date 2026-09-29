//go:build audit7

package z12configstartupobservability

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/oauth"
)

// The three seams httpapi.New requires; none of them is reached by /readyz.
type z12Introspector struct{}

func (z12Introspector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type z12Grants struct{}

func (z12Grants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (z12Grants) RevokeGrant(context.Context, string, string) error     { return nil }

type z12Devices struct{}

func (z12Devices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (z12Devices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

// Z12-7 regression guard: the readiness result is shared between callers, and a
// caller that hangs up must NOT poison it.
//
// The defect ran the dependency check on the CANCELLABLE request context of
// whichever caller happened to trigger it
// (`probeCtx, cancel := context.WithTimeout(ctx, readinessTimeout); probe(probeCtx)`,
// internal/httpapi/health.go). net/http cancels that context when the client's
// connection closes, so a caller that opened /readyz and hung up made the check
// fail on the cancellation rather than on the dependency, and the result was
// stored for readinessTTL — every probe answered from the cache inheriting it. That
// is exactly what the endpoint's own contract forbids: "It never fails because of
// load ... a 503 caused by someone else's traffic would pull a healthy instance out
// of rotation."
//
// The fix derives the check from context.WithoutCancel(r.Context()) +
// readinessTimeout, so a hangup ends only the caller's own response and never the
// shared check. This guard hangs one anonymous caller up mid-check and then
// requires (a) the dependency to have seen zero cancellations and (b) the next
// fresh /readyz to be 200. It was formerly
// TestZ12ReadyzIsPoisonedByACallerThatHangsUp, a finding-confirmation oracle.
func TestZ12ReadyzSurvivesACallerThatHangsUp(t *testing.T) {
	var cancelled atomic.Int64

	// A healthy dependency that takes a moment and honours its context, which is
	// what a database round trip is.
	ready := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
			return nil
		}
	}

	cfg := httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }),
		TokenIntrospector: z12Introspector{},
		GrantStore:        z12Grants{},
		DeviceStore:       z12Devices{},
		Ready:             ready,
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Control: one probe against the healthy dependency answers 200, and nothing
	// was cancelled (the probe is not measuring a broken dependency).
	if code, body := getReadyz(t, ts.URL); code != http.StatusOK {
		t.Fatalf("control: /readyz = %d %q, want 200", code, body)
	}
	if n := cancelled.Load(); n != 0 {
		t.Fatalf("control: the dependency was cancelled %d time(s) with no caller hanging up", n)
	}

	// Let the cached success expire, so the next probe runs a fresh check.
	time.Sleep(1100 * time.Millisecond)

	// An anonymous caller asks for /readyz and leaves mid-check.
	hangUpReadyz(t, ts.URL)
	// Give the detached check time to finish. If the hangup still reached it, the
	// cancellation count below moves.
	time.Sleep(300 * time.Millisecond)

	if n := cancelled.Load(); n != 0 {
		t.Errorf("the dependency saw its context cancelled %d time(s) after one anonymous caller hung up: the "+
			"readiness check is derived from the caller's request context again, so a hangup ends the "+
			"process-wide check and its result is shared with every other caller", n)
	}

	// The orchestrator's next probe — another connection, same process — must be
	// answered about the dependency, which is healthy.
	code, body := getReadyz(t, ts.URL)
	if code != http.StatusOK {
		t.Errorf("/readyz = %d %q after one anonymous caller hung up while the dependency was healthy: the shared "+
			"readiness result is not the dependency's, and every probe answered from the cache for the next %s "+
			"inherits it (probes are exempt from the limiter and the in-flight cap).\nURL: %s",
			code, body, time.Second, ts.URL)
	} else {
		t.Logf("the caller's hangup did not poison the cache: /readyz = 200")
	}
}

func getReadyz(t *testing.T, base string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/readyz") //nolint:gosec // loopback, test-only
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// hangUpReadyz sends a /readyz request over its own connection and closes without
// reading the response — what a client that abandons a probe does, and what makes
// the server cancel the request context.
func hangUpReadyz(t *testing.T, base string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial %s: %v", u.Host, err)
	}
	_, _ = conn.Write([]byte("GET /readyz HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n"))
	// Give the server time to enter the handler and start the check, then leave.
	time.Sleep(25 * time.Millisecond)
	_ = conn.Close()
}
