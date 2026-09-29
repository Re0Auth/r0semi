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

// Z12-7: the readiness result is shared between callers, so one caller that hangs
// up poisons the answer the orchestrator gets.
//
// readinessCache.check (internal/httpapi/health.go:111-133) runs the dependency
// check on the CANCELLABLE request context of whichever caller happened to trigger
// it:
//
//	probeCtx, cancel := context.WithTimeout(ctx, readinessTimeout)
//	err := probe(probeCtx)
//
// and then stores that error for readinessTTL. A caller that opens /readyz and
// hangs up cancels r.Context() (net/http cancels the request context when the
// connection is closed), so the check fails on the cancellation — not on the
// dependency — and every probe answered from the cache for the next second gets
// 503. The endpoint's own contract forbids exactly this: "It never fails because
// of load ... a 503 caused by someone else's traffic would pull a healthy instance
// out of rotation." Probes are also exempt from the limiter and the in-flight cap,
// so the poison costs the caller nothing.
//
// It is reachable in a durable deployment, where Ready is store.db.Ping
// (cmd/re0auth/main.go:860-865) and that is pool.Ping(ctx)
// (internal/store/postgres/postgres.go:268) — a context-aware round trip that
// reports the cancellation. No database is needed to execute the cache's own
// mechanism: the probe below is a ReadinessProbe driven through the real handler.
//
// Relation to G-11: that one is the `running` branch answering from the
// never-written zero value (200 about an unverified dependency). This is the
// `fresh` branch answering from a result that was cancelled, in the opposite
// direction.
func TestZ12ReadyzIsPoisonedByACallerThatHangsUp(t *testing.T) {
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

	// An anonymous caller asks for /readyz and leaves.
	hangUpReadyz(t, ts.URL)
	deadline := time.Now().Add(3 * time.Second)
	for cancelled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cancelled.Load() == 0 {
		t.Fatal("the hang-up never cancelled the dependency check, so this probe cannot conclude")
	}

	// The orchestrator's next probe — another connection, same process — must be
	// answered about the dependency, which is healthy. It gets the cancelled
	// caller's result instead.
	code, body := getReadyz(t, ts.URL)
	if code != http.StatusOK {
		t.Errorf("/readyz = %d %q after one anonymous caller hung up: the shared readiness result was "+
			"replaced by a check that failed on that caller's cancellation, and every probe answered "+
			"from the cache for the next %s inherits it. A caller can hold this at 503 for as long as "+
			"it keeps asking (probes are exempt from the limiter and the in-flight cap).\nURL: %s",
			code, body, time.Second, ts.URL)
	} else {
		t.Logf("the cancelled check did not poison the cache: /readyz = 200")
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
