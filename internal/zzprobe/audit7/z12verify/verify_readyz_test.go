//go:build audit7

// Z12-VERIFY: independent regression guards for the /readyz caller-hangup ruling.
//
// The readiness cache is process-wide, so a caller that hangs up must not be able
// to end the shared dependency check. The fix runs the check on
// context.WithoutCancel(callerCtx) + readinessTimeout. These probes hang anonymous
// callers up continuously and require every kubelet-shaped probe to stay 200 and
// the dependency to see zero cancellations.
package z12verify

import (
	"context"
	"errors"
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

type vzIntrospector struct{}

func (vzIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type vzGrants struct{}

func (vzGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (vzGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type vzDevices struct{}

func (vzDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (vzDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

func readyServer(t *testing.T, ready httpapi.ReadinessProbe) *httptest.Server {
	t.Helper()
	srv, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }),
		TokenIntrospector: vzIntrospector{},
		GrantStore:        vzGrants{},
		DeviceStore:       vzDevices{},
		Ready:             ready,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getReadyz(t *testing.T, base string) (int, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(base + "/readyz") //nolint:gosec // loopback
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// hangUp opens /readyz on its own connection and closes it mid-check.
func hangUp(t *testing.T, base string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET /readyz HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n"))
	time.Sleep(20 * time.Millisecond)
	_ = conn.Close()
}

// TestZ12VerifyReadyzStaysUpWhileKubeletKeepsProbing measures the shape the
// shipped manifest asks for: a probe every 5s (deploy/k8s/base/deployment.yaml
// readinessProbe periodSeconds: 5). The dependency is healthy throughout; the only
// unwelcome caller is one that hangs up once per TTL. Every probe must stay 200 and
// the hang-up must not cancel the shared check. The controls are the same sequence
// with no hang-up (every probe 200, nothing cancelled) and a genuinely down
// dependency (still 503, so the fix did not turn /readyz into an unconditional 200).
//
// It was formerly TestZ12VerifyReadyzStaysDownWhileKubeletKeepsProbing, which
// asserted the poisoning persisted.
func TestZ12VerifyReadyzStaysUpWhileKubeletKeepsProbing(t *testing.T) {
	var cancelled, probes atomic.Int64

	ready := func(ctx context.Context) error {
		probes.Add(1)
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			return ctx.Err()
		case <-time.After(120 * time.Millisecond):
			return nil
		}
	}

	// Control 1: an ordinary probe every 300ms sees 200 every time and cancels
	// nothing.
	ctrlSrv := readyServer(t, ready)
	for i := 0; i < 4; i++ {
		if code, body := getReadyz(t, ctrlSrv.URL); code != http.StatusOK {
			t.Fatalf("control: probe %d = %d %q, want 200", i, code, body)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if n := cancelled.Load(); n != 0 {
		t.Fatalf("control: the dependency was cancelled %d time(s) with no caller hanging up", n)
	}
	probes.Store(0)

	// Control 2: a real dependency failure is still reported 503.
	downSrv := readyServer(t, func(context.Context) error { return errors.New("database down") })
	if code, body := getReadyz(t, downSrv.URL); code != http.StatusServiceUnavailable {
		t.Fatalf("control: a down dependency answered %d %q, want 503: the guard must not be vacuous", code, body)
	}

	// Subject: one hang-up, then poll like a kubelet would.
	ts := readyServer(t, ready)
	if code, _ := getReadyz(t, ts.URL); code != http.StatusOK {
		t.Fatalf("the first probe was not 200, so the subject server was never healthy")
	}
	time.Sleep(1100 * time.Millisecond) // let the cached success expire
	hangUp(t, ts.URL)
	time.Sleep(200 * time.Millisecond) // let the detached check finish

	codes := make([]int, 0, 6)
	for i := 0; i < 6; i++ {
		code, _ := getReadyz(t, ts.URL)
		codes = append(codes, code)
		time.Sleep(400 * time.Millisecond)
	}
	t.Logf("readyz codes after one hang-up, polled every 400ms: %v (dependency checks run: %d, cancellations: %d)",
		codes, probes.Load(), cancelled.Load())

	if n := cancelled.Load(); n != 0 {
		t.Errorf("the dependency saw its context cancelled %d time(s) after one anonymous caller hung up: the check "+
			"runs on the caller's request context again, so a hangup ends the shared readiness check", n)
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("probe %d answered %d after a single anonymous hang-up while the dependency was healthy: the "+
				"caller's cancellation reached the shared readiness cache", i, c)
		}
	}
}

// TestZ12VerifySustainedHangUpsDoNotHoldReadyzDown asks whether the one-window
// effect can be sustained — the difference between "a rolling deploy shows a blip"
// and "a healthy replica stays out of rotation". An attacker that hangs up more
// often than readinessTTL starts every fresh check itself; with the fix those
// detached checks see the healthy dependency and every kubelet-shaped probe stays
// 200 with zero cancellations.
//
// It was formerly TestZ12VerifySustainedHangUpsHoldReadyzDown, which asserted the
// poison could be sustained.
func TestZ12VerifySustainedHangUpsDoNotHoldReadyzDown(t *testing.T) {
	var cancelled atomic.Int64
	ready := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			return ctx.Err()
		case <-time.After(80 * time.Millisecond):
			return nil
		}
	}
	ts := readyServer(t, ready)

	if code, _ := getReadyz(t, ts.URL); code != http.StatusOK {
		t.Fatalf("the server was not healthy to begin with")
	}
	time.Sleep(1100 * time.Millisecond)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			hangUp(t, ts.URL)
			time.Sleep(250 * time.Millisecond)
		}
	}()

	// Three kubelet-shaped probes, 5s apart, over 11 seconds of attack. The
	// dependency is healthy throughout, so every probe must stay 200.
	time.Sleep(1200 * time.Millisecond)
	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		code, _ := getReadyz(t, ts.URL)
		codes = append(codes, code)
		time.Sleep(4500 * time.Millisecond)
	}
	close(stop)
	<-done
	t.Logf("kubelet-shaped probes during a sustained attack: %v (cancellations: %d)", codes, cancelled.Load())

	if n := cancelled.Load(); n != 0 {
		t.Errorf("the dependency saw its context cancelled %d time(s) during sustained anonymous hang-ups: the check "+
			"runs on the caller's request context again, so one client holding a connect-and-close loop ends "+
			"every shared readiness check", n)
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("kubelet-shaped probe %d answered %d during sustained anonymous hang-ups while the dependency "+
				"was healthy: one anonymous client keeps the readiness cache poisoned", i, c)
		}
	}
}
