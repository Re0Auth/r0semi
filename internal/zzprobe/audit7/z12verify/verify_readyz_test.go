//go:build audit7

// Z12-VERIFY: an independent reading of the /readyz poisoning, with a control
// built into the same process (the shipping kubelet cadence).
package z12verify

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

// TestZ12VerifyReadyzStaysDownWhileKubeletKeepsProbing measures the shape the
// shipped manifest asks for: a probe every 5s (deploy/k8s/base/deployment.yaml
// readinessProbe periodSeconds: 5). The dependency is healthy throughout; the
// only unwelcome caller is one that hangs up once per TTL. If the orchestrator's
// probe ever sees 200 again, the poisoning is self-healing and bounded to one
// window; if it does not, the instance is held out of rotation indefinitely.
//
// The control is the same sequence with no hang-up: every probe must be 200.
func TestZ12VerifyReadyzStaysDownWhileKubeletKeepsProbing(t *testing.T) {
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

	// Control: an ordinary probe every 300ms sees 200 every time.
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

	// Subject: one hang-up, then poll like a kubelet would.
	ts := readyServer(t, ready)
	if code, _ := getReadyz(t, ts.URL); code != http.StatusOK {
		t.Fatalf("the first probe was not 200, so the subject server was never healthy")
	}
	time.Sleep(1100 * time.Millisecond) // let the cached success expire
	hangUp(t, ts.URL)
	deadline := time.Now().Add(3 * time.Second)
	for cancelled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cancelled.Load() == 0 {
		t.Fatal("the hang-up never cancelled the dependency check, so this probe cannot conclude")
	}

	codes := make([]int, 0, 6)
	for i := 0; i < 6; i++ {
		code, _ := getReadyz(t, ts.URL)
		codes = append(codes, code)
		time.Sleep(400 * time.Millisecond)
	}
	t.Logf("readyz codes after one hang-up, polled every 400ms: %v (dependency checks run: %d)",
		codes, probes.Load())
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok == len(codes) {
		t.Errorf("the cancelled check did not poison anything: all %d probes answered 200", len(codes))
		return
	}
	if ok > 0 {
		t.Logf("the poisoning healed after %d/%d probes answered 200", len(codes)-ok, len(codes))
		return
	}
	t.Errorf("every one of the %d probes %v after a single anonymous hang-up answered 503 while the "+
		"dependency was healthy: an anonymous caller can keep a healthy instance out of rotation for "+
		"as long as it keeps opening and closing /readyz once per readinessTTL, and the shipped probe "+
		"cadence (periodSeconds: 5, failureThreshold: 3) removes the endpoint.", len(codes), codes)
}

// TestZ12VerifySustainedHangUpsHoldReadyzDown asks whether the one-window effect
// can be sustained, which is the difference between "a rolling deploy shows a
// blip" and "a healthy replica stays out of rotation". An attacker that hangs up
// more often than readinessTTL starts every fresh check itself, so the kubelet's
// own probe never triggers a real check — it always reads the attacker's
// cancelled result.
func TestZ12VerifySustainedHangUpsHoldReadyzDown(t *testing.T) {
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

	// Three kubelet-shaped probes, 5s apart, over 11 seconds of attack.
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

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if cancelled.Load() == 0 {
		t.Fatal("no check was ever cancelled, so this probe observed nothing")
	}
	if ok == len(codes) {
		t.Errorf("sustained hang-ups did not hold /readyz down: %v", codes)
	} else if ok > 0 {
		t.Logf("the attack did not hold every probe down (%d of %d answered 200); the effect is a "+
			"one-window blip unless the attacker wins every readinessTTL race", ok, len(codes))
	} else {
		t.Errorf("every kubelet-shaped probe during the sustained attack answered 503 (%v) while the "+
			"dependency was healthy: one anonymous client holding a connect-and-close loop keeps the "+
			"readiness cache poisoned, so failureThreshold 3 x periodSeconds 5 removes the endpoint",
			codes)
	}
}
