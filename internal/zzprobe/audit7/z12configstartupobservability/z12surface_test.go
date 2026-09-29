//go:build audit7

// Guard: the operational surface is a separate listener, and the public one does
// not answer for it.
package z12configstartupobservability

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a strings.Builder that can be read while the process is still
// writing to it (os/exec copies into it from its own goroutines).
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Guard: the operational surface is a second listener, and the only place /metrics
// and /debug/pprof/ answer is on it. The probe drives the real process to pin the
// separation (a 200 for /debug/pprof/ on the public address would be the finding)
// and the two probes' semantics in an in-memory deployment.
//
// Ports: 127.0.0.1:18201 public, 127.0.0.1:18251 internal (zone 12's allocation).
func TestZ12InternalSurfaceIsSeparateFromThePublicOne(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real process")
	}
	const (
		publicURL   = "http://127.0.0.1:18201"
		internalURL = "http://127.0.0.1:18251"
	)

	env := serveEnv()
	env["RE0AUTH_ADDR"] = "127.0.0.1:18201"
	env["RE0AUTH_INTERNAL_ADDR"] = "127.0.0.1:18251"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Dir = t.TempDir()
	cmd.Env = envWithoutRE0AUTH(env)
	log := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the process: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	client := &http.Client{Timeout: 5 * time.Second}
	get := func(url string) (int, string) {
		t.Helper()
		resp, err := client.Get(url) //nolint:gosec // loopback, test-only
		if err != nil {
			t.Fatalf("GET %s: %v\nprocess log:\n%s", url, err, log.String())
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(body)
	}

	// Wait for the public listener. The log is the failure evidence.
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get(publicURL + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the process never answered /healthz:\n%s", log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Anti-vacuous: the process really did start both listeners and really did get
	// through the OP wires (not a half-started process answering from elsewhere).
	for _, want := range []string{"internal surface listening", "listening", "storage is in-memory"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("the process log never said %q:\n%s", want, log.String())
		}
	}

	// Liveness checks nothing; readiness is always ready without a dependency.
	if code, body := get(publicURL + "/healthz"); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("GET /healthz = %d %q, want 200 ok", code, body)
	}
	if code, body := get(publicURL + "/readyz"); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("GET /readyz = %d %q with no dependency configured, want 200 ok", code, body)
	}

	// The public listener must not serve the operational surface.
	for _, path := range []string{"/metrics", "/debug/pprof/", "/debug/pprof/goroutine"} {
		if code, body := get(publicURL + path); code == http.StatusOK {
			t.Errorf("GET %s on the PUBLIC listener answered 200: the operational surface is "+
				"reachable through the public one\n%s", path, truncate(body, 200))
		} else {
			t.Logf("public %-24s -> %d (not served there)", path, code)
		}
	}

	// And the internal listener must serve it — otherwise the checks above would
	// pass on a process that serves it nowhere.
	if code, body := get(internalURL + "/metrics"); code != http.StatusOK {
		t.Errorf("GET /metrics on the internal listener = %d, want 200\n%s", code, truncate(body, 200))
	} else if !strings.Contains(body, "go_goroutines") {
		t.Errorf("the internal /metrics body does not look like a Prometheus exposition:\n%s", truncate(body, 400))
	} else {
		t.Logf("internal /metrics -> 200 (%d bytes, re0auth_http_requests_total present=%v)",
			len(body), strings.Contains(body, "re0auth_http_requests_total"))
	}
	if code, body := get(internalURL + "/debug/pprof/"); code != http.StatusOK {
		t.Errorf("GET /debug/pprof/ on the internal listener = %d, want 200", code)
	} else if !strings.Contains(body, "goroutine") {
		t.Errorf("/debug/pprof/ did not return the profile index:\n%s", truncate(body, 300))
	}

	// The internal listener serves the operational surface only: the public
	// plane's probes are not mounted there.
	if code, _ := get(internalURL + "/readyz"); code == http.StatusOK {
		t.Errorf("GET /readyz on the INTERNAL listener answered 200: the two surfaces are not separate")
	}
	if code, _ := get(internalURL + "/v1/me"); code == http.StatusOK {
		t.Errorf("GET /v1/me on the INTERNAL listener answered 200: the public plane is mounted there")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
