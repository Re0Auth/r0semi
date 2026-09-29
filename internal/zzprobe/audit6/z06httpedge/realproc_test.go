//go:build audit6

// Real-process black-box probes for zone 06 (round 6). These exercise what the
// in-process fixtures cannot: the http.Server's own limits as cmd/re0auth
// configures them (ReadHeaderTimeout, ReadTimeout, MaxHeaderBytes), request
// forms that Go's parser handles specially (CONNECT), and the well-known verb
// matrix on the composed binary.
//
// The public listener is the zone-06 audit port 127.0.0.1:16601; the process
// runs in memory mode from a temp directory (no config file, environment
// only) and is killed when the tests end.
package z06httpedge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	edgePort = "16601" // zone 06's assigned public audit port
)

var (
	procOnce sync.Once
	procBase string
	procErr  error
	procCmd  *exec.Cmd
)

// TestMain makes sure the real process is stopped when the probes are done,
// even if every real-process test was skipped or failed to build. The Wait
// call lives in the goroutine started by realProcess, so killing here is all
// that is left to do.
func TestMain(m *testing.M) {
	code := m.Run()
	if procCmd != nil {
		_ = procCmd.Process.Kill()
	}
	os.Exit(code)
}

// realProcess builds cmd/re0auth once and starts it on 127.0.0.1:16601.
func realProcess(t *testing.T) string {
	t.Helper()
	procOnce.Do(func() {
		repoRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
		if err != nil {
			procErr = err
			return
		}
		binDir, err := os.MkdirTemp("", "z06-re0auth-*")
		if err != nil {
			procErr = err
			return
		}
		bin := filepath.Join(binDir, "re0auth.exe")
		build := exec.Command("go", "build", "-o", bin, "./cmd/re0auth")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			procErr = fmt.Errorf("go build: %v: %s", err, out)
			return
		}

		// The keys the fail-closed startup requires.
		signing, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			procErr = err
			return
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(signing)
		if err != nil {
			procErr = err
			return
		}
		var tokenKey [32]byte
		if _, err := rand.Read(tokenKey[:]); err != nil {
			procErr = err
			return
		}
		var kek [32]byte
		if _, err := rand.Read(kek[:]); err != nil {
			procErr = err
			return
		}

		workdir, err := os.MkdirTemp("", "z06-run-*")
		if err != nil {
			procErr = err
			return
		}
		addr := "127.0.0.1:" + edgePort
		procBase = "http://" + addr

		cmd := exec.Command(bin)
		cmd.Dir = workdir // no config file here: environment-only mode
		cmd.Env = append(os.Environ(),
			"RE0AUTH_ADDR="+addr,
			"RE0AUTH_ISSUER=http://"+addr,
			"RE0AUTH_KEK="+base64.StdEncoding.EncodeToString(kek[:]),
			"RE0AUTH_OIDC_SIGNING_KEY="+base64.StdEncoding.EncodeToString(pkcs8),
			"RE0AUTH_OIDC_TOKEN_KEY="+base64.StdEncoding.EncodeToString(tokenKey[:]),
		)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			procErr = err
			return
		}
		procCmd = cmd
		go func() { _ = cmd.Wait() }()

		// Wait for the listener to answer before handing the base URL out.
		deadline := time.Now().Add(30 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = conn.Close()
				return
			}
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				procErr = fmt.Errorf("the real process never listened on %s: %v", addr, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	if procErr != nil {
		t.Skipf("the real process could not be built or started: %v", procErr)
	}
	return procBase
}

// rawRoundTrip writes one raw HTTP/1.1 request over a bare TCP connection and
// returns the whole response. This is the only way to send request forms Go's
// own client refuses to build.
func rawRoundTrip(t *testing.T, request string, readWait time.Duration) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+edgePort, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(readWait))
	all, err := io.ReadAll(conn)
	if err != nil {
		return string(all), err
	}
	return string(all), nil
}

// statusOf extracts the numeric status from a raw response.
func statusOf(t *testing.T, raw string) int {
	t.Helper()
	line, _, _ := strings.Cut(raw, "\r\n")
	if line == "" {
		line = strings.TrimSpace(raw)
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		t.Fatalf("cannot read a status line out of %q", firstN(raw, 120))
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		t.Fatalf("status %q is not a number in %q", parts[1], firstN(raw, 120))
	}
	return code
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// TestZ06RealProcessHeaderCap: the shipped server caps headers at 64 KiB
// (main.go's maxHeaderBytes). A header block over the cap must be refused with
// 431, not read into memory and not 400'd after parsing.
func TestZ06RealProcessHeaderCap(t *testing.T) {
	realProcess(t)

	var b strings.Builder
	b.WriteString("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Filler: ")
	b.WriteString(strings.Repeat("a", 70<<10))
	b.WriteString("\r\nConnection: close\r\n\r\n")
	raw, err := rawRoundTrip(t, b.String(), 10*time.Second)
	if err != nil {
		t.Fatalf("reading the 431 response: %v (raw so far: %q)", err, firstN(raw, 200))
	}
	if code := statusOf(t, raw); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a 70 KiB header block answered %d, want 431:\n%s", code, firstN(raw, 300))
	}
}

// TestZ06RealProcessSlowHeaderIsCutOff: ReadHeaderTimeout (10s in the shipped
// server) must close a connection that never finishes its request line/headers.
// This is the slowloris bound; without it a handful of connections parks a
// goroutine and a file descriptor forever.
func TestZ06RealProcessSlowHeaderIsCutOff(t *testing.T) {
	realProcess(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+edgePort, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")); err != nil {
		t.Fatal(err)
	}
	// No terminating blank line: the header block never completes.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 256)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("an incomplete header block was answered instead of cut off: %q", buf)
	}
	elapsed := time.Since(start)
	if elapsed < 9*time.Second || elapsed > 15*time.Second {
		t.Fatalf("the slow-header connection was cut off after %s, want ~10s (ReadHeaderTimeout)", elapsed.Round(time.Second))
	}
}

// TestZ06RealProcessSlowBodyIsCutOff: ReadTimeout (30s in the shipped server)
// must close a connection whose body stalls, independent of the in-flight cap
// (the request never reaches a handler, so no middleware can refuse it).
func TestZ06RealProcessSlowBodyIsCutOff(t *testing.T) {
	realProcess(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+edgePort, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	head := "POST /oauth/token HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\n"
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	// Send a tenth of the body, then stall.
	if _, err := conn.Write([]byte(strings.Repeat("x", 10))); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	buf := make([]byte, 1024)
	n, rerr := conn.Read(buf)
	elapsed := time.Since(start)
	// The server may either close or answer nothing until the deadline; both
	// must happen by the ReadTimeout, not hang forever.
	if rerr == nil && n > 0 {
		t.Logf("the server answered the stalled body after %s: %.120s", elapsed.Round(time.Second), buf[:n])
	}
	if elapsed > 35*time.Second {
		t.Fatalf("the stalled body was still open after %s, want the 30s ReadTimeout to cut it off", elapsed.Round(time.Second))
	}
}

// TestZ06RealProcessCONNECTIsRefused: CONNECT bypasses the mux's path
// canonicalization by design (Go treats it specially), so it is the one method
// shape the in-process probes cannot assume. It must be refused, in some
// caller's shape, without taking the process down.
func TestZ06RealProcessCONNECTIsRefused(t *testing.T) {
	realProcess(t)

	raw, err := rawRoundTrip(t, "CONNECT 127.0.0.1:16601 HTTP/1.1\r\nHost: 127.0.0.1:16601\r\n\r\n", 10*time.Second)
	if err != nil && raw == "" {
		t.Fatalf("CONNECT got no answer at all: %v", err)
	}
	if code := statusOf(t, raw); code < 400 || code >= 500 {
		t.Fatalf("CONNECT answered %d, want a 4xx refusal:\n%s", code, firstN(raw, 300))
	}

	// The process must still be serving ordinary requests afterwards.
	resp, err := http.Get(procBase + "/healthz")
	if err != nil {
		t.Fatalf("the process is dead after CONNECT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz after CONNECT = %d, want 200", resp.StatusCode)
	}
}

// TestZ06RealProcessWellKnownVerbMatrix cross-checks the well-known verb
// matrix on the composed binary: the two discovery documents refuse unlisted
// verbs with 405, and the protected-resource document is the one the in-process
// probe found answering 404.
func TestZ06RealProcessWellKnownVerbMatrix(t *testing.T) {
	base := realProcess(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/.well-known/openid-configuration"},
		{http.MethodPost, "/.well-known/oauth-authorization-server"},
		{http.MethodPost, "/.well-known/oauth-protected-resource"},
		{http.MethodPut, "/.well-known/oauth-protected-resource"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, base+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s on the real process = %d, want 405 per the verb matrix: %s",
					tc.method, tc.path, resp.StatusCode, firstN(string(body), 200))
			}
		})
	}
}

// TestZ06RealProcessOversizedBodyIsRefused cross-checks the 413 on the
// composed binary (the in-process fixtures share the middleware; this proves
// the composition did not bypass it).
func TestZ06RealProcessOversizedBodyIsRefused(t *testing.T) {
	base := realProcess(t)

	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded",
		strings.NewReader("x="+strings.Repeat("a", 128<<10)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized POST on the real process = %d, want 413", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("413 Cache-Control = %q, want no-store", cc)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("413 Content-Type = %q, want the protocol plane's JSON", ct)
	}
}
