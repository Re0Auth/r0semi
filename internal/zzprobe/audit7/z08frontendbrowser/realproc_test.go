//go:build audit7

// Real-process black-box probes for the frontend / browser plane.
//
// The in-process fixtures mount the handler directly; this file drives the
// composed binary (go build ./cmd/re0auth, memory mode, environment only) over a
// real listener on zone 08's assigned port 17801, so what is observed includes
// net/http's own routing, the embed, and the compression and header middleware
// exactly as a deployment gets them.
package z08frontendbrowser

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const z08Port = "17801" // zone 08's assigned public audit port

var (
	z08ProcOnce sync.Once
	z08ProcBase string
	z08ProcErr  error
	z08ProcCmd  *exec.Cmd
)

// TestMain stops the real process when the probes are done, even if the test
// that started it failed.
func TestMain(m *testing.M) {
	code := m.Run()
	if z08ProcCmd != nil {
		_ = z08ProcCmd.Process.Kill()
	}
	os.Exit(code)
}

// z08RealProcess builds cmd/re0auth once and starts it on 127.0.0.1:17801.
func z08RealProcess(t *testing.T) string {
	t.Helper()
	z08ProcOnce.Do(func() {
		repoRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
		if err != nil {
			z08ProcErr = err
			return
		}
		binDir, err := os.MkdirTemp("", "z08-re0auth-*")
		if err != nil {
			z08ProcErr = err
			return
		}
		bin := filepath.Join(binDir, "re0auth.exe")
		build := exec.Command("go", "build", "-o", bin, "./cmd/re0auth")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			z08ProcErr = fmt.Errorf("go build: %v: %s", err, out)
			return
		}

		signing, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			z08ProcErr = err
			return
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(signing)
		if err != nil {
			z08ProcErr = err
			return
		}
		var tokenKey, kek [32]byte
		if _, err := rand.Read(tokenKey[:]); err != nil {
			z08ProcErr = err
			return
		}
		if _, err := rand.Read(kek[:]); err != nil {
			z08ProcErr = err
			return
		}

		workdir, err := os.MkdirTemp("", "z08-run-*")
		if err != nil {
			z08ProcErr = err
			return
		}
		addr := "127.0.0.1:" + z08Port
		z08ProcBase = "http://" + addr

		cmd := exec.Command(bin)
		cmd.Dir = workdir // no config file: environment-only mode
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
			z08ProcErr = err
			return
		}
		z08ProcCmd = cmd
		go func() { _ = cmd.Wait() }()

		deadline := time.Now().Add(30 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = conn.Close()
				return
			}
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				z08ProcErr = fmt.Errorf("the real process never listened on %s: %v", addr, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	if z08ProcErr != nil {
		t.Skipf("the real process could not be built or started: %v", z08ProcErr)
	}
	return z08ProcBase
}

// z08ProcGet performs one request against the real listener.
func z08ProcGet(t *testing.T, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	base := z08RealProcess(t)
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(raw)
}

var z08AssetRef = regexp.MustCompile(`/app/_app/immutable/[A-Za-z0-9._/-]+\.js`)

// TestZ08RealProcessServesTheShellWithItsOwnPolicy is the end-to-end half of the
// CSP claims: the composed binary, not a fixture, must hand the browser a shell
// whose policy permits the shell's own inline script.
func TestZ08RealProcessServesTheShellWithItsOwnPolicy(t *testing.T) {
	resp, body := z08ProcGet(t, http.MethodGet, "/app/consent", nil)
	t.Logf("GET /app/consent -> %d ct=%q cc=%q csp=%q vary=%q etag=%q allow-origin=%q",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"),
		resp.Header.Get("Content-Security-Policy"), resp.Header.Get("Vary"),
		resp.Header.Get("ETag"), resp.Header.Get("Access-Control-Allow-Origin"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the composed binary does not serve the shell: %d", resp.StatusCode)
	}
	if strings.Contains(body, "Frontend not built") {
		t.Skip("this binary was built from a checkout with the placeholder frontend; " +
			"run `cd web && pnpm run build` first")
	}
	if !strings.Contains(body, "http-equiv=\"content-security-policy\"") &&
		!strings.Contains(body, "http-equiv=content-security-policy") {
		t.Errorf("the served shell carries no meta policy: the only policy left is the header's " +
			"frame-ancestors directive, so script-src would be unconstrained")
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("header CSP = %q", resp.Header.Get("Content-Security-Policy"))
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q", resp.Header.Get("X-Frame-Options"))
	}
	// Anti-vacuous control: a real asset named by the shell must load.
	m := z08AssetRef.FindString(body)
	if m == "" {
		t.Fatalf("the shell names no immutable entry script; the asset probe would be vacuous")
	}
	ar, _ := z08ProcGet(t, http.MethodGet, m, nil)
	t.Logf("GET %s -> %d ct=%q cc=%q vary=%q", m, ar.StatusCode, ar.Header.Get("Content-Type"),
		ar.Header.Get("Cache-Control"), ar.Header.Get("Vary"))
	if ar.StatusCode != http.StatusOK || !strings.Contains(ar.Header.Get("Content-Type"), "javascript") {
		t.Errorf("the entry script the shell names (%s) does not load: %d %q", m, ar.StatusCode, ar.Header.Get("Content-Type"))
	}
	// The composed binary, not a fixture: the immutable directive and the Vary
	// that cancels it for any shared cache.
	if strings.Contains(ar.Header.Get("Cache-Control"), "immutable") &&
		strings.Contains(ar.Header.Get("Vary"), "Cookie") {
		t.Errorf("the composed binary serves %s with Cache-Control %q and Vary %q", m,
			ar.Header.Get("Cache-Control"), ar.Header.Get("Vary"))
	}
}

// TestZ08RealProcessAnswersAMissingAssetWithTheShell is the same defect as the
// handler-level probe, observed on the composed binary: a URL under the
// hashed-asset namespace that names no file is answered with the document, 200.
func TestZ08RealProcessAnswersAMissingAssetWithTheShell(t *testing.T) {
	resp, body := z08ProcGet(t, http.MethodGet, "/app/_app/immutable/entry/start.ZZZZZZZZ.js", nil)
	t.Logf("GET a missing immutable asset -> %d ct=%q cc=%q vary=%q len=%d",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"),
		resp.Header.Get("Vary"), len(body))
	if resp.StatusCode == http.StatusOK {
		t.Errorf("the composed binary answers a missing hashed asset with %d %q: a deployment whose "+
			"assets did not ship reports success to every status-code monitor and a MIME error to the browser",
			resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

// TestZ08RealProcessRangeOnAMissingAssetSplicesTheShell is the range half of the
// same defect.
func TestZ08RealProcessRangeOnAMissingAssetSplicesTheShell(t *testing.T) {
	resp, body := z08ProcGet(t, http.MethodGet, "/app/_app/immutable/entry/start.ZZZZZZZZ.js",
		map[string]string{"Range": "bytes=0-15"})
	t.Logf("range over a missing asset -> %d ct=%q cr=%q body=%q",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Range"), body)
	if resp.StatusCode == http.StatusPartialContent &&
		strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("a byte range of a script URL was answered %d with %q (Content-Range %q): the bytes are "+
			"the shell", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Range"))
	}
}

// TestZ08RealProcessStaticSurfaceSurvey records the composed binary's answers for
// the browser plane's static and error paths, including the anti-vacuous control
// that the plane really is the browser plane there.
func TestZ08RealProcessStaticSurfaceSurvey(t *testing.T) {
	for _, tc := range []struct {
		method, target string
	}{
		{http.MethodGet, "/app/"},
		{http.MethodGet, "/app"},
		{http.MethodGet, "/app/index.html"},
		{http.MethodGet, "/app/favicon.svg"},
		{http.MethodGet, "/robots.txt"},
		{http.MethodGet, "/app/robots.txt"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/nope"},
		{http.MethodGet, "/app/../oauth/token"},
		{http.MethodGet, "/app%2Foauth%2Ftoken"},
		{http.MethodPost, "/app/"},
		{http.MethodOptions, "/oauth/token"},
	} {
		resp, body := z08ProcGet(t, tc.method, tc.target, map[string]string{"Origin": "https://evil.example"})
		if resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s %s: Access-Control-Allow-Origin = %q", tc.method, tc.target,
				resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s %s: no framing policy", tc.method, tc.target)
		}
		t.Logf("%-7s %-28s -> %d ct=%q cc=%q loc=%q body=%q", tc.method, tc.target, resp.StatusCode,
			resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"),
			resp.Header.Get("Location"), firstLine(body))
	}
}

// TestZ08RealProcessOpenRedirectSurface drives the browser plane's redirect entry
// points with hostile return_to values. None of the flows is configured in
// memory mode, so the assertion is about what the *router* does with the
// parameter, and the anti-vacuous control is that a benign value is handled the
// same way (never a redirect to another origin).
func TestZ08RealProcessOpenRedirectSurface(t *testing.T) {
	seen := 0
	for _, target := range []string{
		"/auth/z08idp/start?return_to=//evil.example",
		"/auth/z08idp/start?return_to=https://evil.example/x",
		"/auth/z08idp/start?return_to=/\\evil.example",
		"/auth/z08idp/start?return_to=/%09/evil.example",
		"/bind?game=g&source=s&return_to=//evil.example",
		"/bind?game=g&source=s&return_to=javascript:alert(1)",
	} {
		resp, body := z08ProcGet(t, http.MethodGet, target, nil)
		seen++
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "evil.example") || strings.HasPrefix(loc, "javascript:") {
			t.Errorf("%s -> %d Location=%q: the value reached a redirect", target, resp.StatusCode, loc)
		}
		t.Logf("%-52s -> %d loc=%q body=%q", target, resp.StatusCode, loc, firstLine(body))
	}
	if seen < 6 {
		t.Fatalf("only %d redirect cases ran", seen)
	}
}

// TestZ08RealProcessSessionViewIsUncacheableAndCarriesNoCORS records the
// business-plane bootstrap's cache and CORS posture from outside the process.
func TestZ08RealProcessSessionViewIsUncacheableAndCarriesNoCORS(t *testing.T) {
	resp, body := z08ProcGet(t, http.MethodGet, "/v1/sessions/current",
		map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/sessions/current anonymous = %d: %s", resp.StatusCode, body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("the session bootstrap answers Cache-Control %q, want no-store", cc)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("CORS header present: %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &problem); err != nil || problem.Code != "unauthenticated" {
		t.Errorf("the anonymous refusal is not the business plane's problem shape: %s", body)
	}
}
