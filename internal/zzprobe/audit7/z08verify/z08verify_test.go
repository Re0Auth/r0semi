//go:build audit7

// Zone 08 adversarial re-verification probes (round 7).
//
// These do not reuse the audited zone's fixture: they drive the composed binary
// (go build ./cmd/re0auth, memory mode, environment only) on the verifier's own
// port 17802. That settles, independently of the author's harness:
//
//   - the static-surface header facts behind Z08-1 / Z08-2 / Z08-5 (including a
//     positive control that the same probe really reaches the file server), and
//   - whether the audited "open redirect surface" green actually reaches a
//     redirect at all.
package z08verify

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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const z08vPort = "17802" // zone 08 verifier's assigned public port

var (
	z08vOnce sync.Once
	z08vBase string
	z08vErr  error
	z08vCmd  *exec.Cmd
)

func TestMain(m *testing.M) {
	code := m.Run()
	if z08vCmd != nil {
		_ = z08vCmd.Process.Kill()
	}
	os.Exit(code)
}

func z08vProcess(t *testing.T) string {
	t.Helper()
	z08vOnce.Do(func() {
		repoRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
		if err != nil {
			z08vErr = err
			return
		}
		binDir, err := os.MkdirTemp("", "z08v-re0auth-*")
		if err != nil {
			z08vErr = err
			return
		}
		bin := filepath.Join(binDir, "re0auth.exe")
		build := exec.Command("go", "build", "-o", bin, "./cmd/re0auth")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			z08vErr = fmt.Errorf("go build: %v: %s", err, out)
			return
		}
		signing, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			z08vErr = err
			return
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(signing)
		if err != nil {
			z08vErr = err
			return
		}
		var tokenKey, kek [32]byte
		if _, err := rand.Read(tokenKey[:]); err != nil {
			z08vErr = err
			return
		}
		if _, err := rand.Read(kek[:]); err != nil {
			z08vErr = err
			return
		}
		workdir, err := os.MkdirTemp("", "z08v-run-*")
		if err != nil {
			z08vErr = err
			return
		}
		addr := "127.0.0.1:" + z08vPort
		z08vBase = "http://" + addr
		cmd := exec.Command(bin)
		cmd.Dir = workdir
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
			z08vErr = err
			return
		}
		z08vCmd = cmd
		go func() { _ = cmd.Wait() }()
		deadline := time.Now().Add(30 * time.Second)
		for {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = c.Close()
				return
			}
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				z08vErr = fmt.Errorf("the real process never listened on %s: %v", addr, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	if z08vErr != nil {
		t.Skipf("could not build or start cmd/re0auth: %v", z08vErr)
	}
	return z08vBase
}

func z08vGet(t *testing.T, method, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, z08vProcess(t)+path, nil)
	if err != nil {
		t.Fatal(err)
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

var z08vAssetRef = regexp.MustCompile(`/app/_app/immutable/[A-Za-z0-9._/-]+\.js`)

// TestZ08VComposedStaticFacts re-derives the Z08-1 / Z08-2 / Z08-5 header facts
// from a binary this probe built itself, with the file server's positive control
// built in: the shell names a real asset, and that asset must come back as JS.
func TestZ08VComposedStaticFacts(t *testing.T) {
	shellResp, shell := z08vGet(t, http.MethodGet, "/app/consent")
	if shellResp.StatusCode != http.StatusOK || !strings.Contains(shell, "<!doctype html") {
		t.Fatalf("no shell: %d %q", shellResp.StatusCode, shell[:min(len(shell), 80)])
	}
	t.Logf("shell: cc=%q vary=%q etag=%q last-modified=%q len=%d",
		shellResp.Header.Get("Cache-Control"), shellResp.Header.Get("Vary"),
		shellResp.Header.Get("ETag"), shellResp.Header.Get("Last-Modified"), len(shell))

	// Z08-2: no validator on a response that says "revalidate".
	if shellResp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("the shell is not no-cache (%q); the validator question does not arise",
			shellResp.Header.Get("Cache-Control"))
	}
	if shellResp.Header.Get("ETag") != "" || shellResp.Header.Get("Last-Modified") != "" {
		t.Errorf("a validator appeared (etag=%q lm=%q): Z08-2's mechanism would need revisiting",
			shellResp.Header.Get("ETag"), shellResp.Header.Get("Last-Modified"))
	}

	// Positive control: the file server is genuinely reachable.
	asset := z08vAssetRef.FindString(shell)
	if asset == "" {
		t.Fatal("the shell names no immutable asset; the rest of this probe would be vacuous")
	}
	ar, _ := z08vGet(t, http.MethodGet, asset)
	t.Logf("real asset %s: %d ct=%q cc=%q vary=%q etag=%q lm=%q", asset,
		ar.StatusCode, ar.Header.Get("Content-Type"), ar.Header.Get("Cache-Control"),
		ar.Header.Get("Vary"), ar.Header.Get("ETag"), ar.Header.Get("Last-Modified"))
	if ar.StatusCode != http.StatusOK || !strings.Contains(ar.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("the asset the shell names does not load: %d %q", ar.StatusCode, ar.Header.Get("Content-Type"))
	}

	// Z08-5: the immutable directive and the session middleware's Vary coexist.
	if !strings.Contains(ar.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("the asset lost its immutable directive: %q", ar.Header.Get("Cache-Control"))
	}
	if !strings.Contains(ar.Header.Get("Vary"), "Cookie") {
		t.Errorf("no Vary: Cookie on the asset (%q) — Z08-5's mechanism is not reproduced here",
			ar.Header.Get("Vary"))
	}
	if !strings.Contains(ar.Header.Get("Vary"), "Accept-Encoding") {
		t.Errorf("the asset lost Vary: Accept-Encoding (%q)", ar.Header.Get("Vary"))
	}

	// Z08-1: a name that is not a file is answered with the same document, and
	// the byte count proves it is the shell and not some error page.
	miss := strings.TrimSuffix(asset, ".js") + ".ZZZZZZZZ.js"
	mr, mbody := z08vGet(t, http.MethodGet, miss)
	t.Logf("missing asset %s: %d ct=%q cc=%q len=%d (shell len=%d)", miss,
		mr.StatusCode, mr.Header.Get("Content-Type"), mr.Header.Get("Cache-Control"), len(mbody), len(shell))
	if mr.StatusCode != http.StatusOK || !strings.Contains(mr.Header.Get("Content-Type"), "text/html") {
		t.Errorf("a missing hashed asset is no longer answered with the shell: %d %q — Z08-1's mechanism changed",
			mr.StatusCode, mr.Header.Get("Content-Type"))
	}
	if len(mbody) != len(shell) {
		t.Errorf("the fallback body is %d bytes but the shell is %d; the fallback may no longer be index.html",
			len(mbody), len(shell))
	}
}

// TestZ08VOpenRedirectGreenIsVacuous settles the audited "open redirect surface"
// green (§探过没破 20). In memory mode with no IdP configured, /auth/<p>/start
// answers 404 "unknown provider" and /bind answers 401 for an anonymous caller,
// so no redirect sink is ever reached. A 302 carrying the hostile value would be
// a real open redirect; today the observation is the vacuum.
func TestZ08VOpenRedirectGreenIsVacuous(t *testing.T) {
	for _, target := range []string{
		"/auth/z08idp/start?return_to=//evil.example",
		"/auth/z08idp/start?return_to=https://evil.example/x",
		"/bind?game=g&source=s&return_to=//evil.example",
		"/bind?game=g&source=s&return_to=javascript:alert(1)",
	} {
		resp, body := z08vGet(t, http.MethodGet, target)
		loc := resp.Header.Get("Location")
		t.Logf("%-52s -> %d loc=%q body=%q", target, resp.StatusCode, loc, strings.TrimSpace(body))
		if strings.Contains(loc, "evil.example") || strings.HasPrefix(loc, "javascript:") {
			t.Errorf("%s -> %d Location=%q: a hostile return_to reached a redirect", target, resp.StatusCode, loc)
		}
		if resp.StatusCode == http.StatusFound && loc != "" {
			t.Logf("%s DID reach a redirect (%q), so the audited green would be meaningful here", target, loc)
		}
	}
}
