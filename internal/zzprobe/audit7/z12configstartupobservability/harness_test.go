//go:build audit7

package z12configstartupobservability

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// binPath is the real cmd/re0auth binary every black-box probe drives. It is
// built once, in TestMain, from the repository root rather than by importing the
// package: package main's loaders are unexported, and the point of these probes
// is the process's real entry point, not a call into an internal function.
var (
	binPath    string
	signingKey string
)

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "z12: cannot resolve the repository root:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "z12bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "z12: cannot make a build directory:", err)
		os.Exit(1)
	}
	name := "re0auth"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(dir, name)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/re0auth")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "z12: go build ./cmd/re0auth failed: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	cancel()

	// One RSA signing key for the probes that have to get a real process all the
	// way to a listener. Generating it here keeps the key generation out of the
	// measured runs.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z12: cannot generate a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z12: cannot marshal a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	signingKey = base64.StdEncoding.EncodeToString(der)

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// key32 builds the base64 of a 32-byte value whose seed is recognisable, so a
// leaked key can be spotted in a log by its encoding.
func key32(seed string) string {
	raw := make([]byte, 32)
	copy(raw, seed)
	return base64.StdEncoding.EncodeToString(raw)
}

// envWithoutRE0AUTH starts from the ambient environment with every variable this
// process reads stripped, so a probe's environment is exactly what it sets — the
// opposite of a probe that passes because the developer's shell happened to be
// configured.
func envWithoutRE0AUTH(extra map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "RE0AUTH_") || k == "DATABASE_URL" || strings.HasPrefix(k, "Z12_") {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

// runResult is one real-process run: its exit code and its whole output.
type runResult struct {
	code int
	out  string
}

// runBinary runs the built binary with exactly the environment given and returns
// its combined output and exit code. It runs in an empty directory so no
// config/re0auth.toml can be picked up by accident.
func runBinary(t *testing.T, env map[string]string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = envWithoutRE0AUTH(env)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running the binary failed: %v", err)
		}
		code = ee.ExitCode()
	}
	return runResult{code: code, out: buf.String()}
}

// writeConfig writes a TOML file and returns its absolute path.
func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// serverOnly is the minimal valid config skeleton: everything else comes from the
// environment.
const serverOnly = "[server]\nissuer = \"https://re0auth.test\"\n"

// minimalEnv is what a real run needs to reach the point a probe is aiming at:
// a valid KEK, an https issuer with a Secure cookie, and an unbindable address so
// the process returns instead of serving.
func minimalEnv() map[string]string {
	return map[string]string{
		"RE0AUTH_ISSUER":        "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE": "true",
		"RE0AUTH_KEK":           key32("Z12-KEK-MATERIAL-32-BYTES-AAA!"),
		"RE0AUTH_ADDR":          "not-an-address",
	}
}

// serveEnv is minimalEnv plus the OpenID Provider's two keys, so a configuration
// that loads gets past the OP wires and reaches the listener (or the
// operator-plane mount) instead of stopping at openOIDC.
func serveEnv() map[string]string {
	e := minimalEnv()
	e["RE0AUTH_OIDC_TOKEN_KEY"] = key32("Z12-OP-TOKEN-KEY-MATERIAL-32E!")
	e["RE0AUTH_OIDC_SIGNING_KEY"] = signingKey
	return e
}

// oneLine returns the last line of a log, for a t.Logf that does not bury the
// result under a whole startup log.
func oneLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}
