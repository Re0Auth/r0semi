//go:build audit7

package z19verify

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

var (
	binPath    string
	signingKey string
)

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19verify: cannot resolve the repository root:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "z19vbin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19verify: cannot make a build directory:", err)
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
		fmt.Fprintf(os.Stderr, "z19verify: go build ./cmd/re0auth failed: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	cancel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19verify: cannot generate a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19verify: cannot marshal a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	signingKey = base64.StdEncoding.EncodeToString(der)

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func key32(seed string) string {
	raw := make([]byte, 32)
	copy(raw, seed)
	return base64.StdEncoding.EncodeToString(raw)
}

func envWithoutSecrets(extra map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "RE0AUTH_") || k == "DATABASE_URL" || strings.HasPrefix(k, "Z19V") {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

type runResult struct {
	code int
	out  string
}

func runBinary(t *testing.T, env map[string]string) runResult {
	t.Helper()
	return runBinaryArgs(t, env, "-config", "")
}

func runBinaryArgs(t *testing.T, env map[string]string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = envWithoutSecrets(env)
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
