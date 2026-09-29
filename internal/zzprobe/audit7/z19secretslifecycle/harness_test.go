//go:build audit7

package z19secretslifecycle

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
	"sync"
	"testing"
	"time"
)

// binPath is the real cmd/re0auth binary. Every probe in this package drives the
// process's real entry point rather than an unexported loader: cmd/re0auth's
// loadConfig and the secret readers are package-private, and a black-box run is
// what actually writes the log an operator reads.
var (
	binPath    string
	signingKey string
)

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19: cannot resolve the repository root:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "z19bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19: cannot make a build directory:", err)
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
		fmt.Fprintf(os.Stderr, "z19: go build ./cmd/re0auth failed: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	cancel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19: cannot generate a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "z19: cannot marshal a signing key:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	signingKey = base64.StdEncoding.EncodeToString(der)

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// key32 builds the base64 of a 32-byte value with a recognisable seed, so a
// planted key can be spotted in a log by its own encoding.
func key32(seed string) string {
	raw := make([]byte, 32)
	copy(raw, seed)
	return base64.StdEncoding.EncodeToString(raw)
}

// envWithoutSecrets starts from the ambient environment with every variable this
// process reads stripped, so a probe observes exactly what it planted.
func envWithoutSecrets(extra map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "RE0AUTH_") || k == "DATABASE_URL" || strings.HasPrefix(k, "Z19_") {
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

// runBinary runs the built binary with exactly the environment given and returns
// its whole output and exit code. It runs in an empty directory so a stray
// config/re0auth.toml cannot be picked up.
func runBinary(t *testing.T, env map[string]string, args ...string) runResult {
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

func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// A real serving process, for the probes that need the whole composition root.
// ---------------------------------------------------------------------------

// z19Port is zone 19's allocation: 17000+100*19+1. The internal listener takes
// the next slot (+50), which is also the convention.
const (
	z19PublicPort   = 18901
	z19InternalPort = 18951
)

// lockedBuffer is a strings.Builder safe to read while the child process is
// still writing to it.
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

// server is one running process under test.
type server struct {
	base string
	log  *lockedBuffer
	cmd  *exec.Cmd
	done chan struct{}
}

func (s *server) stop() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(os.Interrupt)
	}
	select {
	case <-s.done:
	case <-time.After(20 * time.Second):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		<-s.done
	}
}

// startServer boots the binary in memory mode and waits until it answers
// /readyz. secrets are the recognisable values the caller planted.
func startServer(t *testing.T, secrets map[string]string) (*server, map[string]string) {
	t.Helper()

	cfgPath := writeConfig(t, "serve.toml", fmt.Sprintf(
		"[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\ninternal_addr = \"127.0.0.1:%d\"\n"+
			"[client]\nid = \"cli\"\nname = \"Probe client\"\nsecret_env = \"Z19_CLIENT_SECRET\"\n",
		z19PublicPort, z19PublicPort, z19InternalPort))

	env := map[string]string{
		"RE0AUTH_CONFIG":           cfgPath,
		"RE0AUTH_KEK":              key32("Z19-KEK-MATERIAL-32-BYTES-AAA"),
		"RE0AUTH_OIDC_TOKEN_KEY":   key32("Z19-OP-TOKEN-KEY-MATERIAL-32B"),
		"RE0AUTH_OIDC_SIGNING_KEY": signingKey,
		"RE0AUTH_CLIENT_ID":        "cli",
		"Z19_CLIENT_SECRET":        secrets["client_secret"],
	}

	cmd := exec.Command(binPath, "-config", cfgPath)
	cmd.Dir = t.TempDir()
	cmd.Env = envWithoutSecrets(env)
	log := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the binary: %v", err)
	}
	s := &server{
		base: fmt.Sprintf("http://127.0.0.1:%d", z19PublicPort),
		log:  log,
		cmd:  cmd,
		done: make(chan struct{}),
	}
	go func() { _ = cmd.Wait(); close(s.done) }()
	t.Cleanup(s.stop)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if code, _, err := httpGet(s.base+"/readyz", 2*time.Second); err == nil && code < 500 {
			t.Logf("z19: process serving on %s (readyz=%d)", s.base, code)
			return s, env
		}
		select {
		case <-s.done:
			t.Fatalf("the process exited before serving:\n%s", log.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the process never answered /readyz:\n%s", log.String())
	return nil, nil
}
