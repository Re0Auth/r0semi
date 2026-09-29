//go:build audit6

// Shared fixtures for the zone-03 probes. Read-only with respect to the
// repository: these tests only build the real binary and run it, never modify
// tracked files.
package z03crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// errProbeSink is the error the failing audit logger returns.
var errProbeSink = errors.New("probe: audit sink unreachable")

// userID builds an account id the way the federation package expects.
func userID(s string) account.UserID { return account.UserID(s) }

// writeFile is os.WriteFile with the permissions a config file deserves.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// failingLogger is an audit.Logger whose sink is down: every Record fails with
// err. It stands in for the durable chain being unwritable while the
// vault_credentials table itself still accepts writes.
type failingLogger struct{ err error }

func (f failingLogger) Record(context.Context, audit.Event) error { return f.err }

// probeKEK and probeTokKey are distinct 32-byte values, base64-shaped the way
// the documentation tells an operator to produce them.
var (
	probeKEK    = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	probeTokKey = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
)

// serverBin is the real cmd/re0auth binary, built once for the package.
var (
	serverBin    string
	oidcSignKey  string
	buildFailure string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "re0auth-z03crypto-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "tempdir:", err)
		os.Exit(1)
	}
	serverBin = filepath.Join(dir, "re0auth.exe")
	if out, err := exec.Command("go", "build", "-o", serverBin,
		"github.com/Re0Auth/r0semi/cmd/re0auth").CombinedOutput(); err != nil {
		buildFailure = string(out)
		serverBin = ""
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsa:", err)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	oidcSignKey = base64.StdEncoding.EncodeToString(der)

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func requireBinary(t *testing.T) {
	t.Helper()
	if serverBin == "" {
		t.Fatalf("the server binary did not build:\n%s", buildFailure)
	}
}

// mustWrapper builds a local KeyWrapper with explicit material, so two wrappers
// can differ in material, in id, or both.
func mustWrapper(t *testing.T, id string, material byte) *vault.LocalKeyWrapper {
	t.Helper()
	w, err := vault.NewLocalKeyWrapper(id, bytes.Repeat([]byte{material}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// mustService wires a vault.Service; the caller supplies the logger so a probe
// can hand it a failing one.
func mustService(t *testing.T, repo vault.Repo, kek vault.KeyWrapper, logger audit.Logger, opts ...vault.Option) vault.Service {
	t.Helper()
	svc, err := vault.NewService(repo, kek, logger, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// useSecret reads a credential through the real Use path.
func useSecret(t *testing.T, svc vault.Service, id vault.Identity) (string, error) {
	t.Helper()
	var got string
	err := svc.Use(context.Background(), id, func(plain []byte) error {
		got = string(plain)
		return nil
	})
	return got, err
}

// bindingSecretJSON is the shape federation stores in the vault; reading it
// back as a map keeps the probe independent of the unexported struct.
func accessTokenOf(t *testing.T, blob []byte) string {
	t.Helper()
	var pair map[string]string
	if err := json.Unmarshal(blob, &pair); err != nil {
		t.Fatalf("the vault blob is not a binding secret: %v", err)
	}
	return pair["access_token"]
}

// fakeUpstream is an OAuth authorization server whose token endpoint returns
// one token per client id, so two sources handed different client ids end up
// holding different credentials. The client id is read from the Basic
// credentials golang.org/x/oauth2 sends (with a form fallback), and
// /oauth/revoke answers 200 so the unbind path completes its upstream half.
func newFakeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	clientID := func(r *http.Request) string {
		if cid := r.PostFormValue("client_id"); cid != "" {
			return cid
		}
		if user, _, ok := r.BasicAuth(); ok {
			return user
		}
		return ""
	}
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cid := clientID(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "token-for-" + cid,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-" + cid,
		})
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// zonePublicAddr is this zone's assigned public-facing port; every probe that
// needs a serving process uses it, one at a time.
const zonePublicAddr = "127.0.0.1:16301"

// cleanEnv strips every Re0Auth variable from the test process's environment,
// so nothing inherited can explain a server's behaviour.
func cleanEnv(extra map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra)+4)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		if strings.HasPrefix(up, "RE0AUTH_") || up == "DATABASE_URL" {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

// baseEnv is the environment of a minimal, environment-only, memory-mode
// server bound to this zone's public port.
func baseEnv() map[string]string {
	return map[string]string{
		"RE0AUTH_KEK":              probeKEK,
		"RE0AUTH_OIDC_TOKEN_KEY":   probeTokKey,
		"RE0AUTH_OIDC_SIGNING_KEY": oidcSignKey,
		"RE0AUTH_ISSUER":           "http://" + zonePublicAddr,
		"RE0AUTH_ADDR":             zonePublicAddr,
	}
}

// proc is one real re0auth process, its output captured to a file.
type proc struct {
	t        *testing.T
	cmd      *exec.Cmd
	logPath  string
	waitErr  chan error
	stopOnce sync.Once
}

// startProcess runs the real binary with the given environment and arguments,
// in a fresh temporary directory (so the default config path resolves to
// nothing and the process runs environment-only).
func startProcess(t *testing.T, env map[string]string, args ...string) *proc {
	t.Helper()
	requireBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "out.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(serverBin, args...)
	cmd.Dir = dir
	cmd.Env = cleanEnv(env)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	// The child holds its own inherited handle; ours can close now.
	_ = f.Close()
	p := &proc{t: t, cmd: cmd, logPath: logPath, waitErr: make(chan error, 1)}
	go func() { p.waitErr <- cmd.Wait() }()
	t.Cleanup(func() { p.stop() })
	return p
}

func (p *proc) stop() {
	// Idempotent: the test body may stop the process itself, and the cleanup
	// runs again afterwards — the second run must not sit out the timeout.
	p.stopOnce.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		select {
		case <-p.waitErr:
		case <-time.After(5 * time.Second):
		}
	})
}

func (p *proc) log() string {
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// waitServing polls /healthz until the process answers, so a probe's later
// assertions cannot pass because the server never came up.
func (p *proc) waitServing() {
	p.t.Helper()
	base := "http://" + zonePublicAddr
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.waitErr:
			p.waitErr <- err
			p.t.Fatalf("the server exited before serving (%v); log:\n%s", err, p.log())
		default:
		}
		resp, err := (&http.Client{Timeout: time.Second}).Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.t.Fatalf("the server never served %s/healthz; log:\n%s", base, p.log())
}

// runToExit runs the binary to completion and returns its exit code and full
// output. A guard timer kills it if it starts serving instead of exiting.
func runToExit(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	requireBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "out.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(serverBin, args...)
	cmd.Dir = dir
	cmd.Env = cleanEnv(env)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running the server: %v", err)
		}
		out, rerr := os.ReadFile(logPath)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return code, string(out)
	case <-time.After(60 * time.Second):
		// Generous on purpose: this machine runs parallel audit agents, and a
		// load spike making a refusing startup take longer than 30s would turn
		// a green guard red for no reason. A genuinely serving process is still
		// killed and failed.
		_ = cmd.Process.Kill()
		<-done
		out, _ := os.ReadFile(logPath)
		t.Fatalf("the server did not exit within 60s (it is serving); output:\n%s", string(out))
		return 0, string(out)
	}
}
