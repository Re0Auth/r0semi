//go:build audit7

package z17docscontractdrift

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// z17Port is the real-process port the round-7 brief assigns to zone 17.
const z17Port = 18701

// binary is the composition root built once for every probe in this package.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "z17docs")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}

	root, err := findRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	exe := filepath.Join(dir, "re0auth.exe")
	out, err := runOnce(root, nil, 5*time.Minute,
		"go", "build", "-o", exe, "./cmd/re0auth")
	if err != nil {
		fmt.Fprintf(os.Stderr, "build cmd/re0auth failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	binary = exe
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// baseEnv is the ambient environment with every database/Re0Auth variable
// removed, so an operator's own DATABASE_URL cannot reach a probe.
func baseEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(name, "RE0AUTH_"):
			continue
		case name == "DATABASE_URL", name == "TEST_DATABASE_URL", name == "E2E_DATABASE_URL", name == "RE0AUTH_CONFIG":
			continue
		}
		out = append(out, kv)
	}
	return out
}

func envWith(extra map[string]string) []string {
	env := baseEnv()
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// runProcess runs the binary and returns its exit code and combined output. The
// output is written to a real file rather than a pipe: the sandbox forbids
// named pipes for captured stdio, and a file works in every mode.
func runProcess(t *testing.T, env []string, timeout time.Duration, args ...string) (int, string) {
	t.Helper()
	code, out, err := runCommand(t, binary, env, timeout, args...)
	if err != nil && code == 0 {
		t.Fatalf("run %v: %v\n%s", args, err, out)
	}
	return code, out
}

func runOnce(dir string, env []string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	f, err := os.CreateTemp("", "z17out-*.log")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	cmd.Stdout, cmd.Stderr = f, f
	runErr := cmd.Run()
	f.Close()
	data, _ := os.ReadFile(f.Name())
	return string(data), runErr
}

func runCommand(t *testing.T, name string, env []string, timeout time.Duration, args ...string) (int, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	f, err := os.CreateTemp(t.TempDir(), "out-*.log")
	if err != nil {
		t.Fatalf("temp output: %v", err)
	}
	defer f.Close()
	cmd.Stdout, cmd.Stderr = f, f
	runErr := cmd.Run()
	data, _ := os.ReadFile(f.Name())
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return 0, string(data), runErr
		}
		code = ee.ExitCode()
	}
	return code, string(data), nil
}

// testKeys builds the four secrets the quickstart exports.
type testKeys struct {
	kek, audit, token string
	signing           string
}

func makeKeys(t *testing.T) testKeys {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	audit := make([]byte, 32)
	if _, err := rand.Read(audit); err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{
		kek:     base64.StdEncoding.EncodeToString(kek),
		audit:   base64.StdEncoding.EncodeToString(audit),
		token:   base64.StdEncoding.EncodeToString(token),
		signing: base64.StdEncoding.EncodeToString(der),
	}
}

// TestZ17ReadmeQuickstartCannotStartWithTheShippedExample is Z17-1.
//
// README.md's quickstart is: copy config/re0auth.example.toml, export the five
// variables it lists, run. The copy declares two IdP client secrets by name
// ([idp.github], [idp.google]); internal/config.Secret refuses an unset one, so
// the documented path stops while loading the configuration, before the
// listener is ever opened. This probe requires the documented invocation to get
// past configuration, and FAILS when it does not.
func TestZ17ReadmeQuickstartCannotStartWithTheShippedExample(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(cfg, []byte(readFile(t, filepath.Join(root, "config", "re0auth.example.toml"))), 0o600); err != nil {
		t.Fatal(err)
	}
	k := makeKeys(t)

	// Exactly the README quickstart's exports. DATABASE_URL points at a closed
	// port: the probe must not depend on a database, and config loading never
	// opens the connection.
	quickstart := map[string]string{
		"RE0AUTH_KEK":              k.kek,
		"DATABASE_URL":             "postgres://user:pass@127.0.0.1:1/re0auth?sslmode=disable",
		"RE0AUTH_AUDIT_KEY":        k.audit,
		"RE0AUTH_OIDC_TOKEN_KEY":   k.token,
		"RE0AUTH_OIDC_SIGNING_KEY": k.signing,
	}

	// Positive control: with the two IdP secrets the sample declares also set,
	// the same invocation reaches the storage stage. That is where the
	// documented run should get to; it proves the probe drives a real startup
	// rather than dying on something structural.
	control := map[string]string{}
	for key, value := range quickstart {
		control[key] = value
	}
	control["GITHUB_CLIENT_SECRET"] = "x"
	control["GOOGLE_CLIENT_SECRET"] = "y"
	_, controlOut := runProcess(t, envWith(control), 90*time.Second, "-config", cfg)
	if !strings.Contains(controlOut, "stage=storage") {
		t.Fatalf("positive control did not reach `stage=storage`; the probe proves nothing:\n%s", controlOut)
	}

	_, out := runProcess(t, envWith(quickstart), 90*time.Second, "-config", cfg)
	if strings.Contains(out, "stage=storage") {
		return // the documented quickstart got past configuration: nothing to report.
	}
	t.Errorf("README.md's quickstart (`cp config/re0auth.example.toml` + its five exports) "+
		"refuses to start while loading the shipped example, which declares [idp.github] and "+
		"[idp.google] client secrets the quickstart never sets:\n%s", firstLines(out, 3))
}

// TestZ17ReadmeMemorySnippetCannotStart is the flipped form of Z17-2; the name is
// kept so the coverage matrix still maps here.
//
// The finding was: README.md's environment-only, in-memory snippet showed only
// RE0AUTH_ISSUER and RE0AUTH_KEK, while the https issuer needs cookie_secure and
// the two OP keys are required in memory mode too — so the documented invocation
// could not reach a listener. The document has since been fixed (README.md's
// snippet now carries cookie_secure and both OP keys).
//
// The guard now reads the snippet from README itself and requires it to serve
// /healthz, and names the five variables the surrounding text calls mandatory. The
// anti-vacuity control runs the PRE-FIX shape (ISSUER + KEK only) and requires it
// to FAIL, so a snippet that dropped a key again cannot pass unnoticed.
func TestZ17ReadmeMemorySnippetCannotStart(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.toml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k := makeKeys(t)
	addr := fmt.Sprintf("127.0.0.1:%d", z17Port)

	// The documented snippet, read from README rather than hard-coded: the probe's
	// contract is "what the README shows", so it must follow the document.
	readme := readFile(t, filepath.Join(repoRoot(t), "README.md"))
	names := readmeMemorySnippetNames(t, readme)
	for _, want := range []string{
		"RE0AUTH_ISSUER", "RE0AUTH_KEK", "RE0AUTH_COOKIE_SECURE",
		"RE0AUTH_OIDC_TOKEN_KEY", "RE0AUTH_OIDC_SIGNING_KEY",
	} {
		if !names[want] {
			t.Errorf("README.md's memory-mode snippet no longer sets %s, which the surrounding text "+
				"calls mandatory in this mode; the documented invocation cannot start", want)
		}
	}

	// RE0AUTH_ADDR is a harness accommodation so the probe cannot collide with
	// another listener; it changes only where it would bind.
	env := map[string]string{"RE0AUTH_ADDR": addr}
	for name := range names {
		switch name {
		case "RE0AUTH_ISSUER":
			env[name] = "https://re0auth.example"
		case "RE0AUTH_KEK":
			env[name] = k.kek
		case "RE0AUTH_COOKIE_SECURE":
			env[name] = "true"
		case "RE0AUTH_OIDC_TOKEN_KEY":
			env[name] = k.token
		case "RE0AUTH_OIDC_SIGNING_KEY":
			env[name] = k.signing
		default:
			t.Fatalf("the README snippet now documents %s, which this probe cannot generate a value for; "+
				"re-derive Z17-2", name)
		}
	}
	if served, log := tryServe(t, env, empty, addr); !served {
		t.Errorf("README.md's memory-mode snippet does not start as written: it is refused during "+
			"configuration or never serves /healthz. Observed:\n%s", firstLines(log, 4))
	}

	// Anti-vacuity: the pre-fix snippet (ISSUER + KEK only) must still fail. If it
	// served, this probe could not tell a complete snippet from an incomplete one.
	preFix := map[string]string{
		"RE0AUTH_ISSUER": "https://re0auth.example",
		"RE0AUTH_KEK":    k.kek,
		"RE0AUTH_ADDR":   addr,
	}
	if served, _ := tryServe(t, preFix, empty, addr); served {
		t.Fatal("control: ISSUER + KEK alone served /healthz, so this guard cannot detect a snippet that " +
			"drops the mandatory keys; it is vacuous")
	}
}

// readmeMemorySnippetNames returns the RE0AUTH_* names README's environment-only
// startup block sets. That block is the `sh` fence whose command is `./re0auth`
// without `-config` (the config-file quickstart carries `-config`).
func readmeMemorySnippetNames(t *testing.T, readme string) map[string]bool {
	t.Helper()
	blocks := regexp.MustCompile("(?s)```sh\\n(.*?)```").FindAllStringSubmatch(readme, -1)
	var block string
	for _, m := range blocks {
		if strings.Contains(m[1], "./re0auth") && !strings.Contains(m[1], "-config") {
			block = m[1]
			break
		}
	}
	if block == "" {
		t.Fatalf("README.md no longer has an environment-only ./re0auth snippet; re-derive Z17-2")
	}
	names := map[string]bool{}
	for _, name := range regexp.MustCompile(`RE0AUTH_[A-Z0-9_]+`).FindAllString(block, -1) {
		names[name] = true
	}
	return names
}

// tryServe starts the binary and reports whether /healthz answered 200 within
// 25 seconds, along with the process log. A process that exits early is
// reported immediately; either way it is killed.
func tryServe(t *testing.T, env map[string]string, cfg, addr string) (bool, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "serve-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cmd := exec.Command(binary, "-config", cfg)
	cmd.Env = envWith(env)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waited)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()

	url := fmt.Sprintf("http://%s/healthz", addr)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-waited:
			data, _ := os.ReadFile(f.Name())
			return false, string(data)
		default:
		}
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				data, _ := os.ReadFile(f.Name())
				return true, string(data) + "\nhealthz: " + strings.TrimSpace(string(body))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	data, _ := os.ReadFile(f.Name())
	return false, string(data)
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
