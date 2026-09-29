//go:build audit7

// Z12-VERIFY: black-box probes against the real cmd/re0auth binary, aimed at the
// loader spellings the reporter measured only through one path.
package z12verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var binPath string
var signingKey string

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "z12vbin")
	if err != nil {
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
		os.Stderr.WriteString("z12verify: build failed: " + err.Error() + "\n" + string(out) + "\n")
		os.RemoveAll(dir)
		os.Exit(1)
	}
	cancel()
	// One real RSA key, so the probes that need to get past the OP wires can.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.RemoveAll(dir)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		os.RemoveAll(dir)
		os.Exit(1)
	}
	signingKey = base64.StdEncoding.EncodeToString(der)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// key32 turns a recognisable 32-byte seed into the base64 the loader documents.
func key32(seed string) string {
	raw := make([]byte, 32)
	copy(raw, seed)
	return base64.StdEncoding.EncodeToString(raw)
}

// runBinary is this package's own copy of the reporter's runner: a fresh empty
// working directory and only the environment given.
func runBinary(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = t.TempDir()
	base := make([]string, 0, len(os.Environ())+len(env))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "RE0AUTH_") || k == "DATABASE_URL" {
			continue
		}
		base = append(base, kv)
	}
	for k, v := range env {
		base = append(base, k+"="+v)
	}
	cmd.Env = base
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running the binary: %v", err)
		}
	}
	return code, string(out)
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseEnv reaches stage=listen (a clean configuration with an unbindable
// address), so a probe can tell "the loader refused this" from "the loader took
// it and the process got on with starting". The OP keys are present because
// openOIDC runs before the listener.
func baseEnv() map[string]string {
	return map[string]string{
		"RE0AUTH_ISSUER":           "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":    "true",
		"RE0AUTH_KEK":              key32("Z12V-KEK-MATERIAL-32-BYTES-AAA!"),
		"RE0AUTH_ADDR":             "not-an-address",
		"RE0AUTH_STORAGE_DRIVER":   "memory",
		"RE0AUTH_OIDC_TOKEN_KEY":   key32("Z12V-OP-TOKEN-KEY-32-BYTES-AA!"),
		"RE0AUTH_OIDC_SIGNING_KEY": signingKey,
	}
}

// TestZ12VerifyTOMLNaNIsAlsoAccepted closes Z12-6's own residual blind spot
// ("TOML 的 nan 字面量是否被 BurntSushi 解析成 NaN 未实跑"). Two spellings are
// tried, and the control proves the file path reaches the limiter at all: a
// numeric value must be accepted, and a malformed one must be refused by the
// loader.
func TestZ12VerifyTOMLNaNIsAlsoAccepted(t *testing.T) {
	tmpl := "[server]\nissuer = \"https://re0auth.test\"\nrate_limit = %s\n"

	// Control A: an ordinary number is accepted and the run reaches the listener.
	if code, out := runBinary(t, baseEnv(), "-config", writeFile(t, "ok.toml", strings.Replace(tmpl, "%s", "50", 1))); !strings.Contains(out, "stage=listen") {
		t.Fatalf("control failed: rate_limit = 50 did not reach the listener (exit %d):\n%s", code, out)
	}
	// Control B: a non-numeric literal is refused by the loader.
	if _, out := runBinary(t, baseEnv(), "-config", writeFile(t, "bad.toml", strings.Replace(tmpl, "%s", "\"abc\"", 1))); !strings.Contains(out, "stage=config") {
		t.Fatalf("control failed: rate_limit = \"abc\" was not refused at the config stage:\n%s", out)
	}

	for _, literal := range []string{"nan", "NaN"} {
		code, out := runBinary(t, baseEnv(), "-config", writeFile(t, "nan.toml", strings.Replace(tmpl, "%s", literal, 1)))
		accepted := strings.Contains(out, "stage=listen")
		t.Logf("rate_limit = %s -> exit %d, reached listener: %v", literal, code, accepted)
		if !accepted {
			if strings.Contains(out, "stage=config") {
				t.Logf("rate_limit = %s was refused by the loader (so this spelling is safe)", literal)
				continue
			}
			t.Fatalf("rate_limit = %s neither reached the listener nor was refused at the config stage:\n%s", literal, out)
		}
		t.Errorf("rate_limit = %s in the TOML file was accepted (the run reached the listener), so the "+
			"non-finite spelling is available from the file path too, not just the environment", literal)
	}
}

// TestZ12VerifyEnvPoolSizeIsRefusedWhereTheFileIsTruncated tests Z12-9's second
// half — "the environment path refuses what does not fit" — with the file path as
// the control. If the environment also truncated, the finding would be "no range
// check anywhere" rather than "two spellings disagree".
func TestZ12VerifyEnvPoolSizeIsRefusedWhereTheFileIsTruncated(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_STORAGE_DRIVER"] = "postgres"
	env["RE0AUTH_STORAGE_MAX_CONNS"] = "4294967297"
	env["DATABASE_URL"] = "postgres://z12v:z12v@127.0.0.1:1/z12v?sslmode=disable"
	env["RE0AUTH_AUDIT_KEY"] = key32("Z12V-AUDIT-KEY-32-BYTES-MATERIAL")
	env["RE0AUTH_STORAGE_CONNECT_TIMEOUT"] = "1s"
	code, out := runBinary(t, env, "-config", writeFile(t, "s.toml", "[server]\nissuer = \"https://re0auth.test\"\n"))
	if !strings.Contains(out, "stage=config") {
		t.Errorf("RE0AUTH_STORAGE_MAX_CONNS = 4294967297 was not refused at the config stage "+
			"(exit %d), so the environment path truncates too:\n%s", code, out)
	} else {
		t.Logf("environment path refused the out-of-range value at stage=config (exit %d): %s", code, lastLine(out))
	}
}

// TestZ12VerifyFileListCanBeEmptiedButNotTheEnv verifies the other half of Z12-4:
// the file spelling is the way out. If an empty TOML array also left the list in
// place the finding would be stronger; if it clears the list, the impact is
// reduced to "the environment override cannot express empty".
func TestZ12VerifyFileListCanBeEmptiedButNotTheEnv(t *testing.T) {
	env := baseEnv()
	env["RE0AUTH_OIDC_TOKEN_KEY"] = key32("Z12V-OP-TOKEN-KEY-32-BYTES-AA!")
	env["RE0AUTH_OIDC_SIGNING_KEY"] = signingKey

	withList := "[server]\nissuer = \"https://re0auth.test\"\n[admin]\nsubjects = [\"usr_operator\"]\n"
	if _, out := runBinary(t, env, "-config", writeFile(t, "a.toml", withList)); !strings.Contains(out, "operator plane enabled") {
		t.Fatalf("control failed: the operator plane was not mounted with a non-empty file list:\n%s", out)
	}
	empty := "[server]\nissuer = \"https://re0auth.test\"\n[admin]\nsubjects = []\n"
	code, out := runBinary(t, env, "-config", writeFile(t, "e.toml", empty))
	t.Logf("file subjects = [] -> exit %d, operator plane enabled: %v", code, strings.Contains(out, "operator plane enabled"))
	if strings.Contains(out, "operator plane enabled") {
		t.Logf("an empty TOML array also leaves the allowlist in place; the file cannot clear it either")
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}
