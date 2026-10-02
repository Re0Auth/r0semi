//go:build audit7

// Zone 17 adversarial re-check (round 7), new-finding probe.
//
// Z17's report examined only the re0auth server quickstart. This probe checks
// the SECOND quickstart in the same README: the reference data source
// (README.md:73-79). It is the same shape of defect as Z17-1, in a quickstart
// the reviewed report never opened.
package z17verify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "z17verify")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	root, err := findRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	exe := filepath.Join(dir, "referencesource.exe")
	out, err := runOnce(root, nil, 5*time.Minute, "go", "build", "-o", exe, "./cmd/referencesource")
	if err != nil {
		fmt.Fprintf(os.Stderr, "build cmd/referencesource failed: %v\n%s\n", err, out)
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

func runOnce(dir string, env []string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	f, err := os.CreateTemp("", "z17verify-*.log")
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

// baseEnv strips every reference-source and Re0Auth variable so an operator's
// own environment cannot make this probe pass by accident.
func baseEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "REFERENCE_SOURCE_") ||
			strings.HasPrefix(name, "RE0AUTH_") || name == "TAPTAP_LEANCLOUD_APP_KEY" {
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

// startAndWatch runs the binary against cfg and reports whether the log ever
// held want (success) or the process exited first (returning the log).
func startAndWatch(t *testing.T, cfg string, env map[string]string, want string) (bool, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "watch-*.log")
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
	go func() { _ = cmd.Wait(); close(waited) }()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-waited:
			data, _ := os.ReadFile(f.Name())
			return false, string(data)
		default:
		}
		data, _ := os.ReadFile(f.Name())
		if strings.Contains(string(data), want) {
			return true, string(data)
		}
		time.Sleep(150 * time.Millisecond)
	}
	data, _ := os.ReadFile(f.Name())
	return false, string(data)
}

// TestZ17VerifyReferenceSourceQuickstartCannotStart started as a NEW finding:
// README's reference-source quickstart exported only TAPTAP_LEANCLOUD_APP_KEY
// while the shipped example declares `[client] secret_env =
// "REFERENCE_SOURCE_CLIENT_SECRET"` with no default, so the documented
// invocation stopped at stage=config. README.md:83-96 now exports both secrets;
// this is the regression guard for that, and it keeps the README's honest note
// that GOOGLE_CLIENT_SECRET alone is NOT an alternative while `[social.*]` stays
// commented out. The name is kept for the round-7 verification report.
func TestZ17VerifyReferenceSourceQuickstartCannotStart(t *testing.T) {
	root := findRootAt(t)

	// First pin the README block this probe drives. The env map below is typed
	// out, so without this a README revert to the single-secret snippet would
	// leave the test green while it claims to guard the quickstart.
	readmeSrc, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	quickstart := ""
	if i := strings.Index(string(readmeSrc), "cp config/referencesource.example.toml"); i >= 0 {
		if j := strings.Index(string(readmeSrc)[i:], "```"); j >= 0 {
			quickstart = string(readmeSrc)[i : i+j]
		}
	}
	if quickstart == "" {
		t.Fatalf("README.md no longer contains the reference-source quickstart block; this probe would be measuring nothing")
	}
	if !referenceQuickstartExportsBothSecrets(quickstart) {
		t.Fatalf("README.md's reference-source quickstart no longer exports both secrets the shipped example "+
			"requires; the block is now:\n%s", quickstart)
	}
	// Anti-vacuity: the pre-fix snippet exported only the TapTap key.
	preFixREADME := "cp config/referencesource.example.toml config/referencesource.toml\n" +
		"export TAPTAP_LEANCLOUD_APP_KEY=...\n"
	if referenceQuickstartExportsBothSecrets(preFixREADME) {
		t.Fatal("the predicate accepts the pre-fix single-secret snippet; this guard would not fail on a revert")
	}

	dir := t.TempDir()
	cfg := filepath.Join(dir, "referencesource.toml")
	src, err := os.ReadFile(filepath.Join(root, "config", "referencesource.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, src, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:18702"

	// Positive control: the two secrets the example actually declares, plus a
	// free port, reach `listening`. That proves the binary and config path are
	// driven for real and that the missing secret is the only difference.
	control := map[string]string{
		"TAPTAP_LEANCLOUD_APP_KEY":       "reference-probe-app-key",
		"REFERENCE_SOURCE_CLIENT_SECRET": "reference-probe-client-secret",
		"REFERENCE_SOURCE_ADDR":          addr,
	}
	if ok, log := startAndWatch(t, cfg, control, "listening"); !ok {
		t.Fatalf("positive control never reached `listening`; the probe proves nothing:\n%s", tail(log, 6))
	}

	// README.md:83-96 (fixed): both secrets the shipped example requires are
	// exported, so the documented quickstart reaches `listening`.
	readme := map[string]string{
		"TAPTAP_LEANCLOUD_APP_KEY":       "reference-probe-app-key",
		"REFERENCE_SOURCE_CLIENT_SECRET": "reference-probe-client-secret",
		"REFERENCE_SOURCE_ADDR":          addr,
	}
	if ok, log := startAndWatch(t, cfg, readme, "listening"); !ok {
		t.Errorf("README.md's reference-source quickstart no longer starts: it must export both secrets the "+
			"shipped example requires (REFERENCE_SOURCE_CLIENT_SECRET and TAPTAP_LEANCLOUD_APP_KEY). Observed:\n%s",
			tail(log, 3))
	}

	// Anti-vacuity: the pre-fix quickstart exported only the TapTap key. If that
	// now starts, the client secret is not load-bearing and the guard above
	// proves nothing.
	preFix := map[string]string{
		"TAPTAP_LEANCLOUD_APP_KEY": "reference-probe-app-key",
		"REFERENCE_SOURCE_ADDR":    addr,
	}
	if ok, log := startAndWatch(t, cfg, preFix, "listening"); ok {
		t.Errorf("the pre-fix quickstart (TAPTAP_LEANCLOUD_APP_KEY only) starts the shipped example, so "+
			"REFERENCE_SOURCE_CLIENT_SECRET is not load-bearing and the guard above is vacuous:\n%s", tail(log, 3))
	}

	// The README's own honest note stays true: GOOGLE_CLIENT_SECRET is not an
	// alternative while `[social.google]` is commented out and `[taptap]` is
	// active, so that export alone must not start it.
	google := map[string]string{
		"GOOGLE_CLIENT_SECRET":  "reference-probe-google-secret",
		"REFERENCE_SOURCE_ADDR": addr,
	}
	if ok, log := startAndWatch(t, cfg, google, "listening"); ok {
		t.Errorf("GOOGLE_CLIENT_SECRET alone starts the shipped example: [social.google] is commented out "+
			"while [taptap] is active, so README's note that it is not an alternative is now wrong:\n%s",
			tail(log, 3))
	}
}

func findRootAt(t *testing.T) string {
	t.Helper()
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// referenceQuickstartExportsBothSecrets reports whether a README quickstart block
// exports both environment variables the shipped reference-source example
// requires.
func referenceQuickstartExportsBothSecrets(block string) bool {
	return strings.Contains(block, "export REFERENCE_SOURCE_CLIENT_SECRET=") &&
		strings.Contains(block, "export TAPTAP_LEANCLOUD_APP_KEY=")
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
