//go:build audit5

// Real-process verification probes for
// docs/audit-5/findings/config-startup-disclosure.md.
//
// Every probe here starts the actual cmd/re0auth binary and reads the log the
// process really wrote. The point is to remove the two things an in-process
// probe cannot rule out: that run()'s wiring differs from what loadConfig
// returns, and that a fixture manufactured the observation.
//
// Read-only: tests only, in a new package.
package verifyconfig

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
	"testing"
	"time"
)

var (
	serverBin    string
	oidcSignKey  string
	probeKEK     = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	probeTokKey  = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	buildFailure string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "re0auth-verifyconfig-")
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

// freePort reserves a port and gives it back. A race with another process is
// possible but this machine is quiet, and a lost port shows up as a failed
// startup rather than as a false result.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// cleanEnv is os.Environ with every Re0Auth variable removed, so nothing from
// the test process's environment can explain a server's behaviour.
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

func baseEnv() map[string]string {
	return map[string]string{
		"RE0AUTH_KEK":                     probeKEK,
		"RE0AUTH_OIDC_TOKEN_KEY":          probeTokKey,
		"RE0AUTH_OIDC_SIGNING_KEY":        oidcSignKey,
		"RE0AUTH_COOKIE_SECURE":           "false",
		"RE0AUTH_INTERNAL_ADDR":           "",
		"RE0AUTH_INTERNAL_EXPOSE":         "",
		"RE0AUTH_TRUSTED_PROXIES":         "",
		"RE0AUTH_ALLOW_PRIVATE_UPSTREAMS": "",
		"RE0AUTH_STORAGE_DRIVER":          "",
	}
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type proc struct {
	t       *testing.T
	cmd     *exec.Cmd
	logFile *os.File
	logPath string
	base    string
	intBase string
	waitErr chan error
}

// startServer runs the real binary with the given working directory and
// environment. dir doubles as the config directory when -config is passed.
func startServer(t *testing.T, dir string, env map[string]string, args ...string) *proc {
	t.Helper()
	requireBinary(t)
	logPath := filepath.Join(dir, "server.log")
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
		t.Fatal(err)
	}
	p := &proc{t: t, cmd: cmd, logFile: f, logPath: logPath, waitErr: make(chan error, 1)}
	go func() { p.waitErr <- cmd.Wait() }()
	t.Cleanup(func() { p.stop() })
	return p
}

func (p *proc) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.waitErr:
	case <-time.After(5 * time.Second):
	}
	if p.logFile != nil {
		_ = p.logFile.Close()
		p.logFile = nil
	}
}

func (p *proc) log() string {
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// waitServing polls /healthz until the process answers, or reports why it never
// did — including the log it printed before dying.
func (p *proc) waitServing(base string) {
	p.t.Helper()
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
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.t.Fatalf("the server never served %s/healthz; log:\n%s", base, p.log())
}

// runToExit runs the binary and returns its exit code and full output. A guard
// timer kills it if it starts serving instead of exiting, so a wrong assumption
// in a probe is a failure rather than a five-minute hang.
func runToExit(t *testing.T, dir string, env map[string]string, args ...string) (int, string) {
	t.Helper()
	requireBinary(t)
	cmd := exec.Command(serverBin, args...)
	cmd.Dir = dir
	cmd.Env = cleanEnv(env)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("running the server: %v", err)
	}
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
		return code, buf.String()
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the server did not exit within 30s (it is serving); output:\n%s", buf.String())
		return 0, buf.String()
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url) //nolint:gosec // loopback, test-only
	if err != nil {
		return 0, "ERROR: " + err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// linesWith returns the lines of log containing needle.
func linesWith(log, needle string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, needle) {
			out = append(out, l)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CS-1 / CS-2 at the real-listener level
// ---------------------------------------------------------------------------

// CS1-V1: in a real process, /readyz is anonymous-reachable on the public
// listener and is exempt from the limiter that does answer 429 on a normal
// route; the operational surface is not on the public listener.
func TestV_RealProcessReadyzIsPublicAndLimiterExempt(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := fmt.Sprintf("[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\n"+
		"cookie_secure = false\nrate_limit = 0.0001\nrate_limit_burst = 1\n", port, port)
	p := startServer(t, dir, baseEnv(), "-config", writeConfig(t, dir, cfg))
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	p.waitServing(base)

	// First, with the bucket still full: the operational surface is not here.
	// One check only, because rate_limit_burst = 1 leaves exactly one token.
	if c, _ := get(t, base+"/metrics"); c != http.StatusNotFound {
		t.Errorf("the public listener answered /metrics with %d, want 404", c)
	}
	t.Logf("with an unspent bucket the public listener answers 404 for /metrics")

	// The limiter is real and in force on an ordinary route.
	code, _ := get(t, base+"/v1/me")
	if code != http.StatusUnauthorized {
		t.Fatalf("control failed: first /v1/me = %d, want 401", code)
	}
	code2, _ := get(t, base+"/v1/me")
	t.Logf("GET /v1/me #1 -> %d, #2 -> %d (the bucket is exhausted)", code, code2)
	if code2 != http.StatusTooManyRequests {
		t.Fatalf("control failed: /v1/me #2 = %d, want 429", code2)
	}

	for i := 0; i < 10; i++ {
		if c, _ := get(t, base+"/readyz"); c != http.StatusOK {
			t.Fatalf("/readyz #%d = %d with the bucket empty", i, c)
		}
	}
	t.Logf("10 anonymous GET /readyz on the public listener all returned 200 while " +
		"GET /v1/me on the same address returned 429")

	// An unlisted path is not 404 once the bucket is empty: the limiter runs
	// before routing, so the refusal is a 429 on any path but a probe.
	c, _ := get(t, base+"/metrics")
	t.Logf("after the bucket is empty, GET /metrics on the public listener -> %d "+
		"(the limiter answers before the mux does)", c)
}

// CS2-V1 (real process): `addr = "0.0.0.0:P"` + `internal_addr = "localhost:P"`
// is accepted with no acknowledgement, the process starts, and the operational
// surface stays on loopback — but which handler a client gets depends on which
// loopback address it picks, which is the opposite direction from the audit
// report's claim.
func TestV_RealProcessTwoListenersOnOnePortAndWhoAnswers(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := fmt.Sprintf("[server]\nissuer = \"http://localhost:%d\"\naddr = \"0.0.0.0:%d\"\n"+
		"cookie_secure = false\ninternal_addr = \"localhost:%d\"\n", port, port, port)
	logPath := writeConfig(t, dir, cfg)
	p := startServer(t, dir, baseEnv(), "-config", logPath)

	// 127.0.0.1 is the literal address `internal_addr` names here, and it is
	// where the operational handler answers: the public listener is the
	// wildcard, so this is also proof that the two really coexisted.
	opsBase := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForOps(t, p, opsBase)

	log := p.log()
	for _, want := range []string{"listening", "internal surface listening"} {
		if !strings.Contains(log, want) {
			t.Fatalf("the process never logged %q, so two listeners did not come up:\n%s", want, log)
		}
	}
	t.Logf("both listeners came up on port %d (addr resolved by the loader as 0.0.0.0, "+
		"internal_addr as localhost):\n%s", port, strings.TrimSpace(
		strings.Join(linesWith(log, "listening"), "\n")))

	if c, _ := get(t, opsBase+"/metrics"); c != http.StatusOK {
		t.Errorf("GET 127.0.0.1:%d/metrics = %d, want 200 from the operational handler", port, c)
	}
	t.Logf("GET 127.0.0.1:%d/metrics -> %d (the operational handler answers on the IPv4 loopback)",
		port, mustCode(t, opsBase+"/metrics"))
	t.Logf("GET 127.0.0.1:%d/healthz -> %d (the public health probe is NOT there)", port,
		mustCode(t, opsBase+"/healthz"))

	// The public listener is still reachable — through IPv6 loopback and through
	// any routable address, because the wildcard bind is dual-stack.
	for _, host := range []string{"[::1]", "localhost"} {
		c, _ := get(t, fmt.Sprintf("http://%s:%d/healthz", host, port))
		t.Logf("GET %s:%d/healthz -> %d (the public listener)", host, port, c)
	}
	// Default limiter here, so several paths can be asked in a row.
	for _, path := range []string{"/metrics", "/debug/pprof/", "/debug/pprof/heap"} {
		c, _ := get(t, fmt.Sprintf("http://[::1]:%d%s", port, path))
		t.Logf("GET [::1]:%d%s -> %d (the public listener)", port, path, c)
		if c != http.StatusNotFound {
			t.Errorf("the operational surface answered on the public listener via ::1: %s -> %d", path, c)
		}
	}
}

// waitForOps waits until the operational listener answers /metrics.
func waitForOps(t *testing.T, p *proc, opsBase string) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if c, _ := get(t, opsBase+"/metrics"); c == http.StatusOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the operational listener never answered %s/metrics:\n%s", opsBase, p.log())
}

func mustCode(t *testing.T, url string) int {
	t.Helper()
	c, _ := get(t, url)
	return c
}

// ---------------------------------------------------------------------------
// CS-3
// ---------------------------------------------------------------------------

// CS3-V1: a real process starts with trusted_proxies = ["0.0.0.0/0"], with no
// warning of any kind, and the startup log does not mention the list.
func TestV_RealProcessAcceptsATrustEverythingProxyList(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := fmt.Sprintf("[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\n"+
		"cookie_secure = false\ntrusted_proxies = [\"0.0.0.0/0\", \"::/0\"]\n", port, port)
	p := startServer(t, dir, baseEnv(), "-config", writeConfig(t, dir, cfg))
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	p.waitServing(base)
	log := p.log()
	t.Logf("trusted_proxies=[\"0.0.0.0/0\",\"::/0\"] was accepted by the real loader and the " +
		"process serves normally")
	t.Logf("full startup log (%d bytes):\n%s", len(log), log)
	for _, field := range []string{"trusted_proxies", "0.0.0.0/0"} {
		if strings.Contains(log, field) {
			t.Logf("the startup log DOES mention %q", field)
		} else {
			t.Logf("the startup log never mentions %q", field)
		}
	}
	// The forged header really is believed by the real process: the access log's
	// client field (INFO level on a business route) carries the caller's value.
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.77")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	for _, l := range linesWith(p.log(), "path=/v1/me") {
		t.Logf("access log line: %s", l)
	}
}

// ---------------------------------------------------------------------------
// CS-4
// ---------------------------------------------------------------------------

// CS4-V1: the real binary starts with a mistyped or absent token_class, and
// refuses a mistyped value in a neighbouring enum. The control is what makes
// the first half evidence rather than a claim about a code path nobody reached.
func TestV_RealProcessAcceptsAMistypedTokenClass(t *testing.T) {
	source := func(tokenClass string) string {
		return "[[sources]]\ngame = \"phigros\"\nsource = \"next-phi\"\n" +
			"display_name = \"Next Phi\"\nissuer = \"https://api.next-phi.example\"\n" +
			tokenClass + "client_id = \"re0auth\"\n"
	}
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"a typo of long_lived", "token_class = \"long_live\"\n"},
		{"the value omitted", ""},
		{"an invented third value", "token_class = \"session\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			port := freePort(t)
			cfg := fmt.Sprintf("[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\n"+
				"cookie_secure = false\n", port, port) + source(tc.field)
			p := startServer(t, dir, baseEnv(), "-config", writeConfig(t, dir, cfg))
			p.waitServing(fmt.Sprintf("http://127.0.0.1:%d", port))
			t.Logf("the real server started with %s: the value reaches federation.Source "+
				"unchecked, and unbind.go treats everything that is not \"long_lived\" as revocable", tc.name)
		})
	}

	// Control: the same loader does police another enum in the same file.
	dir := t.TempDir()
	code, out := runToExit(t, dir, baseEnv(), "-config", writeConfig(t, dir,
		"[server]\nissuer = \"http://127.0.0.1:1\"\ncookie_secure = false\n"+
			"[storage]\ndriver = \"mysql\"\n"))
	t.Logf("control: storage.driver = \"mysql\" -> exit %d: %s", code, strings.TrimSpace(out))
	if code == 0 {
		t.Errorf("control failed: an invented storage driver was accepted")
	}
}

// ---------------------------------------------------------------------------
// CS-5
// ---------------------------------------------------------------------------

// CS5-V1: a real process with DATABASE_URL set and no [storage] section runs in
// memory and warns with because="no DATABASE_URL". The exact log line is printed
// so it can be quoted rather than paraphrased.
func TestV_RealProcessDatabaseURLAloneStaysInMemory(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	env := baseEnv()
	env["DATABASE_URL"] = "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable"
	env["RE0AUTH_ADDR"] = fmt.Sprintf("127.0.0.1:%d", port)
	env["RE0AUTH_ISSUER"] = fmt.Sprintf("http://127.0.0.1:%d", port)
	// No -config and no RE0AUTH_CONFIG: the process's directory has no
	// config/re0auth.toml, so this is the environment-only deployment.
	p := startServer(t, dir, env)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	p.waitServing(base)

	if c, _ := get(t, base+"/readyz"); c != http.StatusOK {
		t.Errorf("/readyz = %d, want 200 (memory mode has no dependency to check)", c)
	}
	log := p.log()
	var warn string
	for _, l := range linesWith(log, "storage is in-memory") {
		warn = l
	}
	if warn == "" {
		t.Fatalf("no in-memory warning in the log:\n%s", log)
	}
	t.Logf("DATABASE_URL was set to postgres://user:pass@db.internal:5432/re0auth?sslmode=disable "+
		"and the process printed:\n  %s", strings.TrimSpace(warn))
	if !strings.Contains(warn, `because="no DATABASE_URL"`) {
		t.Errorf("the warning does not carry the because= field the report quotes: %q", warn)
	}
	if !strings.Contains(log, "audit log is in-memory") {
		t.Errorf("expected the in-memory audit sink warning too:\n%s", log)
	}
	t.Logf("the same run also printed: %s",
		strings.TrimSpace(strings.Join(linesWith(log, "audit log is in-memory"), "; ")))
	for _, l := range linesWith(log, "storage ready") {
		t.Logf("storage ready line: %s", l)
	}
	if len(linesWith(log, "storage ready")) > 0 {
		t.Errorf("the process claims durable storage: %s", log)
	}
	for _, needle := range []string{"audit chain head anchored", "audit chain verified"} {
		if strings.Contains(log, needle) {
			t.Errorf("an audit-chain control ran in memory mode: %q", needle)
		}
	}
	t.Logf("no audit-chain line appears in the log of this in-memory run (%d lines total)",
		len(strings.Split(strings.TrimSpace(log), "\n")))
}

// CS5-V3: the README's quickstart copies config/re0auth.example.toml and then
// sets DATABASE_URL. README:30 says the server runs without DATABASE_URL. With
// the shipped example copied verbatim, it does not: [storage] in that file names
// DATABASE_URL as its DSN variable. This runs the real binary against the real
// file (copied into a temp dir; the tracked file is not touched).
func TestV_ShippedExampleConfigRefusesToStartWithoutDatabaseURL(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "re0auth.example.toml"))
	if err != nil {
		t.Fatalf("reading the shipped example config: %v", err)
	}
	secrets := map[string]string{
		"GITHUB_CLIENT_SECRET": "probe",
		"GOOGLE_CLIENT_SECRET": "probe",
	}

	// No DATABASE_URL, example config as shipped.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "re0auth.toml"), example, 0o600); err != nil {
		t.Fatal(err)
	}
	env := baseEnv()
	env["RE0AUTH_COOKIE_SECURE"] = "true" // the example's issuer is https
	for k, v := range secrets {
		env[k] = v
	}
	code, out := runToExit(t, dir, env, "-config", filepath.Join(dir, "re0auth.toml"))
	t.Logf("the shipped example config with NO DATABASE_URL -> exit %d: %s",
		code, strings.TrimSpace(strings.Join(linesWith(out, "cannot start"), " ")))
	if code == 0 {
		t.Logf("the example config started without DATABASE_URL")
	}
	if !strings.Contains(out, "DATABASE_URL") {
		t.Errorf("the refusal does not name DATABASE_URL:\n%s", out)
	}

	// Same config, DATABASE_URL set to something unreachable: now the driver is
	// postgres and the failure is the connection, not the configuration.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "re0auth.toml"), example, 0o600); err != nil {
		t.Fatal(err)
	}
	env2 := baseEnv()
	env2["RE0AUTH_COOKIE_SECURE"] = "true"
	for k, v := range secrets {
		env2[k] = v
	}
	env2["DATABASE_URL"] = "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable"
	env2["RE0AUTH_AUDIT_KEY"] = probeKEK
	code2, out2 := runToExit(t, dir2, env2, "-config", filepath.Join(dir2, "re0auth.toml"))
	t.Logf("the same file WITH DATABASE_URL -> exit %d: %s",
		code2, strings.TrimSpace(strings.Join(linesWith(out2, "cannot start"), " ")))
	if code2 == 0 {
		t.Errorf("expected the connection to the unreachable database to fail")
	}
	if strings.Contains(out2, "storage is in-memory") {
		t.Errorf("the example config stayed in memory with DATABASE_URL set:\n%s", out2)
	}
}

// CS5-V2: the control — the same DATABASE_URL with `[storage] driver` set does
// reach Postgres (and fails there, not on the driver), plus the environment-only
// deployment cannot become durable even when it sets a plausible variable name.
func TestV_RealProcessStorageDriverComesFromTheFileOnly(t *testing.T) {
	dir := t.TempDir()
	env := baseEnv()
	env["DATABASE_URL"] = "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable"
	env["RE0AUTH_AUDIT_KEY"] = probeKEK // durable means the chain key becomes mandatory
	env["RE0AUTH_ADDR"] = "127.0.0.1:1"
	env["RE0AUTH_ISSUER"] = "http://127.0.0.1:1"
	cfg := "[server]\nissuer = \"http://127.0.0.1:1\"\ncookie_secure = false\n" +
		"[storage]\ndriver = \"postgres\"\ndsn_env = \"DATABASE_URL\"\n"
	code, out := runToExit(t, dir, env, "-config", writeConfig(t, dir, cfg))
	t.Logf("control: with [storage] driver = \"postgres\", exit=%d, log:\n%s", code, strings.TrimSpace(out))
	if code == 0 {
		t.Errorf("the control did not fail, so the driver may not have been selected")
	}
	if strings.Contains(out, "storage is in-memory") {
		t.Errorf("the control stayed in memory despite [storage] driver = postgres")
	}
	if !strings.Contains(out, "storage") && !strings.Contains(out, "AUDIT_KEY") {
		t.Errorf("the failure does not show the durable path was selected:\n%s", out)
	}

	// The same variable with no [storage] does not even get that far: there is no
	// audit-key requirement, which is the mark of the memory path.
	dir1 := t.TempDir()
	port1 := freePort(t)
	env1 := baseEnv()
	env1["DATABASE_URL"] = "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable"
	env1["RE0AUTH_ADDR"] = fmt.Sprintf("127.0.0.1:%d", port1)
	env1["RE0AUTH_ISSUER"] = fmt.Sprintf("http://127.0.0.1:%d", port1)
	p1 := startServer(t, dir1, env1, "-config", writeConfig(t, dir1,
		fmt.Sprintf("[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\n"+
			"cookie_secure = false\n", port1, port1)))
	p1.waitServing(fmt.Sprintf("http://127.0.0.1:%d", port1))
	out1 := p1.log()
	if !strings.Contains(out1, "storage is in-memory") {
		t.Errorf("without [storage] the process was not in memory:\n%s", out1)
	}
	t.Logf("without [storage], the same DATABASE_URL and NO audit key started fine and printed: %s",
		strings.TrimSpace(strings.Join(linesWith(out1, "because="), " ")))

	// Variant: a plausible variable name does not exist, so setting it changes
	// nothing and the deployment stays in memory.
	dir2 := t.TempDir()
	port := freePort(t)
	env2 := baseEnv()
	env2["DATABASE_URL"] = "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable"
	env2["RE0AUTH_STORAGE_DRIVER"] = "postgres"
	env2["RE0AUTH_ADDR"] = fmt.Sprintf("127.0.0.1:%d", port)
	env2["RE0AUTH_ISSUER"] = fmt.Sprintf("http://127.0.0.1:%d", port)
	p := startServer(t, dir2, env2)
	p.waitServing(fmt.Sprintf("http://127.0.0.1:%d", port))
	log := p.log()
	if !strings.Contains(log, "storage is in-memory") {
		t.Fatalf("RE0AUTH_STORAGE_DRIVER appears to have had an effect:\n%s", log)
	}
	t.Logf("with DATABASE_URL AND RE0AUTH_STORAGE_DRIVER=postgres set, the real process is still "+
		"in-memory: %s", strings.TrimSpace(strings.Join(linesWith(log, "storage is in-memory"), " ")))
}

// ---------------------------------------------------------------------------
// CS-6
// ---------------------------------------------------------------------------

// CS6-V1: the complete startup log of a real process whose every security switch
// has been turned to its weakest value. The log is printed in full and then
// searched for each switch name, which is what the report's CS-6 claims.
func TestV_RealProcessStartupLogVersusSecuritySwitches(t *testing.T) {
	dir := t.TempDir()
	port, internalPort := freePort(t), freePort(t)
	cfg := fmt.Sprintf(`[server]
issuer = "http://127.0.0.1:%d"
addr = "0.0.0.0:%d"
cookie_secure = false
rate_limit = 0
max_in_flight = 0
trusted_proxies = ["0.0.0.0/0"]
internal_addr = "127.0.0.1:%d"
introspection_clients = ["wide_open_resource_server"]

[upstream]
allow_private_addresses = true

[admin]
subjects = ["usr_someone"]
`, port, port, internalPort)
	p := startServer(t, dir, baseEnv(), "-config", writeConfig(t, dir, cfg))
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	p.waitServing(base)
	log := p.log()
	t.Logf("full startup log of a real process:\n%s", log)

	for _, field := range []string{
		"cookie_secure", "trusted_proxies", "rate_limit", "max_in_flight",
		"expose_internal", "allow_private", "introspection_clients", "reauth",
		"internal_addr", "admins",
	} {
		if strings.Contains(log, field) {
			t.Logf("present in the startup log: %q", field)
		} else {
			t.Logf("ABSENT from the startup log: %q", field)
		}
	}

	// The switches really were the weak ones: the operational surface answers on
	// 127.0.0.1 (proving internal_addr took effect) and no limiter is in force.
	if c, _ := get(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", internalPort)); c != http.StatusOK {
		t.Errorf("internal /metrics = %d, want 200: internal_addr did not take effect", c)
	}
	for i := 0; i < 5; i++ {
		if c, _ := get(t, base+"/v1/me"); c == http.StatusTooManyRequests {
			t.Errorf("rate_limit = 0 still produced a 429")
		}
	}
}

// ---------------------------------------------------------------------------
// CS-7
// ---------------------------------------------------------------------------

// CS7-V1: a real process with internal_addr set. A scrape and two pprof dumps
// produce no log lines at all, while the same number of public requests produce
// exactly one line each — the negative and its control, measured on the process
// rather than on a handler in a test binary.
func TestV_RealProcessInternalSurfaceIsUnlogged(t *testing.T) {
	dir := t.TempDir()
	port, internalPort := freePort(t), freePort(t)
	cfg := fmt.Sprintf("[server]\nissuer = \"http://127.0.0.1:%d\"\naddr = \"127.0.0.1:%d\"\n"+
		"cookie_secure = false\ninternal_addr = \"127.0.0.1:%d\"\n", port, port, internalPort)
	p := startServer(t, dir, baseEnv(), "-config", writeConfig(t, dir, cfg))
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	p.waitServing(base)

	before := len(p.log())
	internal := fmt.Sprintf("http://127.0.0.1:%d", internalPort)
	for _, path := range []string{"/metrics", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=1"} {
		code, body := get(t, internal+path)
		if code != http.StatusOK || body == "" {
			t.Fatalf("control failed: %s = %d, %d bytes", path, code, len(body))
		}
		t.Logf("GET %s -> %d, %d bytes", path, code, len(body))
	}
	time.Sleep(300 * time.Millisecond)
	afterInternal := p.log()[before:]
	t.Logf("after a scrape and two pprof dumps the process wrote %d bytes of log: %q",
		len(afterInternal), afterInternal)

	publicBefore := len(p.log())
	for i := 0; i < 3; i++ {
		if c, _ := get(t, base+"/v1/me"); c != http.StatusUnauthorized {
			t.Fatalf("control failed: /v1/me = %d, want 401", c)
		}
	}
	time.Sleep(300 * time.Millisecond)
	afterPublic := p.log()[publicBefore:]
	n := len(linesWith(afterPublic, "msg=request"))
	t.Logf("the same three requests through the public listener produced %d log lines", n)
	if n != 3 {
		t.Errorf("the public comparison is not a clean contrast: %d lines, want 3", n)
	}
	if len(afterInternal) != 0 {
		t.Errorf("the internal surface logged something after all")
	}
}
