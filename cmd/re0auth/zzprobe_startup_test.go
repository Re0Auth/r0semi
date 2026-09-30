//go:build audit5

// Probes for the configuration / composition-root audit
// (docs/audit-5/findings/config-startup-disclosure.md).
//
// Read-only: this file adds tests only. It lives inside package main because the
// questions are about unexported loaders (loadConfig, parseTrustedProxies,
// newServer, run) that no external test package can reach.
//
// Every probe that claims "X is refused" first asserts the control case, so a
// pass cannot be the result of never reaching the code.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/observability"
)

// probeEnv sets the minimum a loadConfig call needs, and clears the variables the
// other probes set, so one probe's environment cannot explain another's result.
func probeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", "")
	t.Setenv("RE0AUTH_INTERNAL_ADDR", "")
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "")
	t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "")
	t.Setenv("RE0AUTH_ADDR", "")
	t.Setenv("RE0AUTH_TRUSTED_PROXIES", "")
	t.Setenv("RE0AUTH_ALLOW_PRIVATE_UPSTREAMS", "")
	t.Setenv("RE0AUTH_ADMIN_SUBJECTS", "")
	t.Setenv("RE0AUTH_INTROSPECTION_CLIENTS", "")
	t.Setenv("RE0AUTH_RATE_LIMIT", "")
	t.Setenv("RE0AUTH_RATE_LIMIT_BURST", "")
}

// CS-1 probe: server.max_in_flight = -1 is neither refused nor used.
//
// The parser documents -1 as its own internal sentinel for "the operator chose
// nothing", rejecting every other negative value. A value that reaches the parser
// from the file or the environment is not distinguished from the sentinel, so an
// operator who writes -1 — the conventional spelling of "no limit" in the very
// neighbouring knob (`rate_limit = 0` disables, and a negative is refused there)
// gets a cap they did not choose, silently.
func TestProbeMaxInFlightMinusOneIsSilentlyTheDefault(t *testing.T) {
	probeEnv(t)

	// Control: the parser does look at negative values at all.
	t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "-2")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("control failed: -2 was accepted, so this probe is not reaching the check")
	}

	t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "-1")
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("-1 was refused (the useful behaviour): %v", err)
	}
	if cfg.MaxInFlight != defaultMaxInFlightMemory {
		t.Fatalf("MaxInFlight = %d, want the sentinel to have been replaced by the default %d",
			cfg.MaxInFlight, defaultMaxInFlightMemory)
	}
	t.Logf("RE0AUTH_MAX_IN_FLIGHT=-1 was accepted and silently became the default cap %d; "+
		"-2 in the same variable is refused, so the two differ by nothing but luck",
		cfg.MaxInFlight)

	// The same value in the file behaves identically, which is the shape a
	// deployment actually edits.
	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(path,
		[]byte("[server]\nissuer = \"https://re0auth.test\"\nmax_in_flight = -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "")
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatalf("max_in_flight = -1 in the file was refused: %v", err)
	}
	if cfg.MaxInFlight != defaultMaxInFlightMemory {
		t.Fatalf("file: MaxInFlight = %d, want %d", cfg.MaxInFlight, defaultMaxInFlightMemory)
	}
}

// CS-2 probe: the internal/public separation check is a string comparison, so two
// spellings of the same endpoint pass it.
//
// It is not just cosmetic: the check the comment promises is "the operational
// surface is not the public one", and `0.0.0.0:9090` versus `:9090` are the same
// socket. Whether that is harmless depends on what the OS does with the second
// bind, which is exactly what the accompanying bind probe measures.
func TestProbeInternalAddrEqualityIsOnlyAStringComparison(t *testing.T) {
	probeEnv(t)
	t.Setenv("RE0AUTH_ADDR", "0.0.0.0:19090")
	t.Setenv("RE0AUTH_INTERNAL_ADDR", ":19090") // the same endpoint, written differently
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "true")

	// Control: the literal spelling IS refused, so the check exists and runs.
	t.Setenv("RE0AUTH_INTERNAL_ADDR", "0.0.0.0:19090")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("control failed: the identical spelling was accepted")
	}

	t.Setenv("RE0AUTH_INTERNAL_ADDR", ":19090")
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("the equivalent spelling was refused: %v", err)
	}
	t.Logf("addr=%q internal_addr=%q both accepted: the same socket under two spellings",
		cfg.Addr, cfg.InternalAddr)

	// And the same thing with a hostname, which never even reaches the
	// acknowledgement check because internalAddrIsLocal("localhost:…") is true.
	t.Setenv("RE0AUTH_ADDR", "127.0.0.1:19091")
	t.Setenv("RE0AUTH_INTERNAL_ADDR", "localhost:19091")
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "")
	if _, err := loadConfig(""); err != nil {
		t.Fatalf("localhost spelling was refused: %v", err)
	}
	t.Logf("addr=127.0.0.1:19091 internal_addr=localhost:19091 accepted with no acknowledgement: " +
		"the loopback classifier treats the name as local, and the bind may not agree")
}

// CS-2b: what the OS does when both listeners are asked for the same port. This
// is the measurement CS-2's impact rests on: if the second bind fails, a
// mis-spelled pair is a confusing refusal (fail closed), not a leak.
func TestProbeTwoListenersOnOnePort(t *testing.T) {
	first, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	_, port, err := net.SplitHostPort(first.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	for _, second := range []string{":" + port, "127.0.0.1:" + port, "[::1]:" + port, "localhost:" + port} {
		ln, err := net.Listen("tcp", second)
		if err != nil {
			t.Logf("bind %-22s after 0.0.0.0:%s -> refused (%v): fail closed", second, port, err)
			continue
		}
		t.Logf("bind %-22s after 0.0.0.0:%s -> SUCCEEDED as %s: two listeners on one port number",
			second, port, ln.Addr())
		_ = ln.Close()
	}
}

// CS-3 probe: a trusted-proxy list that trusts the whole internet is accepted.
//
// (FIXED) The loader now refuses a universal prefix unless it is explicitly
// acknowledged. The list decides whether a caller's X-Forwarded-For is believed,
// which is what keeps a client from choosing its own rate-limit bucket; 0.0.0.0/0
// is not malformed, it is the value that makes the setting vacuous, so it needs
// the same acknowledgement as expose_internal.
func TestProbeUniversalTrustedPrefixNeedsAcknowledgement(t *testing.T) {
	// Control: a malformed entry is still refused.
	if _, err := parseTrustedProxies([]string{"not-a-network"}); err == nil {
		t.Fatal("control failed: a malformed entry was accepted")
	}

	// parseTrustedProxies itself stays permissive — the gate is one level up, at
	// loadConfig, where the acknowledgement lives.
	got, err := parseTrustedProxies([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatalf("parseTrustedProxies refused a universal prefix: %v", err)
	}
	if !hasUniversalPrefix(got) {
		t.Fatalf("hasUniversalPrefix did not see the universal prefix in %v", got)
	}
	// A narrow list is not universal, so it is unaffected.
	narrow, _ := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1/32"})
	if hasUniversalPrefix(narrow) {
		t.Fatalf("hasUniversalPrefix flagged a narrow list %v", narrow)
	}

	probeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	body := "[server]\nissuer = \"https://re0auth.test\"\ntrusted_proxies = [\"0.0.0.0/0\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without the acknowledgement the process refuses to start.
	if _, err := loadConfig(path); err == nil {
		t.Error("trusted_proxies = [0.0.0.0/0] was accepted with no acknowledgement; " +
			"it makes the whole setting a no-op and must be refused")
	}

	// With it, the configuration loads.
	t.Setenv("RE0AUTH_TRUSTED_PROXIES_ANY", "true")
	if _, err := loadConfig(path); err != nil {
		t.Errorf("the acknowledgement did not permit a universal prefix: %v", err)
	}
}

// (FIXED) token_class is validated and defaulted at the registry, so a typo can
// no longer be silently read as revocable.
//
// The loader refuses an unknown storage driver, a malformed duration and a
// malformed CIDR; token_class is now policed the same way.
func TestProbeTokenClassIsValidatedAndDefaulted(t *testing.T) {
	// Control: the neighbouring enum in the same struct IS handled — an unknown
	// storage.driver is refused — so this loader does police its own values.
	probeEnv(t)
	t.Setenv("RE0AUTH_ADDR", "")
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("[server]\nissuer = \"https://re0auth.test\"\n"+
		"[storage]\ndriver = \"mysql\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(bad); err == nil {
		t.Fatal("control failed: an unknown storage.driver was accepted")
	}

	// Valid values (and the empty default) load, and empty becomes revocable.
	for _, ok := range []string{"revocable", "long_lived", ""} {
		var cfg settings
		if err := loadSources(&cfg, []sourceSection{{
			Game: "phigros", Source: "next-phi", Issuer: "https://api.example",
			TokenClass: ok,
		}}); err != nil {
			t.Errorf("token_class %q was refused: %v", ok, err)
			continue
		}
		if ok == "" && cfg.sources[0].TokenClass != "revocable" {
			t.Errorf("empty token_class stayed %q, want revocable (the safe default)", cfg.sources[0].TokenClass)
		}
	}

	// A typo, the wrong case, and an invented value are all refused.
	for _, bad := range []string{"long_live", "Revocable", "session"} {
		var cfg settings
		if err := loadSources(&cfg, []sourceSection{{
			Game: "phigros", Source: "next-phi", Issuer: "https://api.example",
			TokenClass: bad,
		}}); err == nil {
			t.Errorf("token_class %q was accepted; it would be read as revocable and misreported", bad)
		}
	}
}

// CS-5 probe: the startup log announces no security-relevant switch.
//
// The composition root prints which storage, which engine, how many operators and
// where it listens. It never prints the switches that decide whether a cookie is
// Secure, whether X-Forwarded-For is believed, whether the limiter is on, whether
// /metrics is exposed beyond this host, or whether outbound calls may reach the
// private network — so an operator reading the log cannot tell a hardened
// deployment from a mis-configured one.
//
// The probe drives the real run() rather than grepping the source: it sets
// -rotate-keys, which makes run() open storage, wire the vault and return before
// the listeners, so the whole pre-listener startup path executes for real.
func TestProbeStartupLogOmitsEverySecuritySwitch(t *testing.T) {
	probeEnv(t)
	t.Setenv("RE0AUTH_ADDR", "0.0.0.0:19092")
	t.Setenv("RE0AUTH_INTERNAL_ADDR", "0.0.0.0:19093")
	t.Setenv("RE0AUTH_INTERNAL_EXPOSE", "true")
	t.Setenv("RE0AUTH_ALLOW_PRIVATE_UPSTREAMS", "true")
	t.Setenv("RE0AUTH_TRUSTED_PROXIES", "0.0.0.0/0")
	t.Setenv("RE0AUTH_TRUSTED_PROXIES_ANY", "true")
	t.Setenv("RE0AUTH_RATE_LIMIT", "0")
	t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "0")
	t.Setenv("RE0AUTH_INTROSPECTION_CLIENTS", "wide_open_resource_server")
	t.Setenv("RE0AUTH_ADMIN_REAUTH_WINDOW", "0")

	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(path, []byte("[server]\nissuer = \"https://re0auth.test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The flags are package globals; restore them so no other test sees them.
	prevConfig, prevRotate := *configFlag, *rotateKeys
	t.Cleanup(func() { *configFlag, *rotateKeys = prevConfig, prevRotate })
	*configFlag = path
	*rotateKeys = true

	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := run(); err != nil {
		t.Fatalf("run() = %v", err)
	}

	out := buf.String()
	// Anti-vacuous: the startup path really did log, and really did see the
	// settings this probe configured.
	for _, want := range []string{"configuration file", "in-memory", "key rotation run finished"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the startup log never said %q, so this probe observed nothing:\n%s", want, out)
		}
	}
	for _, field := range []string{
		"cookie_secure", "trusted_proxies", "rate_limit", "max_in_flight",
		"expose_internal", "allow_private", "introspection_clients", "reauth",
	} {
		if strings.Contains(out, field) {
			t.Logf("%s IS announced at startup", field)
			continue
		}
		t.Logf("%s is announced nowhere in the startup log", field)
	}
	t.Logf("startup log was:\n%s", out)
}

// CS-6 probe: the internal listener runs the public surface's write timeout.
//
// cmd/re0auth's newServer is shared by both listeners on purpose ("differ only in
// what they serve, not in how they are bounded"). The hypothesis this probe was
// written to test was that the shared writeTimeout therefore truncates a CPU
// profile longer than it: http.Server arms the write deadline when the request has
// been read, and pprof sleeps for `seconds` before the body is complete.
//
// **The hypothesis was falsified by running it.** A 61-second profile against a
// 60-second writeTimeout came back complete — 200 and a valid gzip stream. Go's
// write deadline only fails a write that would block, and a body that fits in the
// socket buffer is written without ever blocking. What the shared limit can still
// cut off is a large profile being drained by a slow consumer, which is not
// reproducible here without a large heap.
//
// The probe is kept as a guard on the property an operator actually depends on —
// "a profile longer than the write timeout still arrives intact" — so a future
// deadline on the body, or a smaller writeTimeout, turns this red instead of
// silently producing corrupt profiles.
//
// Skipped under -short because it has to outlast the timeout being measured.
func TestProbeInternalListenerWriteTimeoutTruncatesAProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("needs to outlive cmd/re0auth's writeTimeout")
	}
	srv := newServer(observability.New().InternalHandler())
	if srv.WriteTimeout != writeTimeout {
		t.Fatalf("the internal listener's write timeout = %s, want the shared %s",
			srv.WriteTimeout, writeTimeout)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// One second past the deadline, so the failure is the deadline and not a race.
	url := "http://" + ln.Addr().String() + "/debug/pprof/profile?seconds=" +
		strconv.Itoa(int(writeTimeout/time.Second)+1)
	start := time.Now()
	resp, err := http.Get(url) //nolint:gosec // loopback, test-only
	if err != nil {
		t.Fatalf("the profile request itself failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(resp.Body)
	t.Logf("GET %s -> %d, %d bytes, read err = %v, after %s",
		url, resp.StatusCode, len(body), readErr, time.Since(start).Round(time.Second))

	// A complete Go profile is a gzip stream. A truncated one is not, and the
	// status code does not say so.
	zr, zerr := gzip.NewReader(bytes.NewReader(body))
	if zerr != nil {
		t.Fatalf("the profile is not a gzip stream at all (status was %d): %v", resp.StatusCode, zerr)
	}
	_, gunzipErr := io.ReadAll(zr)
	if resp.StatusCode == http.StatusOK && gunzipErr != nil {
		t.Fatalf("status 200 with a truncated profile: the client cannot tell the difference "+
			"between an empty heap and a deadline (%v)", gunzipErr)
	}
}

// CS-8 probe: no secret the process reads is echoed during startup.
//
// The project's own rule is that a config file names the environment variable
// holding a secret rather than holding it, so that a committed config cannot leak
// a credential. The mirror of that rule is that the process must not print one
// either — a startup log is copied into tickets and pasted into chat, which is
// exactly why the access log refuses to log query strings.
//
// Two runs, because the composition root has two exits before the listener: one
// stops at -rotate-keys (which is where the vault is opened and the KEK is used),
// and one is stopped by an unbindable address just after the client is seeded.
// Between them they execute every secret-consuming step that happens before
// serving. The planted values are checked against the whole captured log.
func TestProbeNoSecretIsEchoedAtStartup(t *testing.T) {
	// probeKey builds a 32-byte value whose printable prefix is recognisable in a
	// log, encoded the way the loader documents it.
	probeKey := func(seed string) string {
		raw := make([]byte, 32)
		copy(raw, seed)
		return base64.StdEncoding.EncodeToString(raw)
	}
	kekRaw := probeKey("PROBE-KEK-MATERIAL-32-BYTES-ABC!")
	tokKey := probeKey("PROBE-TOKEN-KEY-MATERIAL-32-BYTE")
	auditK := probeKey("PROBE-AUDIT-KEY-MATERIAL-32-BYTE")
	const (
		clSec  = "CLIENT-SECRET-PROBE-DO-NOT-LOG"
		idpSec = "IDP-SECRET-PROBE-DO-NOT-LOG"
		srcSec = "SOURCE-SECRET-PROBE-DO-NOT-LOG"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signKey := base64.StdEncoding.EncodeToString(der)

	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	body := `
[server]
issuer = "https://re0auth.test"

[client]
id = "cli"
secret_env = "PROBE_CLIENT_SECRET"
redirect_uris = ["https://re0auth.test/callback"]

[idp.github]
client_id = "cid"
client_secret_env = "PROBE_IDP_SECRET"

[[sources]]
game = "phigros"
source = "next-phi"
issuer = "https://api.next-phi.example"
token_class = "revocable"
client_id = "re0auth"
client_secret_env = "PROBE_SOURCE_SECRET"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	setSecrets := func(t *testing.T) {
		t.Helper()
		t.Setenv("RE0AUTH_KEK", kekRaw)
		t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", tokKey)
		t.Setenv("RE0AUTH_OIDC_SIGNING_KEY", signKey)
		t.Setenv("RE0AUTH_AUDIT_KEY", auditK)
		// A retired token key is secret material the process reads (it decrypts
		// access tokens issued before a rotation), and CS-8 did not plant it, so
		// the guard could not see Z12-1's path (cmd/re0auth/main.go's
		// oidcRetiredTokenKeys). Well-formed here: this probe must reach the
		// stages below, so it cannot plant the malformed shape that triggers the
		// refusal; TestOIDCRetiredKeysDoNotEchoKeyMaterial covers that branch.
		t.Setenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS", "probe-old:"+tokKey)
		t.Setenv("PROBE_CLIENT_SECRET", clSec)
		t.Setenv("PROBE_IDP_SECRET", idpSec)
		t.Setenv("PROBE_SOURCE_SECRET", srcSec)
		t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
		t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
		t.Setenv("DATABASE_URL", "")
		t.Setenv("RE0AUTH_INTERNAL_ADDR", "")
	}

	runAndCapture := func(t *testing.T, rotate bool, addr string) string {
		t.Helper()
		prevConfig, prevRotate := *configFlag, *rotateKeys
		t.Cleanup(func() { *configFlag, *rotateKeys = prevConfig, prevRotate })
		*configFlag, *rotateKeys = path, rotate
		t.Setenv("RE0AUTH_ADDR", addr)

		buf := &bytes.Buffer{}
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		defer slog.SetDefault(prev)

		// Both exits are legitimate; what is under test is what each printed.
		err := run()
		t.Logf("run() = %v", err)
		return buf.String()
	}

	for _, tc := range []struct {
		name    string
		rotate  bool
		addr    string
		reached string
	}{
		{"the vault path", true, "127.0.0.1:0", "key rotation run finished"},
		{"the serving path", false, "not-an-address", "registered downstream client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setSecrets(t)
			out := runAndCapture(t, tc.rotate, tc.addr)
			if !strings.Contains(out, tc.reached) {
				t.Fatalf("the run never reached %q, so this probe observed nothing:\n%s", tc.reached, out)
			}
			for _, s := range []string{
				kekRaw, clSec, idpSec, srcSec, tokKey, auditK,
				"PROBE-KEK-MATERIAL", "PROBE-TOKEN-KEY-MATERIAL", "PROBE-AUDIT-KEY-MATERIAL",
			} {
				if strings.Contains(out, s) {
					t.Errorf("a secret was printed during startup: %q appears in the log", s)
				}
			}
			t.Logf("startup log (%d bytes) mentions none of the planted secrets:\n%s", len(out), out)
		})
	}
}

// CS-9 probe (FIXED): DATABASE_URL alone now makes the deployment durable, and the
// warning names the real cause.
//
// Before: an environment-only deployment that set DATABASE_URL (the variable every
// doc names as "the way to be durable") still ran in memory — the driver came from
// the file only — and warned `because="no DATABASE_URL"` while the variable was
// set. Now DATABASE_URL alone selects postgres, RE0AUTH_STORAGE_DRIVER exists, and
// the warning states the actual reason.
func TestProbeDatabaseURLAloneSelectsDurable(t *testing.T) {
	probeEnv(t)
	t.Setenv("RE0AUTH_ADDR", "not-an-address")
	// Present, non-empty, and reachable-looking: the variable the docs name.
	t.Setenv("DATABASE_URL", "postgres://user:pass@db.internal:5432/re0auth?sslmode=disable")
	// Durable now that DATABASE_URL selects the driver, so the chain key is
	// mandatory — the very fact this probe is asserting.
	t.Setenv("RE0AUTH_AUDIT_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	dir := t.TempDir()
	// A config with no [storage] section at all.
	path := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(path, []byte("[server]\nissuer = \"https://re0auth.test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig = %v", err)
	}
	if cfg.StorageDriver != "postgres" {
		t.Errorf("driver = %q with DATABASE_URL set, want postgres: the environment-only deployment must be able to be durable", cfg.StorageDriver)
	}
	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL was cleared despite being set, so the deployment is in memory")
	}

	// The environment variable can override it back to memory, and the reason the
	// warning carries is the actual cause.
	t.Setenv("RE0AUTH_STORAGE_DRIVER", "memory")
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StorageDriver != "memory" {
		t.Errorf("RE0AUTH_STORAGE_DRIVER=memory had no effect: driver = %q", cfg.StorageDriver)
	}
	if strings.Contains(cfg.StorageReason, "no DATABASE_URL") {
		t.Errorf("the reason blames a variable that is set: %q", cfg.StorageReason)
	}
	if !strings.Contains(cfg.StorageReason, "storage.driver is memory") {
		t.Errorf("the reason does not name the real cause: %q", cfg.StorageReason)
	}
}

// CS-10 probe: the sections an operator is most likely to invent are refused, and
// every refusal names the problem.
//
// `[oidc]` does not exist in the schema — the OP's two keys are environment-only —
// but it is exactly the section a reader of config/re0auth.example.toml would write
// after seeing `[vault]` beside it. Strict decoding turns that into a refusal that
// names the key rather than a section that silently does nothing. The other two are
// the empty-section cases: present, syntactically fine, and useless.
func TestProbeInventedAndEmptySectionsAreRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := "[server]\nissuer = \"https://re0auth.test\"\n"

	probeEnv(t)
	probeEnvKeep := func() { probeEnv(t) }
	probeEnvKeep()

	cases := []struct {
		name string
		body string
		want string
	}{
		{"an [oidc] section", base + "[oidc]\n", "unknown keys"},
		{"an empty [vault] section with no RE0AUTH_KEK", base + "[vault]\n", "vault"},
		{"postgres without a reachable DSN", base + "[storage]\ndriver = \"postgres\"\ndsn_env = \"PROBE_DSN\"\n",
			"storage.dsn_env"},
		{"a malformed statement timeout", base + "[storage]\nstatement_timeout = \"30\"\n", "duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RE0AUTH_KEK", "")
			t.Setenv("PROBE_DSN", "")
			_, err := loadConfig(write(strings.ReplaceAll(tc.name, " ", "_")+".toml", tc.body))
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name %q: %v", tc.want, err)
			}
			t.Logf("%s -> %v", tc.name, err)
		})
	}

	// Control: the same base with a key and no invented section loads, so the
	// refusals above are not the loader refusing everything.
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, err := loadConfig(write("good.toml", base)); err != nil {
		t.Fatalf("control failed: a valid minimal config was refused: %v", err)
	}
}

// CS-7 probe: duplicate keys in the TOML file.
//
// An operator who writes a setting twice has made a mistake either way; the only
// question is whether the process says so. A silent last-one-wins would mean the
// effective value is not the one a reader of the file would predict — the same
// class of surprise the unknown-key check exists to remove.
func TestProbeDuplicateTOMLKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.toml")
	body := "[server]\nissuer = \"https://a.example\"\nissuer = \"https://b.example\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var f file
	err := config.Read(path, &f)
	t.Logf("duplicate key in one table: err=%v, issuer=%q", err, f.Server.Issuer)

	// And a duplicated whole table.
	path2 := filepath.Join(dir, "duptable.toml")
	body2 := "[server]\nissuer = \"https://a.example\"\n[server]\naddr = \"0.0.0.0:1\"\n"
	if err := os.WriteFile(path2, []byte(body2), 0o600); err != nil {
		t.Fatal(err)
	}
	var f2 file
	err2 := config.Read(path2, &f2)
	t.Logf("duplicated table: err=%v, issuer=%q addr=%q", err2, f2.Server.Issuer, f2.Server.Addr)

	if err == nil && f.Server.Issuer == "https://b.example" {
		t.Logf("a duplicate key silently took the LAST value: the file does not say what it does")
	}
}
