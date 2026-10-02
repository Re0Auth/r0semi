package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// P3 fixes in cmd/re0auth: S08-5, S08-6, S08-8, S08-9, Z10V-2, Z12-5, Z12-8,
// Z12V-1, Z12V-3, Z19V-2, G-22.
//
// Each probe is written to fail on the pre-fix tree: either the behaviour it
// asserts was the opposite, or the helper/field it names did not exist, which is
// a build failure in the same package. Every probe carries a control so a pass
// cannot come from never reaching the code.

// p3Env sets the minimum loadConfig needs and clears the knobs these probes set,
// so one probe's environment cannot explain another's result. The audit5-tagged
// probeEnv is not built into the default suite, so this is its local counterpart.
func p3Env(t *testing.T) {
	t.Helper()
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", "")
	t.Setenv("RE0AUTH_STORAGE_DRIVER", "")
	t.Setenv("RE0AUTH_STORAGE_MAX_CONNS", "")
	t.Setenv("RE0AUTH_KEK_ID", "")
	t.Setenv("RE0AUTH_MAX_UPSTREAM_BUFFER_BYTES", "")
	t.Setenv("RE0AUTH_TRUSTED_PROXIES_ANY", "")
	unsetEnv(t, "RE0AUTH_TRUSTED_PROXIES")
}

func p3Config(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "re0auth.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// S08-5: the acknowledgement guard must key off COVERAGE, not off one entry's
// length: 0.0.0.0/1 + 128.0.0.0/1 covers all of IPv4 exactly as 0.0.0.0/0 does.
func TestP3UniversalTrustedPrefixIsCheckedByCoverage(t *testing.T) {
	p3Env(t)

	// Control: a narrow list is not universal, so the check is not just "true".
	narrow, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if hasUniversalPrefix(narrow) {
		t.Fatalf("a narrow list %v was flagged universal", narrow)
	}
	// Control: the single /0 spelling still is.
	zero, _ := parseTrustedProxies([]string{"0.0.0.0/0"})
	if !hasUniversalPrefix(zero) {
		t.Fatal("control failed: 0.0.0.0/0 was not seen as universal")
	}

	for _, tc := range []struct {
		name string
		list []string
	}{
		{"IPv4 halves", []string{"0.0.0.0/1", "128.0.0.0/1"}},
		{"IPv6 halves", []string{"::/1", "8000::/1"}},
		{"IPv4 quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}},
	} {
		got, err := parseTrustedProxies(tc.list)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !hasUniversalPrefix(got) {
			t.Errorf("%s (%v) covers the whole address family but was not treated as universal; "+
				"the trusted_proxies_any acknowledgement is skipped", tc.name, tc.list)
		}
	}

	// And through the real loader: the split spelling is refused without the
	// acknowledgement and accepted with it.
	path := p3Config(t, "[server]\nissuer = \"https://re0auth.test\"\n"+
		"trusted_proxies = [\"0.0.0.0/1\", \"128.0.0.0/1\"]\n")
	if _, err := loadConfig(path); err == nil {
		t.Error("two /1 halves were accepted with no trusted_proxies_any acknowledgement")
	}
	t.Setenv("RE0AUTH_TRUSTED_PROXIES_ANY", "true")
	if _, err := loadConfig(path); err != nil {
		t.Errorf("the acknowledgement did not permit the split universal list: %v", err)
	}
}

// S08-6 / Z19V-2: -print-secret-env prints role=name, so a value pasted into the
// name slot was echoed to stdout (and into backup-keys.sh and the CI transcript).
func TestP3PrintSecretEnvRefusesAPastedValue(t *testing.T) {
	const pasted = "cGFzdGVkLWtlay1tYXRlcmlhbC0zMi1ieXRlcy1hYmM="
	path := p3Config(t, "[server]\nissuer = \"https://auth.example\"\n\n"+
		"[vault]\nkek_env = \""+pasted+"\"\n")

	lines, err := configSecretEnvNames(path)
	if err == nil {
		t.Fatalf("a value pasted into the kek_env name slot was printed: %q", lines)
	}
	if strings.Contains(err.Error(), pasted) {
		t.Fatalf("the refusal repeats the pasted value: %v", err)
	}
	if !strings.Contains(err.Error(), "vault.kek_env") {
		t.Fatalf("the refusal does not name the field: %v", err)
	}

	// Control: a legal name is still enumerated, and the secret-shaped one among
	// several does not suppress the others silently.
	good := p3Config(t, "[server]\nissuer = \"https://auth.example\"\n\n"+
		"[vault]\nkek_env = \"MY_KEK\"\n\n[client]\nsecret_env = \"CLIENT_SECRET\"\n")
	names, err := configSecretEnvNames(good)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "vault.kek_env=MY_KEK") {
		t.Fatalf("names = %q, want the legal kek_env declaration", names)
	}
}

// S08-8: an explicitly configured 0 was carried to federation.NewService, which
// replaced it with the 64 MiB default — neither applied nor refused.
func TestP3ZeroUpstreamBufferIsRefusedNotDefaulted(t *testing.T) {
	p3Env(t)

	t.Setenv("RE0AUTH_MAX_UPSTREAM_BUFFER_BYTES", "0")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("max_upstream_buffer_bytes = 0 was accepted; federation.NewService silently " +
			"replaces it with the 64 MiB default, so the chosen value is never applied")
	} else if !strings.Contains(err.Error(), "max_upstream_buffer_bytes") {
		t.Fatalf("the refusal does not name the field: %v", err)
	}

	// Control: the sentinel (-1) still means "not chosen", and every value below it
	// is still refused.
	t.Setenv("RE0AUTH_MAX_UPSTREAM_BUFFER_BYTES", "-1")
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("-1 (not chosen) was refused: %v", err)
	}
	if cfg.MaxUpstreamBufferBytes != defaultMaxUpstreamBufferBytes {
		t.Fatalf("MaxUpstreamBufferBytes = %d, want the default %d",
			cfg.MaxUpstreamBufferBytes, defaultMaxUpstreamBufferBytes)
	}
	t.Setenv("RE0AUTH_MAX_UPSTREAM_BUFFER_BYTES", "-2")
	if _, err := loadConfig(""); err == nil {
		t.Fatal("control failed: -2 was accepted, so the zero branch is not the only check")
	}
}

// S08-9: an http issuer is accepted, and nothing at startup named the scheme the
// token exchange (client secret + authorization code) travels over.
func TestP3InsecureIdPIssuerIsRecordedAndWarned(t *testing.T) {
	p3Env(t)

	secure := p3Config(t, "[idp.custom]\nissuer = \"https://idp.example\"\nclient_id = \"re0auth\"\n")
	cfg, err := loadConfig(secure)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.insecureIdPIssuers) != 0 {
		t.Fatalf("an https issuer was flagged insecure: %v", cfg.insecureIdPIssuers)
	}

	insecure := p3Config(t, "[idp.custom]\nissuer = \"http://idp.example\"\nclient_id = \"re0auth\"\n")
	cfg, err = loadConfig(insecure)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cfg.insecureIdPIssuers, "custom") {
		t.Fatalf("insecureIdPIssuers = %v, want it to name the http provider", cfg.insecureIdPIssuers)
	}

	// The startup path must actually say it, naming the provider and the scheme.
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	reportInsecureIdPIssuers(cfg.insecureIdPIssuers)
	if !strings.Contains(buf.String(), "custom") || !strings.Contains(buf.String(), "cleartext") {
		t.Fatalf("no warning named the provider and the cleartext exchange: %q", buf.String())
	}
	buf.Reset()
	reportInsecureIdPIssuers(nil)
	if buf.Len() != 0 {
		t.Fatalf("a warning was emitted with no insecure issuer: %q", buf.String())
	}
}

// Z10V-2: the operational listener has no business traffic to drain, and draining
// it from the same context spent the public listener's budget: whichever went
// first could consume all of it.
func TestP3OperationalListenerIsClosedNotDrained(t *testing.T) {
	// The control first: a drained endpoint whose handler is stuck DOES consume the
	// budget and reports a timeout. The no-drain case below must differ from this.
	t.Run("a drained stuck handler spends the budget", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(started)
				<-release
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		errCh := make(chan error, 1)
		go func() {
			errCh <- serveUntilSignal(ctx, 300*time.Millisecond, 0, nil, endpoint{server: srv, listener: ln})
		}()
		go func() {
			resp, err := http.Get("http://" + ln.Addr().String() + "/")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-started
		start := time.Now()
		cancel()
		err = <-errCh
		if err == nil {
			t.Fatal("control failed: a stuck drained handler did not report a drain timeout")
		}
		if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
			t.Fatalf("control failed: the drain returned in %v, so it did not wait", elapsed)
		}
	})

	t.Run("the operational listener is closed without waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		pubLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		intLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		pub := &http.Server{
			Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
			ReadHeaderTimeout: 5 * time.Second,
		}
		internal := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(started)
				<-release
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		errCh := make(chan error, 1)
		go func() {
			errCh <- serveUntilSignal(ctx, 3*time.Second, 0, nil,
				endpoint{server: pub, listener: pubLn},
				endpoint{server: internal, listener: intLn, noDrain: true})
		}()
		go func() {
			resp, err := http.Get("http://" + intLn.Addr().String() + "/")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-started
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("serveUntilSignal = %v, want nil: Close is a clean stop", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("serveUntilSignal waited on the operational listener's stuck handler; " +
				"it shared the public drain budget instead of being closed")
		}
	})
}

// Z12-5: -migrate-down ran the whole serving-period validation first, so a
// deployment whose KEK or audit chain key was missing could not roll back.
func TestP3MigrateDownNeedsNoServingSecrets(t *testing.T) {
	t.Setenv("RE0AUTH_ISSUER", "")
	t.Setenv("RE0AUTH_KEK", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", "")
	t.Setenv("RE0AUTH_STORAGE_MAX_CONNS", "")
	t.Setenv("DATABASE_URL", "postgres://localhost/r0semi")

	// Control: the serving loader refuses this, which is the behaviour the rollback
	// used to inherit.
	if _, err := loadConfig(""); err == nil {
		t.Fatal("control failed: the serving loader accepted a config with no issuer and no KEK")
	}

	cfg, err := loadMigrateConfig("")
	if err != nil {
		t.Fatalf("the rollback loader refused a config that carries only a DSN: %v", err)
	}
	if cfg.DatabaseURL != "postgres://localhost/r0semi" {
		t.Fatalf("DatabaseURL = %q, want the configured DSN", cfg.DatabaseURL)
	}

	// It still refuses what it actually uses.
	t.Setenv("RE0AUTH_STORAGE_MAX_CONNS", "4294967297")
	if _, err := loadMigrateConfig(""); err == nil {
		t.Fatal("the narrow loader accepted an out-of-range pool size")
	}
}

// Z12-8: positional arguments were never checked, so a flag missing its dash was
// silently ignored and the process served.
func TestP3PositionalArgumentsAreRefused(t *testing.T) {
	if err := rejectPositionalArgs(nil); err != nil {
		t.Fatalf("no positional arguments were refused: %v", err)
	}
	err := rejectPositionalArgs([]string{"rotate-keys"})
	if err == nil {
		t.Fatal("a positional argument (a flag missing its dash) was ignored")
	}
	if !strings.Contains(err.Error(), "rotate-keys") {
		t.Fatalf("the refusal does not name the argument: %v", err)
	}

	// And main actually consults it: removing the call is the regression this
	// pins, and a helper nobody calls would pass the assertions above.
	src, readErr := os.ReadFile("main.go")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(src, []byte("rejectPositionalArgs(flag.Args())")) {
		t.Fatal("main does not reject positional arguments; flag.Args() is unchecked again")
	}
}

// Z12V-1: the record-label id has to follow the same declaration as the key. A
// stale RE0AUTH_KEK_ID labelled records written with the new key as the old one.
func TestP3KekIDFollowsTheFileDeclaration(t *testing.T) {
	p3Env(t)
	keyA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	body := "[server]\nissuer = \"https://re0auth.test\"\n\n" +
		"[vault]\nkek_id = \"kek-2\"\nkek_env = \"MY_KEK\"\n"
	path := p3Config(t, body)
	t.Setenv("MY_KEK", keyA)
	// The KEK itself is the same material, so the stale-KEK check is not what
	// answers here.
	t.Setenv("RE0AUTH_KEK", keyA)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the file's kek_id was refused: %v", err)
	}
	if cfg.KEKID != "kek-2" {
		t.Fatalf("KEKID = %q, want the file's kek-2", cfg.KEKID)
	}

	t.Setenv("RE0AUTH_KEK_ID", "kek-1")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("a stale RE0AUTH_KEK_ID labelling new-key records with the old id was accepted")
	} else if !strings.Contains(err.Error(), "RE0AUTH_KEK_ID") || !strings.Contains(err.Error(), "kek-2") {
		t.Fatalf("the refusal names neither the stale variable nor the file's id: %v", err)
	}

	// Control: with no kek_id in the file the environment is still the source.
	t.Setenv("RE0AUTH_KEK_ID", "kek-9")
	envOnly := p3Config(t, "[vault]\nkek_env = \"MY_KEK\"\n")
	cfg, err = loadConfig(envOnly)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KEKID != "kek-9" {
		t.Fatalf("KEKID = %q, want the environment's kek-9 when the file names none", cfg.KEKID)
	}
}

// Z12V-3: an integer outside int32 was reported as "not an integer", pointing the
// operator at a typo instead of at the magnitude.
func TestP3EnvInt32SeparatesRangeFromSyntax(t *testing.T) {
	t.Setenv("P3_POOL_SIZE", "4294967297")
	_, err := envInt32("P3_POOL_SIZE", 4)
	if err == nil {
		t.Fatal("an out-of-range pool size was accepted")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("err = %v, want it to say the value is out of range", err)
	}

	t.Setenv("P3_POOL_SIZE", "abc")
	_, err = envInt32("P3_POOL_SIZE", 4)
	if err == nil || !strings.Contains(err.Error(), "not an integer") {
		t.Fatalf("err = %v, want a syntax refusal for a non-number", err)
	}

	t.Setenv("P3_POOL_SIZE", "16")
	n, err := envInt32("P3_POOL_SIZE", 4)
	if err != nil || n != 16 {
		t.Fatalf("envInt32(in range) = %d, %v, want 16, nil", n, err)
	}
}

// G-22: the KEK, the OP token key and the audit chain key could all be the same
// value with no signal, so one leak covered three roles.
func TestP3ReusedKeyMaterialIsReported(t *testing.T) {
	var a, b [32]byte
	a[0] = 0xAA
	b[0] = 0xBB

	if got := keyRoleReuse(a[:], nil, b); len(got) != 0 {
		t.Fatalf("distinct keys were reported as reused: %v", got)
	}
	got := keyRoleReuse(a[:], nil, a)
	if !slices.Contains(got, "the vault KEK and the OP token key") {
		t.Fatalf("keyRoleReuse = %v, want the KEK/token-key pair", got)
	}
	if got := keyRoleReuse(a[:], a[:], a); len(got) != 3 {
		t.Fatalf("keyRoleReuse = %v, want all three pairs for one shared value", got)
	}

	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	reportReusedKeys(a[:], a[:], a)
	out := buf.String()
	if !strings.Contains(out, "more than one role") || !strings.Contains(out, "vault KEK") {
		t.Fatalf("no warning named the reuse: %q", out)
	}
	buf.Reset()
	reportReusedKeys(a[:], nil, b)
	if buf.Len() != 0 {
		t.Fatalf("a warning was emitted for distinct keys: %q", buf.String())
	}
}
