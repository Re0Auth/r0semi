//go:build audit7

// Loader-level probes: values that are read, validated in the wrong way, or
// impossible to express from the environment.
package z12configstartupobservability

import (
	"fmt"
	"strings"
	"testing"
)

// Z12-9 / Z12V-3 — 原为发现演示，现为回归守卫.
//
// The finding was that the pool sizes read from the file were cast to int32
// without a range check (`out.MaxConns = int32(*section.MaxConns)`), so 2^32
// truncated to 0 and 2^32+1 truncated to 1 and was accepted, while the
// environment spelling next to it used strconv.ParseInt(..., 32) and refused what
// did not fit. cmd/re0auth/config.go:1488-1493 now routes both spellings through
// poolSize, which refuses anything outside int32 by name, and envInt32
// (config.go:1502-1514) separates "a number that does not fit" (strconv.ErrRange)
// from "not a number", so the two spellings no longer disagree and the message
// points at the right problem (Z12V-3).
//
// The guard asserts both: a file value outside int32 is refused at stage=config
// with an "out of range" message (not silently truncated), and the environment
// spelling distinguishes a magnitude error from a syntax error.
//
// Proven without a database: the connect step is aimed at 127.0.0.1:1, so a value
// that survives validation dies at stage=storage (a connection refusal) while a
// value that does not dies at stage=config. The two stages are the measurement.
func TestZ12PoolSizesAreTruncatedToInt32(t *testing.T) {
	base := map[string]string{
		"RE0AUTH_ISSUER":                  "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":           "true",
		"RE0AUTH_KEK":                     key32("Z12-KEK-MATERIAL-32-BYTES-CCC!"),
		"RE0AUTH_AUDIT_KEY":               key32("Z12-AUDIT-KEY-MATERIAL-32C!!"),
		"RE0AUTH_ADDR":                    "not-an-address",
		"RE0AUTH_STORAGE_CONNECT_TIMEOUT": "1s",
		"DATABASE_URL":                    "postgres://z12u:z12p@127.0.0.1:1/z12db?sslmode=disable",
	}

	run := func(t *testing.T, extra map[string]string, body string) runResult {
		t.Helper()
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		path := writeConfig(t, "pool.toml", serverOnly+body)
		return runBinary(t, env, "-config", path)
	}
	// min_conns = 0 throughout, so the default min_conns (2) cannot be what
	// refuses a max_conns that truncates to a small number: the two checks have to
	// be told apart.
	maxConns := func(v any) string {
		return fmt.Sprintf("[storage]\ndriver = \"postgres\"\ndsn_env = \"DATABASE_URL\"\nmin_conns = 0\nmax_conns = %v\n", v)
	}
	minConns := func(v any) string {
		return fmt.Sprintf("[storage]\ndriver = \"postgres\"\ndsn_env = \"DATABASE_URL\"\nmax_conns = 16\nmin_conns = %v\n", v)
	}

	// Controls. 0 is refused (the validation runs at all), 16 is accepted and the
	// run moves on to the connection attempt.
	if got := run(t, nil, maxConns(0)); !strings.Contains(got.out, "stage=config") ||
		!strings.Contains(got.out, "max_conns") {
		t.Fatalf("control failed: max_conns = 0 was not refused at the config stage:\n%s", got.out)
	}
	if got := run(t, nil, maxConns(16)); !strings.Contains(got.out, "stage=storage") {
		t.Fatalf("control failed: max_conns = 16 did not reach the storage stage:\n%s", got.out)
	}

	// Subject (file path): every value outside int32 is refused by name at the
	// config stage. 2^32 used to truncate to 0 and 2^32+1 to 1 (the latter was
	// accepted silently); both must now be "out of range".
	for _, tc := range []struct {
		name  string
		body  string
		field string
	}{
		{"max_conns = 2^32", maxConns(1 << 32), "max_conns"},
		{"max_conns = 2^32+1", maxConns(1<<32 + 1), "max_conns"},
		{"min_conns = 2^32", minConns(1 << 32), "min_conns"},
		{"min_conns = 2^32+1", minConns(1<<32 + 1), "min_conns"},
	} {
		got := run(t, nil, tc.body)
		if !strings.Contains(got.out, "stage=config") {
			t.Errorf("%s was accepted (reached %s) instead of being refused at the config stage: "+
				"the truncation is back, or the range check stopped running:\n%s",
				tc.name, stageOf(got.out), got.out)
			continue
		}
		if !strings.Contains(got.out, "out of range") || !strings.Contains(got.out, tc.field) {
			t.Errorf("%s was refused, but not with an %q message naming %s:\n%s",
				tc.name, "out of range", tc.field, oneLine(got.out))
			continue
		}
		t.Logf("%s refused at the config stage: %s", tc.name, oneLine(got.out))
	}

	// Subject (environment path, Z12V-3): a magnitude error must not be reported
	// as "not an integer" — that sends the operator looking for a typo.
	envBody := maxConns(16)
	if got := run(t, map[string]string{"RE0AUTH_STORAGE_MAX_CONNS": "4294967296"}, envBody); !strings.Contains(got.out, "out of range") {
		t.Errorf("RE0AUTH_STORAGE_MAX_CONNS=4294967296 was not refused as out of range (Z12V-3); "+
			"a magnitude error must not read like a syntax error:\n%s", got.out)
	} else {
		t.Logf("RE0AUTH_STORAGE_MAX_CONNS=4294967296: %s", oneLine(got.out))
	}
	if got := run(t, map[string]string{"RE0AUTH_STORAGE_MAX_CONNS": "not-a-number"}, envBody); !strings.Contains(got.out, "not an integer") {
		t.Errorf("RE0AUTH_STORAGE_MAX_CONNS=not-a-number was not refused as a syntax error:\n%s", got.out)
	} else {
		t.Logf("RE0AUTH_STORAGE_MAX_CONNS=not-a-number: %s", oneLine(got.out))
	}
}

// Z12-2: -rotate-keys against a store that cannot hold credentials reports
// success.
//
// rotationReport (main.go:1209-1231) treats "scanned == 0" as a line of prose and
// still returns complete=false, so the command exits 0. The documented gate in
// config/re0auth.example.toml ("repeat it until it prints rewrapped=0 skipped=0
// AND exits 0") is then already satisfied by a run against the in-memory store,
// which holds no credentials at all — the one run that cannot have made anything
// safer is the one that says "nothing left to do". The remedy line is printed, so
// the information is there; the exit code, which is what automation reads, is not.
func TestZ12RotateKeysExitsZeroHavingScannedNothing(t *testing.T) {
	env := minimalEnv()
	path := writeConfig(t, "rotate.toml", serverOnly)

	got := runBinary(t, env, "-config", path, "-rotate-keys")
	// Anti-vacuous: the run really did execute the rotation and really did scan
	// nothing.
	if !strings.Contains(got.out, "scanned=0") {
		t.Fatalf("the run did not report a scan, so it did not reach the rotation:\n%s", got.out)
	}
	if !strings.Contains(got.out, "nothing to rotate") {
		t.Fatalf("the run did not report that it had nothing to rotate:\n%s", got.out)
	}
	if got.code != 0 {
		t.Logf("-rotate-keys over an empty store exited %d", got.code)
		return
	}
	t.Errorf("-rotate-keys over an in-memory store (which by construction holds no credentials) "+
		"printed scanned=0 and exited 0, the same success signal a completed rotation gives; "+
		"the documented gate then removes the retired key:\n%s", got.out)
}

// Z12-4: a file-configured list cannot be turned OFF from the environment.
//
// server.rate_limit is a pointer precisely so that "absent" (take the default) is
// distinguishable from an explicit zero (turn it off) — the comment says a
// deployment that wanted limiting off "would silently get the default". The three
// list settings use the opposite rule: an empty RE0AUTH_ADMIN_SUBJECTS /
// RE0AUTH_TRUSTED_PROXIES / RE0AUTH_INTROSPECTION_CLIENTS is treated as unset, so
// the file's value survives and the operator's attempt to empty it is silently
// ignored. For the admin allowlist that means the operator plane stays mounted
// while the environment says nobody is an operator.
func TestZ12FileConfiguredListsCannotBeClearedFromTheEnvironment(t *testing.T) {
	env := serveEnv()
	env["RE0AUTH_ADMIN_SUBJECTS"] = "" // the operator's way of saying "nobody"
	env["RE0AUTH_INTROSPECTION_CLIENTS"] = ""

	// Control: with no [admin] section the same empty environment leaves the
	// operator plane unmounted, so the log line this probe looks for is specific.
	plain := writeConfig(t, "plain.toml", serverOnly)
	if got := runBinary(t, env, "-config", plain); strings.Contains(got.out, "operator plane enabled") {
		t.Fatalf("control failed: the operator plane was mounted with no allowlist anywhere:\n%s", got.out)
	}

	path := writeConfig(t, "admin.toml", serverOnly+"\n[admin]\nsubjects = [\"usr_operator\"]\n")

	// Control: with the variable unset the file's allowlist does mount the plane,
	// so the empty environment is what changed the outcome.
	fileOnly := serveEnv()
	if withFile := runBinary(t, fileOnly, "-config", path); !strings.Contains(withFile.out, "operator plane enabled") {
		t.Fatalf("control failed: the file's allowlist did not mount the operator plane:\n%s", withFile.out)
	}

	got := runBinary(t, env, "-config", path)
	if strings.Contains(got.out, "operator plane enabled") {
		t.Fatalf("RE0AUTH_ADMIN_SUBJECTS=\"\" did not clear the file's allowlist: the operator plane is "+
			"still mounted for usr_operator\n%s", got.out)
	}
	// A surface that is unmounted by configuration must be announced, or the two
	// outcomes look the same in the log (Z12-4).
	if !strings.Contains(got.out, "operator plane disabled") {
		t.Fatalf("the cleared operator plane was not announced at startup:\n%s", got.out)
	}
	if !strings.Contains(got.out, "access lists resolved") {
		t.Fatalf("the effective access lists were not logged:\n%s", got.out)
	}
}

// stageOf pulls the stage= field out of a startFailure log line, for messages.
func stageOf(out string) string {
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "stage=") {
			return field
		}
	}
	return "an unknown stage"
}
