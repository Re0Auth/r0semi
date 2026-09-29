//go:build audit7

// Loader-level probes: values that are read, validated in the wrong way, or
// impossible to express from the environment.
package z12configstartupobservability

import (
	"fmt"
	"strings"
	"testing"
)

// Z12-9: the pool sizes read from the file are cast to int32 without a range
// check, so a number the operator typed can become a different number.
//
// cmd/re0auth/config.go:1062-1067 does `out.MaxConns = int32(*section.MaxConns)`
// (and the same for MinConns). On a 64-bit build `int` holds 2^63-1, so every
// value above 2^31-1 is silently truncated — the environment path next to it uses
// strconv.ParseInt(raw, 10, 32) and refuses what does not fit, so the two spellings
// of the same setting disagree.
//
// The truncation is invisible in the process: resolvePool validates the truncated
// value, and a pool of 1 (from 2^32+1) passes "must be at least 1" and starts.
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

	run := func(t *testing.T, body string) runResult {
		t.Helper()
		path := writeConfig(t, "pool.toml", serverOnly+body)
		return runBinary(t, base, "-config", path)
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
	if got := run(t, maxConns(0)); !strings.Contains(got.out, "stage=config") ||
		!strings.Contains(got.out, "max_conns") {
		t.Fatalf("control failed: max_conns = 0 was not refused at the config stage:\n%s", got.out)
	}
	if got := run(t, maxConns(16)); !strings.Contains(got.out, "stage=storage") {
		t.Fatalf("control failed: max_conns = 16 did not reach the storage stage:\n%s", got.out)
	}

	// Mechanism: 2^32 truncates to 0 and is refused as if the operator had typed
	// 0, which is the truncation made visible.
	if got := run(t, maxConns(1<<32)); !strings.Contains(got.out, "stage=config") ||
		!strings.Contains(got.out, "max_conns must be at least 1") {
		t.Fatalf("2^32 in max_conns was not reported as 0, so the truncation premise is wrong:\n%s", got.out)
	}

	// The finding: 2^32+1 truncates to 1 and is accepted. The operator asked for
	// 4294967297 connections and got one, with nothing said.
	got := run(t, maxConns(1<<32+1))
	if !strings.Contains(got.out, "stage=config") {
		t.Errorf("max_conns = 4294967297 was accepted (it reached stage=storage, i.e. it was read as 1) "+
			"instead of being refused as out of range:\n%s", got.out)
	} else {
		t.Logf("max_conns = 4294967297 was refused: %s", oneLine(got.out))
	}

	// min_conns shows the other direction: 2^32 truncates to 0, which is a legal
	// value, so it is silently accepted as "no warm connections".
	gotMin := run(t, minConns(1<<32))
	if strings.Contains(gotMin.out, "stage=config") {
		t.Logf("min_conns = 2^32 was refused")
	} else {
		t.Errorf("min_conns = 4294967296 was accepted as 0 warm connections instead of being refused "+
			"as out of range (reached stage=storage):\n%s", gotMin.out)
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
	got := runBinary(t, env, "-config", path)
	if !strings.Contains(got.out, "operator plane enabled") {
		t.Fatalf("the run never reached the operator-plane mount, so this probe observed nothing:\n%s", got.out)
	}
	t.Errorf("RE0AUTH_ADMIN_SUBJECTS=\"\" did not clear the file's allowlist: the operator plane is "+
		"still mounted for usr_operator. There is no spelling that turns it off from the environment\n%s", got.out)
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
