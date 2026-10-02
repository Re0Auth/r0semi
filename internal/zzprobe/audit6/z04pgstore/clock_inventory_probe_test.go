//go:build audit6

package z04pgstore

// The single-clock policy's inventory, over every adapter file — including the
// one the round-5 scanner did not read.
//
// Round 5's TestOnlyReviewedStatementsUseDatabaseNow (internal/zzprobe/pgstore,
// audit5) scans oidc.go, oauth.go and sessions.go. account.go is not in its
// file list, so the adapter's TouchLogin `SET last_login_at = now()` was
// invisible to that guard. This probe scans all thirteen adapter files and
// requires every SQL now() it finds to be one of the reviewed forms, so a new
// unreviewed one fails here no matter which file it lands in.
//
// The reviewed set, with the reason each is acceptable under "a deadline written
// by this process must be judged by this process's clock":
//
//	sessions.go SweepExpired's `now() - $1::interval`   a RELATIVE comparison, so the two
//	                                                    database clocks cancel (round-5 ruling);
//	                                                    it appears twice, in the batch delete
//	                                                    and in the orphan subquery
//	account.go  TouchLogin's `SET last_login_at = now()` a write-only timestamp, never compared
//	                                                    against any deadline in SQL or Go
//	oidc.go     COALESCE(auth_time, now())              a display-only fallback KEPT by the
//	                                                    P2-32 ruling (bf81b2a); allowed if it
//	                                                    ever returns, but it is NOT shipped today
//
// The oidc.go entry is the one that drifted. `auth_time = COALESCE(auth_time, now())`
// sat in CompleteLogin when this probe was written; P2-32 (bf81b2a) parameterized
// it, and the shipped statement is now `SET ... auth_time = $4` with `$4` taken
// from `s.now()` (oidc.go:1323-1326). So oidc.go legitimately reports ZERO SQL
// now() now, and an anti-vacuous check that demands one there asserts a statement
// that no longer exists — the failure this file used to report. That is a probe
// shape problem, not a production defect: the scanner reads oidc.go fine (the
// read sentinel below pins it), and the audit5 sibling already corrected the same
// stale premise (internal/zzprobe/pgstore/clock_source_probe_test.go:57-64).

import (
	"regexp"
	"strings"
	"testing"
)

// sqlNowRE matches `now()` anywhere. It also matches inside Go's `s.now()`
// (`.` is a non-word character, so a word boundary does sit before `now`); the
// region check in sqlNowLinesInCode is what rejects the Go call, not this regex.
var sqlNowRE = regexp.MustCompile(`\bnow\(\)`)

// sqlNowLinesInCode is the scanner as a pure function of Go source: it returns
// the trimmed source line of every `now()` that sits inside a backtick-quoted
// SQL literal. Inside a backtick region `now()` is SQL; outside one it is Go.
// Comment text is removed first, so a `now()` quoted in prose is never counted.
//
// Splitting this out of sqlNowOccurrences is what makes the scanner testable
// against synthetic source (TestTheSQLNowScannerSeparatesSQLFromGoAndComments),
// which is the anti-vacuous half: the extractor is proved to recognise the
// reviewed form and to ignore the Go and comment look-alikes.
func sqlNowLinesInCode(code string) []string {
	code = stripGoComments(code)
	var out []string
	for _, loc := range sqlNowRE.FindAllStringIndex(code, -1) {
		if strings.Count(code[:loc[0]], "`")%2 == 0 {
			continue // Go, not SQL
		}
		start := strings.LastIndex(code[:loc[0]], "\n") + 1
		end := strings.Index(code[loc[0]:], "\n")
		if end < 0 {
			end = len(code) - loc[0]
		}
		out = append(out, strings.TrimSpace(code[start:loc[0]+end]))
	}
	return out
}

// sqlNowOccurrences reads every adapter file and maps file -> the SQL now()
// lines the scanner found in it.
func sqlNowOccurrences(t *testing.T) map[string][]string {
	t.Helper()
	out := make(map[string][]string)
	files := []string{
		"account.go", "audit.go", "auditbatch.go", "auditchain.go", "auditpseudo.go",
		"auditread.go", "federation.go", "oauth.go", "oidc.go", "postgres.go",
		"sessions.go", "sweep.go", "vault.go",
	}
	found := 0
	for _, f := range files {
		lines := sqlNowLinesInCode(readShipped(t, adapterDir+"/"+f))
		if len(lines) > 0 {
			out[f] = lines
			found += len(lines)
		}
	}
	if found < 3 {
		t.Fatalf("found only %d SQL now() occurrences; the scanner is not reading the adapter "+
			"(the shipped code carries three: sessions.go's two relative-interval comparisons and "+
			"account.go's TouchLogin)", found)
	}
	return out
}

// TestEverySQLDatabaseClockUseIsReviewed is the guard: every occurrence must be
// one of the reviewed forms, in any file. It passes today.
func TestEverySQLDatabaseClockUseIsReviewed(t *testing.T) {
	occurrences := sqlNowOccurrences(t)
	reviewed := regexp.MustCompile(`COALESCE\(auth_time, now\(\)\)|now\(\) - \$1::interval|SET last_login_at = now\(\)`)

	for file, lines := range occurrences {
		for _, line := range lines {
			if !reviewed.MatchString(line) {
				t.Errorf("UNREVIEWED now() IN SQL: %s: %s\nOnly the reviewed forms are allowed (the sweep's "+
					"relative interval, TouchLogin's write-only last_login_at, and the P2-32 display-only "+
					"auth_time fallback). Add the new one to the reviewed list with its reason, or replace it "+
					"with an $n parameter written from the store clock", file, line)
			}
		}
	}
}

// TestTheSQLNowScannerSeparatesSQLFromGoAndComments is the extractor's own
// anti-vacuous check: feed it the reviewed form and it must find it; feed it the
// Go and comment look-alikes and it must find nothing. Without this, a scanner
// that returned an empty slice for every input would still let the two tests
// above reason about an empty inventory.
func TestTheSQLNowScannerSeparatesSQLFromGoAndComments(t *testing.T) {
	positive := []struct {
		name string
		src  string
		form string
	}{
		{
			name: "the historical oidc.go display fallback, in a backtick SQL literal",
			src:  "pool.Exec(ctx, `UPDATE oidc_auth_requests SET auth_time = COALESCE(auth_time, now()) WHERE id = $1`)",
			form: "COALESCE(auth_time, now())",
		},
		{
			name: "the shipped sessions.go relative interval",
			src:  "q := `UPDATE session_subjects si SET x = 1 WHERE si.created_at < now() - $1::interval`",
			form: "now() - $1::interval",
		},
		{
			name: "the shipped account.go write-only stamp",
			src:  "q := `UPDATE accounts_identities SET last_login_at = now() WHERE provider = $1`",
			form: "SET last_login_at = now()",
		},
	}
	for _, tc := range positive {
		got := sqlNowLinesInCode(tc.src)
		if len(got) != 1 {
			t.Errorf("%s: scanner found %d SQL now() lines, want exactly 1 (%q)", tc.name, len(got), got)
			continue
		}
		if !strings.Contains(got[0], tc.form) {
			t.Errorf("%s: scanner read the wrong line %q, want one containing %q", tc.name, got[0], tc.form)
		}
	}

	negative := []struct {
		name string
		src  string
	}{
		{
			name: "the store clock and the wall clock, both Go calls outside any SQL literal",
			src:  "func f() {\n\tnow := s.now()\n\ttoday := time.Now()\n\t_ = now\n\t_ = today\n}\n",
		},
		{
			name: "a now() quoted only in a Go comment",
			src:  "// the database now() is display-only here\nx := 1\n",
		},
		{
			name: "a trailing Go comment on a statement that carries no now()",
			src:  "q := `UPDATE oidc_devices SET last_poll = $3 WHERE device_code_hash = $1` // no now()\n",
		},
	}
	for _, tc := range negative {
		if got := sqlNowLinesInCode(tc.src); len(got) != 0 {
			t.Errorf("%s: scanner reported SQL now() where there is none: %q", tc.name, got)
		}
	}
}

// TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter is the anti-vacuous half:
// the reviewed forms still shipped must actually be visible to the scanner, each
// in its own file, or the guard above is asserting over nothing.
//
// oidc.go no longer carries a SQL now() (see the file comment), so demanding one
// there would be a false alarm. What proves the scanner read it is a statement
// sentinel instead — the same shape the audit5 sibling uses for oauth.go.
func TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter(t *testing.T) {
	occurrences := sqlNowOccurrences(t)

	// The reviewed forms that are still shipped: if either disappears from the
	// scanner's output without disappearing from the source, the guard above has
	// gone blind.
	for file, form := range map[string]string{
		"sessions.go": "now() - $1::interval",
		"account.go":  "SET last_login_at = now()",
	} {
		visible := false
		for _, line := range occurrences[file] {
			if strings.Contains(line, form) {
				visible = true
				break
			}
		}
		if !visible {
			t.Errorf("%s reports no SQL now() matching %q; the reviewed statement is gone or the scanner "+
				"is not reading it, and every claim built on it is vacuous", file, form)
		}
	}

	// oidc.go is the file whose reviewed form was removed (P2-32 parameterized
	// CompleteLogin's fallback), so the read control is a statement that must be
	// there, not a now() that must not.
	oidc := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))
	if !strings.Contains(oidc, "UPDATE oidc_devices") {
		t.Error("oidc.go's device statements are not visible; the scanner is not reading the file")
	}
}
