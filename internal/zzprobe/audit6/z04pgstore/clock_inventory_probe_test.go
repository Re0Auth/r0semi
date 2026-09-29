//go:build audit6

package z04pgstore

// The single-clock policy's inventory, over every adapter file — including the
// one the round-5 scanner did not read.
//
// Round 5's TestOnlyReviewedStatementsUseDatabaseNow (internal/zzprobe/pgstore,
// audit5) scans oidc.go, oauth.go and sessions.go. account.go is not in its
// file list, so the adapter's third remaining SQL now() — TouchLogin's
// `SET last_login_at = now()` — is invisible to that guard. This probe scans
// all eight adapter files and requires every SQL now() it finds to be one of
// the reviewed forms, so a new unreviewed one fails here no matter which file
// it lands in.
//
// It is a green probe: the current occurrences are all reviewed. The reviewed
// set, with the reason each is acceptable under "a deadline written by this
// process must be judged by this process's clock":
//
//	oidc.go     CompleteLogin's COALESCE(auth_time, now())   display-only fallback for
//	                                                       when the human authenticated; no
//	                                                       deadline decision reads it (kept by the
//	                                                       P2-32 ruling, bf81b2a)
//	sessions.go SweepExpired's now() - $1::interval          a RELATIVE comparison, so the two
//	                                                       database clocks cancel (round-5 ruling)
//	account.go  TouchLogin's SET last_login_at = now()      a write-only timestamp, never compared
//	                                                       against any deadline in SQL or Go

import (
	"regexp"
	"strings"
	"testing"
)

// sqlNowOccurrences returns every `now()` that sits inside a backtick-quoted
// SQL literal in the adapter's Go files. Inside a backtick region `now()` is
// SQL; outside one it is Go (s.now() never matches: `.` is not a word boundary
// before `now`).
func sqlNowOccurrences(t *testing.T) map[string][]string {
	t.Helper()
	out := make(map[string][]string)
	files := []string{
		"account.go", "audit.go", "auditbatch.go", "auditchain.go", "auditpseudo.go",
		"auditread.go", "federation.go", "oauth.go", "oidc.go", "postgres.go",
		"sessions.go", "sweep.go", "vault.go",
	}
	nowRE := regexp.MustCompile(`\bnow\(\)`)
	found := 0

	for _, f := range files {
		code := stripGoComments(readShipped(t, adapterDir+"/"+f))
		for _, loc := range nowRE.FindAllStringIndex(code, -1) {
			if strings.Count(code[:loc[0]], "`")%2 == 0 {
				continue // Go, not SQL
			}
			start := strings.LastIndex(code[:loc[0]], "\n") + 1
			end := strings.Index(code[loc[0]:], "\n")
			if end < 0 {
				end = len(code) - loc[0]
			}
			line := strings.TrimSpace(code[start : loc[0]+end])
			out[f] = append(out[f], line)
			found++
		}
	}
	if found < 3 {
		t.Fatalf("found only %d SQL now() occurrences; the scanner is not reading the adapter "+
			"(there are three: oidc.go's COALESCE, sessions.go's relative interval, account.go's TouchLogin)", found)
	}
	return out
}

// TestEverySQLDatabaseClockUseIsReviewed is the guard: every occurrence must be
// one of the three reviewed forms, in any file. It passes today.
func TestEverySQLDatabaseClockUseIsReviewed(t *testing.T) {
	occurrences := sqlNowOccurrences(t)
	reviewed := regexp.MustCompile(`COALESCE\(auth_time, now\(\)\)|now\(\) - \$1::interval|SET last_login_at = now\(\)`)

	for file, lines := range occurrences {
		for _, line := range lines {
			if !reviewed.MatchString(line) {
				t.Errorf("UNREVIEWED now() IN SQL: %s: %s\nOnly three forms are reviewed (display-only "+
					"auth_time fallback, the sweep's relative interval, TouchLogin's write-only "+
					"last_login_at). Add the new one to the reviewed list with its reason, or replace it "+
					"with an $n parameter written from the store clock", file, line)
			}
		}
	}
}

// TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter is the anti-vacuous half:
// the reviewed forms must actually be present, each in its own file, or the
// scanner has silently stopped reading one of them.
func TestTheClockPolicyHasNoSecondUnjudgedDeadlineWriter(t *testing.T) {
	occurrences := sqlNowOccurrences(t)
	for _, f := range []string{"oidc.go", "sessions.go", "account.go"} {
		if len(occurrences[f]) == 0 {
			t.Errorf("%s reports no SQL now() but carries one of the reviewed forms; the scanner is not "+
				"reading it and every claim built on it is vacuous", f)
		}
	}
}
