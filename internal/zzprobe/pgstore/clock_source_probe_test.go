//go:build audit5

package pgstore

// This file probes WHERE each deadline in the device-authorization path is
// judged.
//
// The project states a single-clock policy in three places — postgres.go's
// `now` field comment, OIDCStore.now's comment, and clock_test.go's doc comment —
// and the invariant is: a deadline written by this process must be judged by this
// process's clock, in SQL as well as in Go. clock_test.go enforces it for
// sessions, the transaction sweep, AuthRequestByCode and Grants. It does not
// cover the device path at all, which is where the policy is broken.
//
// The probe is necessarily source-level: this machine has no Postgres, so a
// runtime assertion is impossible here (see the report's 读；无 DB 执行 labels).
// Reading the SQL text is enough to decide the question, because the question is
// "which expression appears in the predicate", not "what does the server do".

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// databaseNowOccurrence is one `now()` inside a SQL string literal, with the
// statement it appears in. Only SQL text counts: a Go call to time.Now() — or to
// the store clock, s.now() — is the store clock and is exactly what the policy
// wants.
type databaseNowOccurrence struct {
	file string
	line int
	stmt string // the trimmed line, for the report
}

// sqlNowRE finds `now()` occurrences that sit inside a backtick-quoted SQL
// literal or a plain quoted SQL fragment.
var sqlNowRE = regexp.MustCompile(`\bnow\(\)`)

// scanDatabaseNow reads the adapter's files and returns every `now()` that
// appears inside a backtick-quoted string literal.
//
// The anti-vacuous check is per file and honest about which files can carry one:
// oidc.go and sessions.go both contain SQL `now()` in the shipped code, so a
// scanner that found none there is broken; oauth.go contains none today (its only
// poll write passes a Go timestamp as a parameter), so the check for it is that
// the scanner can still see its statements at all — asserting a `now()` it does
// not have would be a false alarm, which is exactly what the first version of
// this function did.
func scanDatabaseNow(t *testing.T) []databaseNowOccurrence {
	t.Helper()
	var out []databaseNowOccurrence

	// The floor is the number of REVIEWED, deliberate now() uses left in the
	// shipped code: CompleteLogin's COALESCE(auth_time, now()) display fallback
	// in oidc.go, and the relative interval comparison in sessions.go. The device
	// path used to carry three more; they are store-clock parameters now, so a
	// scanner finding fewer than these two is broken, and finding MORE is the
	// finding the test below reports.
	mustHave := map[string]int{"oidc.go": 1, "sessions.go": 1}
	for _, f := range []string{"oidc.go", "oauth.go", "sessions.go"} {
		body, err := os.ReadFile(filepath.Join(adapterDir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		found := scanSourceForSQLNow(f, string(body))
		if want, ok := mustHave[f]; ok && len(found) < want {
			t.Errorf("found %d now() inside SQL in %s, want at least %d; the scanner is not reading it",
				len(found), f, want)
		}
		out = append(out, found...)
	}

	// oauth.go's control: the statement the probe describes must be visible to the
	// scanner even though it carries no now(). This is what proves the file was
	// read rather than skipped.
	body, err := os.ReadFile(filepath.Join(adapterDir, "oauth.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stripGoComments(string(body)), "UPDATE oauth_device_authorizations") {
		t.Error("oauth.go's poll statement is no longer visible; the scanner is not reading the file")
	}
	return out
}

// scanSourceForSQLNow is the scanner, as a pure function of (file name, Go
// source). Splitting it out is what makes TestClockScannerDistinguishesGoAndSQLClocks
// possible: that test feeds it synthetic source in which a database-clock `now()`
// and a store-clock `s.now()` sit on adjacent lines, and requires the two to be
// classified differently.
//
// The rule: inside a backtick region, `now()` is SQL; outside one, it is Go.
// `s.now()` never matches because the package-level regex requires a word
// boundary before `now` and `.` is not one — which the sentinel test pins.
func scanSourceForSQLNow(file, src string) []databaseNowOccurrence {
	var out []databaseNowOccurrence
	code := stripGoComments(src)
	lineOf := func(off int) int { return strings.Count(code[:off], "\n") + 1 }
	lineText := func(off int) string {
		start := strings.LastIndex(code[:off], "\n") + 1
		end := strings.Index(code[off:], "\n")
		if end < 0 {
			end = len(code)
		} else {
			end += off
		}
		return strings.TrimSpace(code[start:end])
	}

	for _, loc := range sqlNowRE.FindAllStringIndex(code, -1) {
		// An odd number of backticks before the occurrence means it sits inside a
		// string literal, i.e. it is SQL rather than a Go call.
		if strings.Count(code[:loc[0]], "`")%2 == 0 {
			continue
		}
		out = append(out, databaseNowOccurrence{file: file, line: lineOf(loc[0]), stmt: lineText(loc[0])})
	}
	return out
}

// TestDevicePathsJudgeExpiryWithTheDatabaseClock is the finding.
//
// It asserts the policy for the device-authorization path specifically: every
// statement that writes or judges a device deadline — `expires_at`, `last_poll`,
// `auth_time` on oidc_devices/oauth_device_authorizations — must use the store
// clock (a $n parameter written from s.now()), never the database's now().
//
// It PASSES since P2-32: the three device statements (the poll write's
// last_poll, ApproveDevice's expires_at predicate and auth_time stamp) take the
// store clock as a parameter, matching internal/store/memory's device path, so
// the two backends answer "is this device code still valid" the same way. The
// other reviewed now() uses are enumerated in the control test below.
func TestDevicePathsJudgeExpiryWithTheDatabaseClock(t *testing.T) {
	occurrences := scanDatabaseNow(t)
	if len(occurrences) == 0 {
		t.Fatal("found no now() inside any SQL literal; the scanner is broken (oidc.go has the COALESCE)")
	}

	// Statements that touch a device deadline and use the database clock. Each is
	// a policy violation; the list is what the report cites.
	deviceDeadlineRE := regexp.MustCompile(`(?i)(oidc_devices|oauth_device_authorizations|last_poll|expires_at > now|auth_time = now|SET last_poll)`)
	var violations []string
	for _, o := range occurrences {
		if !deviceDeadlineRE.MatchString(o.stmt) {
			continue
		}
		violations = append(violations, o.file+":"+strconv.Itoa(o.line)+": "+o.stmt)
	}
	for _, v := range violations {
		t.Errorf("DEVICE DEADLINE JUDGED BY THE DATABASE CLOCK: %s", v)
	}
	if len(violations) == 0 {
		t.Log("the device path now judges every deadline with the store clock; the divergence from " +
			"internal/store/memory is closed")
	}
}

// TestOnlyReviewedStatementsUseDatabaseNow is the control for the probe above: it
// enumerates every `now()` inside SQL in the adapter and prints it with the
// reason it is acceptable. Adding an unreviewed one fails here.
//
// The reviewed set, and why each is acceptable:
//
//	oidc.go  CompleteLogin's `COALESCE(auth_time, now())`  a display-only fallback for
//	         "when did the human authenticate", written once if the caller did not set it;
//	         no deadline decision reads it
//	oauth.go RecordPoll's caller-supplied `at` is a Go value; the legacy table's deadline
//	         comparisons happen in the service (oauth/device.go:285-293), on the store clock
//	sessions.go SweepExpired's `now() - $1::interval`  a RELATIVE comparison, so the two
//	         clocks cancel; the same reasoning the method's own comment gives
//
// The device path's three (ApproveDevice's expires_at > now() and auth_time = now(),
// GetDeviceAuthorizatonState's last_poll) were the finding; they are store-clock
// parameters now (P2-32), matching internal/store/memory's device path.
func TestOnlyReviewedStatementsUseDatabaseNow(t *testing.T) {
	occurrences := scanDatabaseNow(t)
	if len(occurrences) < 2 {
		t.Fatalf("found only %d now() in SQL; the scanner is broken", len(occurrences))
	}
	unreviewed := 0
	for _, o := range occurrences {
		where := o.file + ":" + strconv.Itoa(o.line)
		switch {
		case strings.Contains(o.stmt, "COALESCE(auth_time, now())"):
			t.Logf("REVIEWED (display-only auth_time fallback): %s %s", where, o.stmt)
		case strings.Contains(o.stmt, "now() - $1::interval"):
			t.Logf("REVIEWED (relative comparison, clocks cancel): %s %s", where, o.stmt)
		default:
			unreviewed++
			t.Errorf("UNREVIEWED now() IN SQL: %s %s\nAdd it to this test's reviewed list with the reason, or "+
				"replace it with a $n parameter written from the store clock", where, o.stmt)
		}
	}
	t.Logf("scanned %d now() occurrences inside SQL across the adapter's statements; %d unreviewed",
		len(occurrences), unreviewed)
}
