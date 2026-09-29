//go:build audit6

package z05memstore

// Falsification probes for finding 05-1 (the Postgres refresh-token TTL is
// never judged on the read path; only the 15-minute sweep removes the row).
//
// The runtime half cannot run in this environment (no database), so these
// attack the finding the only other way available: against the shipped
// adapter source, with controls on both sides of the claimed drift so a
// missing string can never pass vacuously.
//
// If finding 05-1 is wrong, the first probe is GREEN: the refresh grant's
// lookup and the rotation claim would carry an expires_at predicate. It is
// red today, which is the source-level half of the evidence the original
// report could only assert by reading.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// revRepoRoot is the workspace root, resolved from this package's test working
// directory (go test runs with the package directory as cwd).
const revRepoRoot = "../../../.."

// revRead returns a tracked file's bytes, failing loudly when the path does
// not resolve — a probe that reads nothing passes vacuously.
func revRead(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(revRepoRoot + "/" + path))
	if err != nil {
		t.Fatalf("read %s: %v (path resolution broken; every assertion built on it is vacuous)", path, err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return string(body)
}

// revStripComments removes // and /* */ comments so SQL fragments quoted in
// prose are never mistaken for executed code.
func revStripComments(src string) string {
	out := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// revMethodBody returns one method's source, from its func line to the next
// top-level func declaration.
func revMethodBody(t *testing.T, code, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \([^)]*\) ` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(code)
	if loc == nil {
		t.Fatalf("method %s not found; the probe is not reading the file (was it renamed?)", name)
	}
	rest := code[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	return rest
}

// TestRev1ThePostgresRefreshReadPathJudgesExpiry is the falsification attempt
// for 05-1: if the Postgres adapter judged a refresh token's deadline anywhere
// on its read or rotation path, this is green and the finding is wrong.
func TestRev1ThePostgresRefreshReadPathJudgesExpiry(t *testing.T) {
	code := revStripComments(revRead(t, "internal/store/postgres/oidc.go"))

	// The lookup the refresh grant consults (zitadel/oidc's
	// pkg/op/token_refresh.go checks no expiry of its own, so this SELECT is
	// the only place the deadline could be judged on the wire path).
	read := revMethodBody(t, code, "TokenRequestByRefreshToken")
	if !strings.Contains(read, "expires_at") {
		t.Errorf("finding 05-1 stands: TokenRequestByRefreshToken never mentions expires_at — the refresh grant's " +
			"lookup never judges the 30-day TTL in the Postgres backend, while the memory twin refuses at the deadline")
	}

	// The rotation claim: the DELETE that spends the presented token.
	rotate := revMethodBody(t, code, "CreateAccessAndRefreshTokens")
	claim := regexp.MustCompile(`DELETE FROM oidc_refresh_tokens[^;]*`).FindString(rotate)
	if claim == "" {
		t.Fatal("the rotation claim DELETE was not found; the probe is not reading the method")
	}
	if !strings.Contains(claim, "expires_at") {
		t.Errorf("finding 05-1 stands: the rotation claim %q carries no expiry predicate — an expired token is "+
			"spent and re-minted without its deadline ever being consulted", claim)
	}

	// Controls, so a missing string cannot pass vacuously:
	// (a) the same file's authorization-code claim DOES judge expiry — the
	// in-file shape a fix would copy, proving the omission is path-specific.
	byCode := revMethodBody(t, code, "AuthRequestByCode")
	codeClaim := regexp.MustCompile(`DELETE FROM oidc_codes[^;]*`).FindString(byCode)
	if codeClaim == "" || !strings.Contains(codeClaim, "expires_at") {
		t.Fatal("control broken: AuthRequestByCode's claim no longer judges expiry, so the comparison above is vacuous")
	}
	// (b) the memory twin judges the same deadline on the same method — the
	// direction of the drift the finding claims.
	mem := revStripComments(revRead(t, "internal/store/memory/oidc.go"))
	memRead := revMethodBody(t, mem, "TokenRequestByRefreshToken")
	if !strings.Contains(memRead, "expiresAt") {
		t.Fatal("control broken: the memory twin's TokenRequestByRefreshToken no longer judges expiresAt")
	}
}

// TestRev1TheSweepRemainsTheOnlyExpiryEnforcer pins the finding's other half:
// the deadline is written into the row and removed only by the sweep, which
// the composition root runs every 15 minutes while the memory mode runs its
// own janitor every 5.
func TestRev1TheSweepRemainsTheOnlyExpiryEnforcer(t *testing.T) {
	sweep := revRead(t, "internal/store/postgres/sweep.go")
	if !strings.Contains(sweep, `{"oidc_refresh_tokens", "expires_at"}`) {
		t.Fatal("control broken: the sweep no longer lists oidc_refresh_tokens with its expires_at column")
	}

	adapter := revRead(t, "internal/store/postgres/oidc.go")
	if !strings.Contains(adapter, "30 * 24 * time.Hour") {
		t.Fatal("control broken: the Postgres adapter no longer pins the 30-day refresh TTL")
	}

	main := revRead(t, "cmd/re0auth/main.go")
	if !strings.Contains(main, "sweepLoop(loopCtx, store.sweep, 15*time.Minute)") {
		t.Fatal("control broken: main.go no longer runs the Postgres expiry sweep every 15 minutes")
	}
	if !strings.Contains(main, "opJanitorInterval = 5 * time.Minute") {
		t.Fatal("control broken: main.go no longer runs the memory janitor every 5 minutes")
	}
}
