package postgres

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// W3 / G-15 source guards, default build. The register adjudicated Direction A
// for the device poll throttle — both engines anchor the RFC 8628 §3.5 interval
// at the client's LAST ATTEMPT, not at its last admitted poll — and the postgres
// half is a statement shape, so it is pinned here where it needs no database.
//
// The memory half's behavior is pinned by
// internal/store/memory/oidc_test.go::TestDeviceThrottleAnchorsOnTheLastAttempt;
// the memory *source* assertion below is only the cross-engine companion of the
// postgres shape, so a flip of either engine shows up in the default `go test`
// run where the Postgres integration tests skip without TEST_DATABASE_URL.

// TestW3G15DevicePollClaimMovesTheAnchorOnEveryAttempt is the postgres shape
// guard: the claim moves last_poll unconditionally and judges the OLD value it
// read under the same lock, which is what makes the window run from the last
// attempt rather than the last admission.
func TestW3G15DevicePollClaimMovesTheAnchorOnEveryAttempt(t *testing.T) {
	source, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("read oidc.go: %v", err)
	}
	body := methodBody(t, string(source), "func (s *OIDCStore) GetDeviceAuthorizatonState(")

	claim := sqlStatement(t, body, "UPDATE oidc_devices")
	if !strings.Contains(claim, "SET last_poll = $3") {
		t.Fatalf("the poll claim no longer writes last_poll: %q", collapse(claim))
	}
	// Direction A: the anchor moves on a throttled attempt too, so the claim
	// must NOT gate its own write on last_poll. Either predicate below is the
	// old last-admitted anchor reintroduced.
	if strings.Contains(claim, "last_poll <=") || strings.Contains(claim, "last_poll IS NULL") {
		t.Error("the poll claim predicates its own write on last_poll again: a premature attempt writes " +
			"nothing and the interval is anchored at the last ADMITTED poll — the cross-engine divergence " +
			"G-15 adjudicated against (Direction A). The write must be unconditional; the window decides " +
			"only whether the poll is admitted, not whether the anchor moves")
	}

	// The old value must be read under a row lock, and the lock must come before
	// the write — otherwise two concurrent polls can read the same pre-winner
	// anchor and both admit themselves (TOCTOU).
	lock := regexp.MustCompile(`(?s)SELECT last_poll FROM oidc_devices.*?FOR UPDATE`).FindString(body)
	if lock == "" {
		t.Fatal("the poll claim no longer reads the old last_poll under `FOR UPDATE`: the admission " +
			"decision needs the value the row held BEFORE this statement, and the row lock is what " +
			"serializes concurrent polls against each other")
	}
	if strings.Index(body, lock) > strings.Index(body, claim) {
		t.Error("the locked read of the old last_poll comes after the UPDATE in source order: re-derive " +
			"this guard, the claim's shape is not what the probe is reading")
	}
	if !regexp.MustCompile(`previous\s*!=\s*nil\s*&&\s*previous\.After\(staleBefore\)`).MatchString(body) {
		t.Error("the poll claim does not decide admission by comparing the OLD anchor against staleBefore " +
			"(s.now() - DefaultDevicePollInterval): the only value that answers \"did a full interval pass " +
			"since the last attempt\" is the one read before the write")
	}

	// Read and write are one transaction: the lock is held from the read to the
	// commit, which is the whole reason the decision cannot race.
	if !strings.Contains(body, "s.pool.Begin(ctx)") || !strings.Contains(body, "tx.Commit(ctx)") {
		t.Error("the poll claim is not one transaction: the old anchor is read and the new one is written " +
			"in separate statements, so a concurrent poll can slip between them and be admitted against a " +
			"stale anchor")
	}

	if !strings.Contains(body, "context.DeadlineExceeded") {
		t.Error("the poll claim no longer has a slow_down path: the RFC 8628 §3.5 refusal is gone")
	}
}

// TestW3G15MemoryThrottledPollStillMovesTheAnchor is the other engine's source
// half of the consistency guard above: memory advances lastPoll on the rejected
// attempt before returning slow_down, which is the anchor postgres now copies.
func TestW3G15MemoryThrottledPollStillMovesTheAnchor(t *testing.T) {
	source, err := os.ReadFile("../memory/oidc.go")
	if err != nil {
		t.Fatalf("read ../memory/oidc.go: %v", err)
	}
	body := methodBody(t, string(source), "func (s *OIDCStore) GetDeviceAuthorizatonState(")

	assign := strings.Index(body, "d.lastPoll = s.now()")
	// The full return, not the bare error name: the method's prose names
	// context.DeadlineExceeded before the branch that returns it.
	refuse := strings.Index(body, "return nil, context.DeadlineExceeded")
	if assign < 0 || refuse < 0 {
		t.Fatalf("the memory store's poll no longer moves lastPoll or no longer refuses (%d, %d): "+
			"re-derive this guard", assign, refuse)
	}
	if assign > refuse {
		t.Error("the memory store returns slow_down before moving lastPoll: the anchor would be the last " +
			"admitted poll again, and the two engines would answer the same 3s client differently (G-15)")
	}
}

// sqlStatement returns the backtick-delimited SQL statement that begins with
// prefix, so a guard can inspect the whole statement text without the Go prose
// around it.
func sqlStatement(t *testing.T, body, prefix string) string {
	t.Helper()
	i := strings.Index(body, prefix)
	if i < 0 {
		t.Fatalf("statement %q not found; the guard is not reading the shipped SQL", prefix)
	}
	stmt := body[i:]
	if j := strings.Index(stmt, "`"); j >= 0 {
		stmt = stmt[:j]
	}
	if strings.TrimSpace(stmt) == "" {
		t.Fatalf("statement %q extracted as empty text", prefix)
	}
	return stmt
}

// collapse folds a statement's whitespace onto one line so a failure message
// can quote it.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
