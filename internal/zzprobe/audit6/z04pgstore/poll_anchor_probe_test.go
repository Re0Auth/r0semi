//go:build audit6

package z04pgstore

// The device poll throttle's anchoring, after G-15's Direction A adjudication.
//
// RFC 8628 §3.5 tells a client polling faster than the advertised interval to
// slow_down, but it does not name the instant the interval is measured from.
// The two engines used to disagree:
//
//   - memory (internal/store/memory/oidc.go, GetDeviceAuthorizatonState): a
//     throttled poll still writes `d.lastPoll = s.now()`, so the window runs
//     from the client's LAST ATTEMPT.
//   - postgres (the same method in internal/store/postgres/oidc.go): the claim
//     UPDATE's predicate `last_poll <= $4` failed on a premature attempt and
//     wrote nothing, so the window ran from the last ADMITTED poll.
//
// G-15 adjudicated Direction A: both engines anchor at the last ATTEMPT, which
// is the anchor the memory store always had. The postgres claim now moves
// last_poll unconditionally, in one transaction that locks the row and reads
// the OLD value, and judges admission against that old value — a bare
// `UPDATE … RETURNING last_poll` cannot express it, because RETURNING reports
// the NEW row. This file guards that adjudication:
//
//   - TestThePollThrottleAnchorsTheSamePollInBothEngines runs one sequence
//     (the advertised 5s interval, a poll every 3s) through the executable
//     memory engine and through the postgres claim's logic read off the shipped
//     statement, and fails if the two answers differ.
//   - TestAPollAFullIntervalAfterTheLastAttemptIsAdmittedInBothEngines is the
//     positive control: quiet for a full interval → admitted, on both engines.
//   - TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits pins the shipped
//     postgres statement shape the equivalence above models. Its name is kept
//     from the pre-adjudication probe because docs/audit-6 and docs/audit-7
//     reference it by name; the assertion under it is the ratified one, and its
//     old meaning ("only moves last_poll when it admits") is exactly what
//     Direction A reversed.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// probeInterval is the interval both engines advertise to a client.
var probeInterval = oidcstore.DefaultDevicePollInterval

// TestThePollThrottleAnchorsTheSamePollInBothEngines is the dual-engine
// consistency guard. The sequence is a client polling every 3s against the 5s
// interval: under Direction A only its first poll is admitted, because every
// attempt is 3s after the previous attempt; under the old postgres anchor the
// polls at 6s and 12s — a full interval after the last ADMISSION at 0s — would
// have been admitted. Both engines must answer the same way.
func TestThePollThrottleAnchorsTheSamePollInBothEngines(t *testing.T) {
	offsets := []time.Duration{0, 3 * time.Second, 6 * time.Second, 9 * time.Second, 12 * time.Second}
	want := []bool{true, false, false, false, false}

	memory := memoryPollVerdicts(t, offsets)
	postgres := postgresPollVerdicts(t, offsets)
	t.Logf("memory   (executed)        verdicts at %v: %v", offsets, memory)
	t.Logf("postgres (shipped-claim)   verdicts at %v: %v", offsets, postgres)

	for i, off := range offsets {
		if memory[i] != want[i] {
			t.Errorf("memory: a poll %s after the start was admitted=%v, want %v — the throttle is not "+
				"anchored at the last attempt", off, memory[i], want[i])
		}
		if postgres[i] != want[i] {
			t.Errorf("postgres (equivalent of the shipped claim): a poll %s after the start was "+
				"admitted=%v, want %v — the claim no longer anchors at the last attempt", off, postgres[i], want[i])
		}
		if memory[i] != postgres[i] {
			t.Errorf("the engines disagree at %s: memory admitted=%v, postgres admitted=%v. G-15's "+
				"Direction A is broken on one side; the whole point of the adjudication is that the same "+
				"3s client gets the same answer from both stores", off, memory[i], postgres[i])
		}
	}
}

// TestAPollAFullIntervalAfterTheLastAttemptIsAdmittedInBothEngines is the
// positive control for the guard above: the throttle is a floor, not a ban. A
// client that goes quiet for a full interval after its last attempt — including
// the rejected 3s attempt — is admitted again, on both engines.
func TestAPollAFullIntervalAfterTheLastAttemptIsAdmittedInBothEngines(t *testing.T) {
	// t=3s is refused (and becomes the anchor); t=8s is exactly one interval
	// after that attempt, so it is admitted; t=12s is only 4s after it, so it is
	// refused again.
	offsets := []time.Duration{0, 3 * time.Second, 8 * time.Second, 12 * time.Second}
	want := []bool{true, false, true, false}

	memory := memoryPollVerdicts(t, offsets)
	postgres := postgresPollVerdicts(t, offsets)
	t.Logf("memory   (executed)        verdicts at %v: %v", offsets, memory)
	t.Logf("postgres (shipped-claim)   verdicts at %v: %v", offsets, postgres)

	for i, off := range offsets {
		if memory[i] != want[i] {
			t.Errorf("memory: poll %s admitted=%v, want %v — a full interval of quiet after the last "+
				"attempt must be admitted", off, memory[i], want[i])
		}
		if postgres[i] != want[i] {
			t.Errorf("postgres (equivalent of the shipped claim): poll %s admitted=%v, want %v", off, postgres[i], want[i])
		}
	}
}

// TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits pins the shipped shape
// the equivalence above models, together with the memory source it must agree
// with. Read the name as historical: the claim used to move last_poll only when
// it admitted, and that is the behaviour G-15 removed.
func TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits(t *testing.T) {
	_, anchoredAtTheAttempt := assertPostgresClaimAnchorsAtTheAttempt(t)
	if !anchoredAtTheAttempt {
		return // the shape assertion above already reported it
	}

	// The memory companion: the throttled branch assigns d.lastPoll before it
	// returns slow_down, which is what "anchored at the last attempt" means in
	// code. The runtime half of this comparison is the guard above.
	mem := stripGoComments(readShipped(t, memoryDir+"/oidc.go"))
	memBody := methodBodyOf(t, mem, "GetDeviceAuthorizatonState")
	assign := strings.Index(memBody, "d.lastPoll = s.now()")
	// The full return, not the bare error name: the method's prose names
	// context.DeadlineExceeded before the branch that returns it.
	refuse := strings.Index(memBody, "return nil, context.DeadlineExceeded")
	if assign < 0 || refuse < 0 {
		t.Fatalf("the memory store's poll no longer moves lastPoll or no longer refuses (%d, %d): "+
			"re-derive this guard", assign, refuse)
	}
	if assign > refuse {
		t.Error("the memory store returns slow_down before moving lastPoll: it would anchor at the last " +
			"admitted poll again, and the postgres claim this test pins would be the only engine still on " +
			"Direction A")
	}
}

// assertPostgresClaimAnchorsAtTheAttempt checks that the shipped poll claim
// moves last_poll on every pending poll and judges admission against the OLD
// value it read under a row lock. It returns the claim statement text and
// whether the shipped shape anchors at the attempt, which the source-driven
// model in postgresPollVerdicts consumes: on the pre-adjudication shape the
// assertions below fail AND the model reproduces the last-admitted anchor, so
// the verdict comparison fails with them instead of merely restating a fixed
// assumption.
func assertPostgresClaimAnchorsAtTheAttempt(t *testing.T) (string, bool) {
	t.Helper()
	code := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))
	body := methodBodyOf(t, code, "GetDeviceAuthorizatonState")

	start := strings.Index(body, "UPDATE oidc_devices")
	if start < 0 {
		t.Fatal("the poll claim UPDATE was not found; the probe is not reading the statement")
	}
	claim := body[start:]
	if i := strings.Index(claim, "`"); i >= 0 {
		claim = claim[:i]
	}
	if !strings.Contains(claim, "SET last_poll = $3") {
		t.Fatalf("the poll claim no longer writes last_poll: %q", strings.Join(strings.Fields(claim), " "))
	}
	// Direction A: a throttled attempt moves the anchor too, so the claim must
	// not gate its own write on last_poll. Either predicate is the old
	// last-admitted anchor reintroduced.
	gatesOnLastPoll := strings.Contains(claim, "last_poll <=") || strings.Contains(claim, "last_poll IS NULL")
	if gatesOnLastPoll {
		t.Error("the postgres poll claim predicates its own write on last_poll again: a premature " +
			"attempt writes nothing, so the interval is anchored at the last ADMITTED poll and the two " +
			"engines answer the same 3s client differently (G-15, Direction A). The write must be " +
			"unconditional; the window decides only whether the poll is admitted")
	}
	// The old value must be read under a row lock, or two concurrent polls can
	// read the same pre-winner anchor and both admit themselves (TOCTOU).
	locked := regexp.MustCompile(`(?s)SELECT last_poll FROM oidc_devices.*?FOR UPDATE`).MatchString(body)
	if !locked {
		t.Error("the poll claim does not read the old last_poll under `FOR UPDATE`: the admission " +
			"decision needs the value the row held BEFORE this statement, and the row lock is what " +
			"serializes concurrent polls against each other")
	}
	if !strings.Contains(body, "previous.After(staleBefore)") {
		t.Error("the poll claim does not judge admission against the OLD anchor read under the lock " +
			"(s.now() - DefaultDevicePollInterval); the only value that answers \"did a full interval " +
			"pass since the last attempt\" is the one read before the write")
	}
	return claim, !gatesOnLastPoll && locked
}

// memoryPollVerdicts polls one fresh memory device at each offset from the
// store's start clock and reports whether the poll was admitted. A refused poll
// must be context.DeadlineExceeded (the library's slow_down); anything else is a
// failure of the premise.
func memoryPollVerdicts(t *testing.T, offsets []time.Duration) []bool {
	t.Helper()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := &fakeDeviceClock{now: start}
	store := memoryOIDCOn(t, clock)
	ctx := context.Background()

	const (
		clientID   = "probe-device"
		deviceCode = "probe-anchor-code"
		userCode   = "JKLM-NPQR"
	)
	if err := store.StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode,
		start.Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatalf("store device authorization: %v", err)
	}

	verdicts := make([]bool, 0, len(offsets))
	for _, off := range offsets {
		clock.now = start.Add(off)
		_, err := store.GetDeviceAuthorizatonState(ctx, clientID, deviceCode)
		switch {
		case err == nil:
			verdicts = append(verdicts, true)
		case errors.Is(err, context.DeadlineExceeded):
			verdicts = append(verdicts, false)
		default:
			t.Fatalf("the poll at %s returned an unexpected error: %v", off, err)
		}
	}
	return verdicts
}

// postgresPollVerdicts is the DB-free equivalent of the shipped postgres claim
// for one device: the poll is admitted only when the OLD anchor is at least one
// interval behind, and whether a refused attempt still moves the anchor is read
// off the shipped statement (asserted above) rather than assumed. On the
// pre-adjudication shape — the write gated on last_poll, no row lock — the model
// reproduces the last-admitted anchor, so the sequence verdicts diverge from
// memory's exactly as the finding described.
func postgresPollVerdicts(t *testing.T, offsets []time.Duration) []bool {
	t.Helper()
	_, anchoredAtTheAttempt := assertPostgresClaimAnchorsAtTheAttempt(t)

	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var previous *time.Time
	verdicts := make([]bool, 0, len(offsets))
	for _, off := range offsets {
		now := start.Add(off)
		staleBefore := now.Add(-probeInterval)
		// A NULL anchor is the first poll; otherwise a full interval must have
		// passed since the last ATTEMPT.
		admitted := previous == nil || !previous.After(staleBefore)
		verdicts = append(verdicts, admitted)
		if admitted || anchoredAtTheAttempt {
			anchor := now // Direction A: every attempt moves last_poll
			previous = &anchor
		}
	}
	return verdicts
}
