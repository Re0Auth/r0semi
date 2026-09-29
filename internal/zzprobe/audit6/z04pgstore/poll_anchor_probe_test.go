//go:build audit6

package z04pgstore

// The device poll throttle's anchoring, after bf81b2a.
//
// bf81b2a (P2-32) moved the device path's three clock decisions to the store
// clock, closing the "two clocks judge one deadline" divergence. What it did
// not close is WHERE the slow_down interval is anchored:
//
//   - memory (internal/store/memory/oidc.go, GetDeviceAuthorizatonState): a
//     throttled poll still writes `d.lastPoll = s.now()`, so the window runs
//     from the client's LAST ATTEMPT — a client polling every 3s against a 5s
//     interval is never admitted again until it pauses.
//   - postgres (oidc.go, the same method): the claim UPDATE's predicate
//     `last_poll <= $4 - make_interval(...)` fails on a premature attempt and
//     the UPDATE writes nothing, so the window runs from the last ADMITTED
//     poll — the same 3s client is admitted once per interval.
//
// Both are "at least the interval" in the RFC 8628 §3.5 sense, so neither is a
// security hole on its own; the finding is that the two engines answer the
// same client differently, which is the exact class P2-32 was filed to close
// ("两个后端对同一问题给出不同答案"). The memory half is executable with an
// injected clock; the postgres half is asserted on the shipped SQL.

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestThePollThrottleAnchorsTheSamePollInBothEngines runs the memory half and
// then checks the postgres half's SQL, and fails while the two disagree.
func TestThePollThrottleAnchorsTheSamePollInBothEngines(t *testing.T) {
	anchor := lastAttemptAnchoringOfMemory(t)
	t.Logf("memory: the throttle window is anchored at the client's %s", anchor)

	if anchor != "last admitted poll" {
		t.Errorf("the two engines anchor the RFC 8628 §3.5 interval differently: memory anchors it at the "+
			"client's %s, postgres's claim UPDATE anchors it at the last admitted poll (a failed predicate "+
			"writes nothing). A client polling every 3s against a 5s interval is never admitted on memory "+
			"and admitted once per interval on postgres — the same client, the same question, different "+
			"answers, which is the divergence class P2-32 was filed to close", anchor)
	}
}

// lastAttemptAnchoringOfMemory demonstrates, with a settable clock, which poll
// the memory store anchors the interval at. It returns the finding as prose so
// the test above can report it in one place.
func lastAttemptAnchoringOfMemory(t *testing.T) string {
	t.Helper()
	clock := &fakeDeviceClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	store := memoryOIDCOn(t, clock)
	ctx := context.Background()

	const (
		clientID   = "probe-device"
		deviceCode = "probe-anchor-code"
		userCode   = "JKLM-NPQR"
	)
	if err := store.StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode,
		clock.now.Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatalf("store device authorization: %v", err)
	}

	// t=0: admitted (pending).
	if _, err := store.GetDeviceAuthorizatonState(ctx, clientID, deviceCode); err != nil {
		t.Fatalf("first poll was refused: %v", err)
	}
	// t=3s: inside the 5s interval, so throttled — and, on memory, this
	// attempt is what the next window is measured from.
	clock.now = clock.now.Add(3 * time.Second)
	if _, err := store.GetDeviceAuthorizatonState(ctx, clientID, deviceCode); err == nil {
		t.Fatal("a poll 3s after the admitted one was not throttled; the interval is not 5s and the " +
			"probe's premise about the advertised interval is wrong")
	}

	// t=7.5s: 7.5s after the ADMITTED poll but only 4.5s after the throttled
	// ATTEMPT. Which of the two the store admits is the whole question.
	clock.now = clock.now.Add(4500 * time.Millisecond)
	_, err := store.GetDeviceAuthorizatonState(ctx, clientID, deviceCode)
	switch {
	case err == nil:
		// Admitted: the window ran from the admitted poll (t=0), like postgres.
		return "last admitted poll"
	case err == context.DeadlineExceeded:
		// Throttled: the window ran from the attempt (t=3s).
		return "last attempted poll"
	default:
		t.Fatalf("the discriminating poll returned an unexpected error: %v", err)
	}
	return ""
}

// TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits is the SQL half: the
// memory store's throttled path writes last_poll (that is what the runtime
// probe above observes), while the postgres claim UPDATE can only write it when
// the predicate already holds. The check is on the shipped statement text.
func TestThePostgresPollClaimOnlyMovesLastPollWhenItAdmits(t *testing.T) {
	code := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))
	consume := methodBodyOf(t, code, "GetDeviceAuthorizatonState")

	claim := regexp.MustCompile("UPDATE oidc_devices[^`]*").FindString(consume)
	if claim == "" {
		t.Fatal("the poll claim UPDATE was not found; the probe is not reading the statement")
	}
	// The claim is one statement: the SET and the interval predicate sit in the
	// same WHERE-guarded UPDATE, so last_poll can only move when the predicate
	// (last_poll <= $4 - make_interval(...)) already holds.
	if !strings.Contains(claim, "last_poll <=") {
		t.Fatal("the claim no longer predicates on last_poll; the probe's premise is stale — re-read the adapter")
	}

	// The memory side, for the comparison this test pins: the throttled branch
	// assigns d.lastPoll before returning slow_down.
	mem := stripGoComments(readShipped(t, memoryDir+"/oidc.go"))
	memBody := methodBodyOf(t, mem, "GetDeviceAuthorizatonState")
	throttle := regexp.MustCompile(`(?s)context\.DeadlineExceeded`).FindString(memBody)
	if throttle == "" {
		t.Fatal("the memory store no longer has a slow_down branch; the comparison is stale")
	}
	// The assignment `d.lastPoll = s.now()` must sit BEFORE the DeadlineExceeded
	// return for memory to anchor at the attempt.
	assign := regexp.MustCompile(`d\.lastPoll\s*=\s*s\.now\(\)`).FindAllStringIndex(memBody, -1)
	found := false
	for _, a := range assign {
		if de := strings.Index(memBody[a[1]:], "DeadlineExceeded"); de >= 0 && de < 300 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("memory no longer advances last_poll on the throttled path; the divergence this probe " +
			"reports may have been fixed on one side — re-run the runtime half")
	}
}
