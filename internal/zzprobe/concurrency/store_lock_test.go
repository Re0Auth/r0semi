//go:build audit5

package concurrency

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// --- S13-4 regression guards: the store's single lock is NOT held across the
// audit write ---
//
// Originally this block was a discovery pair: memory.OIDCStore.ApproveDevice /
// DenyDevice used to call s.record(...) inside the critical section (the
// `defer s.mu.Unlock()` had not run yet), while every other auditing method in
// the same file minted its record after releasing the lock. audit.Logger.Record
// is synchronous by contract ("returning nil means safe to proceed") and in a
// durable deployment it is a Postgres batch append that takes the chain-head row
// lock — i.e. network I/O plus a database lock — so a device decision stalled
// every other request against the store.
//
// The fix (S13-4) moved both audit writes outside the critical section. These
// probes are now regression guards for that fix: the control proves the probe can
// tell "held" from "not held", and the two device probes assert the safe property
// — that the lock is released before the audit sink runs. Remove the fix and the
// flipped assertions below fail again.

func newStoreWithBlockingAudit(t *testing.T) (*memory.OIDCStore, *blockingAudit) {
	t.Helper()
	log := newBlockingAudit()
	return newProbeStore(t, log), log
}

// Control: minting an access token audits *after* the lock is released, so the
// store answers Counts() while its audit write is in flight. If this ever fails,
// the probe below is measuring nothing.
func TestControlTokenMintAuditsOutsideTheStoreLock(t *testing.T) {
	st, log := newStoreWithBlockingAudit(t)
	op := func() error {
		_, _, err := st.CreateAccessToken(context.Background(), tokenRequest("usr_1", "account.id"))
		return err
	}
	if held := lockHeldDuring(t, st, log, op); held {
		t.Error("CreateAccessToken holds the store lock across its audit write; the probe cannot distinguish the cases below")
	}
}

// Guard (was the finding): approving a device authorization must release the
// store's only lock before the audit write runs. Every other request against this
// store — every authorize, every token exchange, every introspection, every grant
// list, the janitor's sweep — must not wait behind an audit append.
func TestApproveDeviceHoldsTheStoreLockAcrossTheAuditWrite(t *testing.T) {
	st, log := newStoreWithBlockingAudit(t)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-1", "AAAA-BBBB",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	op := func() error { return st.ApproveDevice(ctx, "AAAA-BBBB", "usr_1", nil) }
	if held := lockHeldDuring(t, st, log, op); held {
		t.Error("ApproveDevice held the store lock while the audit write was in flight: S13-4 regressed, " +
			"so every other call on this store waits behind a (possibly remote) audit append")
	}
}

// Guard (was the finding): the same for a denial.
func TestDenyDeviceHoldsTheStoreLockAcrossTheAuditWrite(t *testing.T) {
	st, log := newStoreWithBlockingAudit(t)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-2", "CCCC-DDDD",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	op := func() error { return st.DenyDevice(ctx, "CCCC-DDDD") }
	if held := lockHeldDuring(t, st, log, op); held {
		t.Error("DenyDevice held the store lock while the audit write was in flight: S13-4 regressed")
	}
}

// guardAudit is an audit.Logger that asks the store a question — the shape of any
// sink that resolves the subject it is recording. It is a plausible wiring, and it
// is what turns "a lock held across a callback" into a deadlock rather than just a
// stall: the callback needs the lock its caller is holding.
type guardAudit struct {
	st       *memory.OIDCStore
	answered chan bool
}

func (g *guardAudit) Record(context.Context, audit.Event) error {
	done := make(chan struct{})
	go func() {
		_ = g.st.Counts()
		close(done)
	}()
	select {
	case <-done:
		g.answered <- true
	case <-time.After(2 * time.Second):
		g.answered <- false
	}
	return nil
}

// Guard (was the deadlock demonstration). An audit sink that reads the store is
// the shape that turns "a lock held across a callback" into a deadlock: the
// callback needs the lock its caller was holding. Before S13-4 this probe proved
// the callback could not complete. After the fix the audit write runs outside the
// critical section, so the same callback completes — the assertion is inverted to
// guard that ordering.
func TestAnAuditSinkThatReadsTheStoreDeadlocksUnderTheLock(t *testing.T) {
	g := &guardAudit{answered: make(chan bool, 1)}
	audited, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  newProbeClients(t),
		Registry: oauth.DefaultRegistry(),
		Signer:   probeSigner(t),
		Audit:    g,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.st = audited
	ctx := context.Background()
	if err := audited.StoreDeviceAuthorization(ctx, probeClientID, "device-code-3", "EEEE-FFFF",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := audited.ApproveDevice(ctx, "EEEE-FFFF", "usr_1", nil); err != nil {
		t.Fatal(err)
	}
	if !<-g.answered {
		t.Error("an audit write that reads the store did NOT complete: the store lock is held across the " +
			"audit callback again (S13-4 regressed), so a sink that resolves its subject deadlocks")
	}
}

// --- CM-2: every audit path forwards the request context ---

type ctxMarker struct{}

// CreateAccessToken and the two device-decision methods used to pass
// context.Background() to the audit sink while CreateAccessAndRefreshTokens passed
// the caller's context, so those three records lost the request's values, deadline
// and cancellation. All four forward it now. The refresh path is the control: a
// probe that stopped reaching the sink fails on it rather than passing vacuously.
func TestEveryAuditPathForwardsTheRequestContext(t *testing.T) {
	log := &recordingAudit{}
	st := newProbeStore(t, log)
	ctx := context.WithValue(context.Background(), ctxMarker{}, "marker")
	ctx, cancel := context.WithCancel(ctx)
	cancel() // the caller is already gone

	assertForwarded := func(t *testing.T, what string) {
		t.Helper()
		got := log.last()
		if got == nil || log.count() == 0 {
			t.Fatalf("%s recorded nothing; the probe is not reaching the audit sink", what)
		}
		if got.Value(ctxMarker{}) != "marker" || !errors.Is(got.Err(), context.Canceled) {
			t.Errorf("%s did not forward the request context: value=%v err=%v",
				what, got.Value(ctxMarker{}), got.Err())
		}
	}

	if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_1", "account.id"), ""); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, "CreateAccessAndRefreshTokens (control)")

	if _, _, err := st.CreateAccessToken(ctx, tokenRequest("usr_1", "account.id")); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, "CreateAccessToken")

	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-4", "GGGG-HHHH",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveDevice(ctx, "GGGG-HHHH", "usr_1", nil); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, "ApproveDevice")

	if err := st.DenyDevice(ctx, "GGGG-HHHH"); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, "DenyDevice")
}
