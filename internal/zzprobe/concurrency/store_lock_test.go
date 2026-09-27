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

// --- Finding CM-1: the store's single lock is held across the audit write ---
//
// memory.OIDCStore.ApproveDevice / DenyDevice call s.record(...) inside the
// critical section (the `defer s.mu.Unlock()` has not run yet), while every other
// auditing method in the same file mints its record after releasing the lock.
// audit.Logger.Record is synchronous by contract ("returning nil means safe to
// proceed") and in a durable deployment it is a Postgres batch append that takes
// the chain-head row lock — i.e. network I/O plus a database lock.
//
// These two tests are a matched pair: the control proves the probe can tell
// "held" from "not held", and the finding asserts the safe property, which
// currently fails.

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

// Finding: approving a device authorization holds the store's only lock across
// the audit write. Every other request against this store — every authorize, every
// token exchange, every introspection, every grant list, the janitor's sweep —
// waits behind an audit append.
func TestApproveDeviceHoldsTheStoreLockAcrossTheAuditWrite(t *testing.T) {
	st, log := newStoreWithBlockingAudit(t)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-1", "AAAA-BBBB",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	op := func() error { return st.ApproveDevice(ctx, "AAAA-BBBB", "usr_1", nil) }
	if held := lockHeldDuring(t, st, log, op); !held {
		t.Error("ApproveDevice did not hold the store lock while the audit write was in flight")
	}
}

// Finding: the same for a denial.
func TestDenyDeviceHoldsTheStoreLockAcrossTheAuditWrite(t *testing.T) {
	st, log := newStoreWithBlockingAudit(t)
	ctx := context.Background()
	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-2", "CCCC-DDDD",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	op := func() error { return st.DenyDevice(ctx, "CCCC-DDDD") }
	if held := lockHeldDuring(t, st, log, op); !held {
		t.Error("DenyDevice did not hold the store lock while the audit write was in flight")
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

// A callback under the store's lock cannot complete. This is the mechanism, not a
// claim about the current wiring: today's durable sink does not call back into the
// store, but the lock order it establishes (store lock -> audit lock) is the one
// the vault path already documents as a hazard ("audit -> vault query -> audit").
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
	if <-g.answered {
		t.Error("an audit write that reads the store completed while the lock was held; the probe measured nothing")
	}
}

// --- Finding CM-2: the request context is dropped on some audit paths ---

type ctxMarker struct{}

// CreateAccessToken and the two device-decision methods pass
// context.Background() to the audit sink, while CreateAccessAndRefreshTokens
// passes the caller's context. The control below (the refresh path) proves the
// probe sees a real context when one is forwarded, so the zero-value answer on the
// other paths is the store's choice and not the probe's.
func TestSomeAuditPathsDropTheRequestContext(t *testing.T) {
	log := &recordingAudit{}
	st := newProbeStore(t, log)
	ctx := context.WithValue(context.Background(), ctxMarker{}, "marker")
	ctx, cancel := context.WithCancel(ctx)
	cancel() // the caller is already gone

	// Control: the refresh path forwards the request's context, cancellation and
	// all.
	if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, tokenRequest("usr_1", "account.id"), ""); err != nil {
		t.Fatal(err)
	}
	control := log.last()
	if control == nil || log.count() == 0 {
		t.Fatal("the refresh path recorded nothing; the probe is not reaching the audit sink")
	}
	if control.Value(ctxMarker{}) != "marker" || !errors.Is(control.Err(), context.Canceled) {
		t.Fatalf("the refresh path did not forward the request context: value=%v err=%v",
			control.Value(ctxMarker{}), control.Err())
	}

	// Finding: these do not forward it — the record is written with a fresh
	// context.Background(), so the caller's cancellation and deadline are gone.
	// Each assertion below FAILS on the code as found.
	if _, _, err := st.CreateAccessToken(ctx, tokenRequest("usr_1", "account.id")); err != nil {
		t.Fatal(err)
	}
	if got := log.last(); got.Value(ctxMarker{}) != "marker" || !errors.Is(got.Err(), context.Canceled) {
		t.Errorf("CreateAccessToken did not forward the request context: value=%v err=%v",
			got.Value(ctxMarker{}), got.Err())
	}

	if err := st.StoreDeviceAuthorization(ctx, probeClientID, "device-code-4", "GGGG-HHHH",
		time.Now().Add(10*time.Minute), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveDevice(ctx, "GGGG-HHHH", "usr_1", nil); err != nil {
		t.Fatal(err)
	}
	if got := log.last(); got.Value(ctxMarker{}) != "marker" || !errors.Is(got.Err(), context.Canceled) {
		t.Errorf("ApproveDevice did not forward the request context: value=%v err=%v",
			got.Value(ctxMarker{}), got.Err())
	}
	if err := st.DenyDevice(ctx, "GGGG-HHHH"); err != nil {
		t.Fatal(err)
	}
	if got := log.last(); got.Value(ctxMarker{}) != "marker" || !errors.Is(got.Err(), context.Canceled) {
		t.Errorf("DenyDevice did not forward the request context: value=%v err=%v",
			got.Value(ctxMarker{}), got.Err())
	}
}
