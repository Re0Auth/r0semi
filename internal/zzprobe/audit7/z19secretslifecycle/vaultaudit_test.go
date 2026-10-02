//go:build audit7

package z19secretslifecycle

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// switchableAudit is an audit.Logger that counts what it was asked to record and
// can be made to fail, which is how an audit outage is modelled without a
// database.
type switchableAudit struct {
	mu     sync.Mutex
	events []audit.Event
	down   bool
	calls  int
}

func (l *switchableAudit) Record(_ context.Context, e audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.down {
		return errors.New("z19 probe: audit sink unreachable")
	}
	l.events = append(l.events, e)
	return nil
}

func (l *switchableAudit) setDown(down bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.down = down
}

// reset forgets what was recorded so far, so each phase measures only itself.
// The attempted-call counter is deliberately not reset: the phases below compare
// it before and after a call.
func (l *switchableAudit) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
}

// attempts is how many times vault asked the sink to record, whether or not the
// sink answered. It is the anti-vacuity control for the failure paths: a probe
// that asserts "the audit failure was surfaced" must first show the record call
// was actually attempted.
func (l *switchableAudit) attempts() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func (l *switchableAudit) actions() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.events))
	for _, e := range l.events {
		out = append(out, e.Action+"/"+e.Outcome)
	}
	return out
}

// Z19-3 — every FAILURE path in vault.Service.Use used to swallow its audit write
// (`_ = s.record(...)`, vault/service.go) while the success path is fail-closed
// (I3). The most consequential of the four is the key-unavailable branch: "this
// record was wrapped by a key this deployment no longer has" is precisely the
// signal an operator needs after retiring a KEK, and it is the one `-rotate-keys`
// exists to prevent.
//
// 【原为发现演示，现为回归守卫】It is FIXED: the four failure paths now
// `errors.Join(err, aerr)` (vault/service.go:313, :329-330, :339, :349), so the
// audit outage travels with the caller's error instead of being discarded, and
// the caller's own sentinel (`errors.Is(err, vault.ErrNotFound)`) survives the
// join — which is why the fix could not simply return the audit error.
// docs/issues/_fragments/round7.md:154 (Z19-3) stated the fix and that constraint.
//
// The probe now guards that contract. The success path is the control that the
// same sink fails closed when the audit write fails; the two failure paths below
// assert that the record call was still attempted (so the assertion is not
// vacuous), that the returned error still carries the caller's original meaning,
// and that the audit failure is visible in it.
func TestZ19VaultUseFailurePathsDropTheirAuditRecord(t *testing.T) {
	ctx := context.Background()
	auditLog := &switchableAudit{}
	repo := vault.NewMemoryRepo()
	wrapper, err := vault.NewLocalKeyWrapper("kek-1", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(repo, wrapper, auditLog)
	if err != nil {
		t.Fatal(err)
	}

	// Control 1: the success path is fail-closed. With the sink down, Use must
	// not hand the plaintext to the callback.
	if err := svc.Enroll(ctx, vault.Identity{Subject: "usr_z19", Provider: "taptap"}, []byte("upstream-token"), nil); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	auditLog.setDown(true)
	handed := false
	err = svc.Use(ctx, vault.Identity{Subject: "usr_z19", Provider: "taptap"}, func([]byte) error {
		handed = true
		return nil
	})
	if err == nil || handed {
		t.Fatalf("control failed: the success path did not fail closed (err=%v handed=%v)", err, handed)
	}
	if !strings.Contains(err.Error(), "vault: audit:") {
		t.Fatalf("control failed: the refusal was not the audit failure: %v", err)
	}
	t.Logf("control (success path, sink down): %v", err)

	// Control 2: with the sink up, a use on a missing credential records its
	// denial, so the probe is looking at a path that does write when it can.
	auditLog.setDown(false)
	_ = svc.Use(ctx, vault.Identity{Subject: "usr_missing", Provider: "taptap"}, func([]byte) error { return nil })
	if got := auditLog.actions(); len(got) == 0 || !strings.HasPrefix(got[len(got)-1], "vault.use/") {
		t.Fatalf("control failed: a missing credential wrote no vault.use event: %v", got)
	}

	// Subject A: a missing credential, sink down. The caller still gets
	// ErrNotFound AND the audit failure is surfaced, not dropped.
	auditLog.reset()
	auditLog.setDown(true)
	before := auditLog.attempts()
	errMissing := svc.Use(ctx, vault.Identity{Subject: "usr_never", Provider: "taptap"}, func([]byte) error { return nil })
	if !errors.Is(errMissing, vault.ErrNotFound) {
		t.Fatalf("the missing-credential path returned %v, want ErrNotFound: the errors.Join fix must keep "+
			"the caller's sentinel", errMissing)
	}
	if auditLog.attempts() == before {
		t.Fatalf("the missing-credential failure path never asked the sink to record, so the assertion " +
			"below would pass vacuously")
	}
	if !strings.Contains(errMissing.Error(), "audit") {
		t.Errorf("REGRESSION (Z19-3): vault.Use on a missing credential dropped its audit failure; the "+
			"returned error carries no trace of the sink: %v", errMissing)
	}
	t.Logf("missing credential, sink down: %v (ErrNotFound preserved, audit failure surfaced)", errMissing)

	// Subject B: a record whose KEK is not configured — the post-rotation signal.
	if err := repo.Put(ctx, vault.Record{
		Identity:   vault.Identity{Subject: "usr_orphan", Provider: "taptap"},
		Version:    1,
		WrappedDEK: bytes.Repeat([]byte{0x01}, 40),
		KEKID:      "kek-that-was-deleted",
	}); err != nil {
		t.Fatal(err)
	}
	before = auditLog.attempts()
	errOrphan := svc.Use(ctx, vault.Identity{Subject: "usr_orphan", Provider: "taptap"}, func([]byte) error { return nil })
	if errOrphan == nil || !strings.Contains(errOrphan.Error(), "not configured") {
		t.Fatalf("the orphaned-credential path returned %v, want the key-unavailable error", errOrphan)
	}
	if auditLog.attempts() == before {
		t.Fatalf("the key-unavailable failure path never asked the sink to record, so the assertion below " +
			"would pass vacuously")
	}
	if !strings.Contains(errOrphan.Error(), "audit") {
		t.Errorf("REGRESSION (Z19-3): vault.Use detected a credential wrapped by an unconfigured key and "+
			"dropped its `vault.use/error` audit failure — the record an operator must see after a botched "+
			"KEK retirement is invisible again: %v", errOrphan)
	}
	t.Logf("key unavailable, sink down: %v (the post-rotation signal now travels with the audit failure)",
		errOrphan)
}
