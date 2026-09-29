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
}

func (l *switchableAudit) Record(_ context.Context, e audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
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
func (l *switchableAudit) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
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

// Z19-3 — every FAILURE path in vault.Service.Use swallows its audit write
// (`_ = s.record(...)`, vault/service.go:247, :269, :278, :288) while the success
// path is fail-closed (I3, :298-303). The most consequential of the four is the
// key-unavailable branch: "this record was wrapped by a key this deployment no
// longer has" is precisely the signal an operator needs after retiring a KEK, and
// it is the one `-rotate-keys` exists to prevent.
//
// This is a supplement to round 6's 03-2 (G-19 family: `Rotate`'s audit write is
// dropped with `_ =`). That finding named Rotate; the same discipline gap exists
// at four more sites in the same package, on the hot path rather than an
// operational command.
//
// The control is the same sink on the success path: it does fail closed there,
// which is what makes the asymmetry a defect rather than a design.
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
	// ErrNotFound; the denial is lost.
	auditLog.reset()
	auditLog.setDown(true)
	errMissing := svc.Use(ctx, vault.Identity{Subject: "usr_never", Provider: "taptap"}, func([]byte) error { return nil })
	if !errors.Is(errMissing, vault.ErrNotFound) {
		t.Fatalf("the missing-credential path returned %v, want ErrNotFound", errMissing)
	}
	if got := auditLog.actions(); len(got) != 0 {
		t.Fatalf("the probe is not measuring the failure path: the sink recorded %v", got)
	}
	t.Logf("CONFIRMED: vault.Use on a missing credential returned %v and recorded nothing "+
		"(the same sink refuses the success path)", errMissing)

	// Subject B: a record whose KEK is not configured — the post-rotation signal.
	if err := repo.Put(ctx, vault.Record{
		Identity:   vault.Identity{Subject: "usr_orphan", Provider: "taptap"},
		Version:    1,
		WrappedDEK: bytes.Repeat([]byte{0x01}, 40),
		KEKID:      "kek-that-was-deleted",
	}); err != nil {
		t.Fatal(err)
	}
	errOrphan := svc.Use(ctx, vault.Identity{Subject: "usr_orphan", Provider: "taptap"}, func([]byte) error { return nil })
	if errOrphan == nil || !strings.Contains(errOrphan.Error(), "not configured") {
		t.Fatalf("the orphaned-credential path returned %v, want the key-unavailable error", errOrphan)
	}
	if got := auditLog.actions(); len(got) != 0 {
		t.Fatalf("the probe is not measuring the failure path: the sink recorded %v", got)
	}
	t.Errorf("DISCLOSURE: vault.Use detected a credential wrapped by an unconfigured key, returned "+
		"%v, and dropped its `vault.use/error` audit event because the write failed and the error "+
		"was discarded (`_ = s.record`, vault/service.go:269). The success path on the same sink is "+
		"fail-closed, so this is an asymmetry rather than a policy: the record an operator must see "+
		"after a botched KEK retirement is the one that disappears during an audit outage.", errOrphan)
}
