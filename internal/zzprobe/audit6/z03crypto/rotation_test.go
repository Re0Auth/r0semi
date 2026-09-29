//go:build audit6

// Rotation probes: the regression guards for the round-5 P1-1 / P1-2 fix
// (narrow CAS write, Skipped accounting, the re-run gate), plus the one red
// probe for the audit write that fix left discarded.
package z03crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// hookRepo fires one callback inside the rotation's compare-and-swap window,
// before the envelope write is attempted — the interleaving a live server
// produces when a credential is enrolled while a rotation page is in flight.
type hookRepo struct {
	*vault.MemoryRepo
	hook func()
}

func (h *hookRepo) RewrapIfUnchanged(ctx context.Context, id vault.Identity, expect []byte, next vault.Envelope) (bool, error) {
	if h.hook != nil {
		fn := h.hook
		h.hook = nil
		fn()
	}
	return h.MemoryRepo.RewrapIfUnchanged(ctx, id, expect, next)
}

// TestProbeRotationCASSurvivesAConcurrentEnroll is the round-6 regression
// guard for P1-2: a credential enrolled while a rotation page is in flight must
// survive, the run must report it as Skipped rather than Rewrapped, and a re-run
// must reach the "rewrapped=0 skipped=0" gate the operator is told to demand.
func TestProbeRotationCASSurvivesAConcurrentEnroll(t *testing.T) {
	ctx := context.Background()
	repo := &hookRepo{MemoryRepo: vault.NewMemoryRepo()}
	logger := audit.NewMemoryLogger()
	old := mustWrapper(t, "kek-1", 0xA1)
	fresh := mustWrapper(t, "kek-2", 0xB2)
	id := vault.Identity{Subject: "usr_race", Provider: "taptap"}

	oldPod := mustService(t, repo, old, logger)
	if err := oldPod.Enroll(ctx, id, []byte("first-secret"), nil); err != nil {
		t.Fatal(err)
	}

	// The "new pod" still serving with the new key as current: what writes a
	// credential while the rotation is between its read and its CAS.
	newPod := mustService(t, repo, fresh, logger)

	rotator := mustService(t, repo, fresh, logger, vault.WithRetiredKeys(old))
	repo.hook = func() {
		if err := newPod.Enroll(ctx, id, []byte("second-secret"), nil); err != nil {
			t.Errorf("concurrent enroll during the rotation window: %v", err)
		}
	}

	rotation, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Rewrapped != 0 || rotation.Skipped != 1 || rotation.Scanned != 1 {
		t.Fatalf("rotation = %+v; the concurrent enroll must be Skipped, not rolled back or silently counted", rotation)
	}

	// The concurrently enrolled credential survived the rotation intact.
	got, err := useSecret(t, newPod, id)
	if err != nil || got != "second-secret" {
		t.Fatalf("after the rotation the credential reads %q, %v; want second-secret (P1-2 regression)", got, err)
	}

	// The gate: re-running must now find nothing to do.
	again, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Scanned != 1 || again.Rewrapped != 0 || again.Skipped != 0 || again.AlreadyCurrent != 1 {
		t.Fatalf("second rotation = %+v; want rewrapped=0 skipped=0 (the documented gate)", again)
	}
}

// TestProbeRotationRewritesOnlyTheEnvelope is the round-6 regression guard for
// the narrow write: a re-wrap changes wrapped_dek/kek_id/updated_at and
// nothing else.
func TestProbeRotationRewritesOnlyTheEnvelope(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := mustWrapper(t, "kek-1", 0xA1)
	fresh := mustWrapper(t, "kek-2", 0xB2)
	id := vault.Identity{Subject: "usr_env", Provider: "taptap"}

	before := mustService(t, repo, old, logger)
	if err := before.Enroll(ctx, id, []byte("payload"), map[string]string{"game": "phigros"}); err != nil {
		t.Fatal(err)
	}
	original, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	rotator := mustService(t, repo, fresh, logger, vault.WithRetiredKeys(old))
	rotation, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Rewrapped != 1 {
		t.Fatalf("rotation = %+v", rotation)
	}

	after, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(after.Nonce) != string(original.Nonce) || string(after.Ciphertext) != string(original.Ciphertext) {
		t.Error("the rotation touched the payload ciphertext or nonce")
	}
	if after.KEKID != fresh.KeyID() {
		t.Errorf("kek_id = %q after rotation", after.KEKID)
	}
	if string(after.WrappedDEK) == string(original.WrappedDEK) {
		t.Error("the wrapped DEK is unchanged, so nothing was re-wrapped")
	}
	if after.Meta["game"] != "phigros" {
		t.Errorf("meta = %v after rotation", after.Meta)
	}
	// Windows clock granularity can make two time.Now() reads in one test
	// agree; what must never happen is the timestamp going backwards.
	if after.UpdatedAt.Before(original.UpdatedAt) {
		t.Error("updated_at went backwards across the re-wrap")
	}
}

// TestProbeRotationAuditFailureIsSwallowed is the red probe for the finding:
// Rotate discards the failure of its own audit write (`_ = s.record(...)` in
// vault/rotate.go), while the comment the P1-1 fix added says that trail "is
// what an operator consults before deleting the retired key", and while
// Enroll/Use/Revoke all fail closed on the same sink. A rotation whose audit
// write failed must not report success.
func TestProbeRotationAuditFailureIsSwallowed(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := mustWrapper(t, "kek-1", 0xA1)
	fresh := mustWrapper(t, "kek-2", 0xB2)
	id := vault.Identity{Subject: "usr_aud", Provider: "taptap"}

	seeder := mustService(t, repo, old, logger)
	if err := seeder.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	rotator := mustService(t, repo, fresh, failingLogger{err: errors.New("probe: audit sink unreachable")},
		vault.WithRetiredKeys(old))
	rotation, err := rotator.Rotate(ctx)

	if err == nil {
		t.Fatalf("a rotation whose audit write failed reported success: %+v; "+
			"the same sink makes Enroll/Use/Revoke fail closed, and the rotate_keys "+
			"trail is what an operator consults before deleting the retired key", rotation)
	}
	// Had the write failure been surfaced, the run still happened; assert the
	// counts are what the caller needs to judge a re-run.
	if rotation.Rewrapped != 1 {
		t.Fatalf("rotation = %+v", rotation)
	}
}
