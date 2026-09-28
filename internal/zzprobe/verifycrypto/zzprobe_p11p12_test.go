//go:build audit5

package verifycrypto

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// The dedicated guard for P1-1 and P1-2, which are one change: a rotation must
// write only the envelope, only when the row is still the one it read, and it must
// say so when it could not.
//
// P1-2 — `rotate.go` wrote back the WHOLE record it had read (Nonce, Ciphertext,
// Meta, CreatedAt), and the Postgres adapter's `ON CONFLICT DO UPDATE` overwrites
// every column, so a credential enrolled between the page read and the write was
// silently rolled back while the command reported success.
//
// P1-1 — a write that lands on the retired KEK after the rotation cursor passed it
// stays there; removing the retired key then makes it permanently unreadable, and
// `-rotate-keys` printed `{Scanned:1 Rewrapped:1}` and exited 0. No run can see
// such a write (it happens in another process), so the fix is (a) never report a
// run as complete when it left work behind, and (b) tell the operator the gate they
// must pass before deleting the key.
//
// Part A drives the interleaving; part B walks the documented procedure to its
// conclusion; part C pins the report the command gives, including that an
// incomplete run is not rendered as a success.
func TestZZProbeRotationIsAtomicAndReportsWhatItDidNotDo(t *testing.T) {
	ctx := context.Background()
	id := vault.Identity{Subject: "usr_p11", Provider: "taptap"}
	other := vault.Identity{Subject: "usr_p11b", Provider: "taptap"}
	logger := audit.NewMemoryLogger()

	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	// --- A: the interleaving P1-2 is about ---------------------------------

	t.Run("A a concurrent enrol survives and is reported as skipped", func(t *testing.T) {
		repo := &hookRepo{inner: vault.NewMemoryRepo()}
		oldPod, err := vault.NewService(repo, old, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := oldPod.Enroll(ctx, id, []byte("first"), nil); err != nil {
			t.Fatal(err)
		}

		var raced bool
		repo.onRewrap = func() {
			if raced {
				return
			}
			raced = true
			if err := oldPod.Enroll(ctx, id, []byte("second"), nil); err != nil {
				t.Errorf("concurrent enroll: %v", err)
			}
		}
		rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
		if err != nil {
			t.Fatal(err)
		}
		rotation, err := rotator.Rotate(ctx)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if !raced {
			t.Fatal("the hook never fired: the rotation performed no re-wrap, so nothing below is measurable")
		}
		if rotation.Skipped != 1 {
			t.Errorf("rotation = %+v, want Skipped 1: the refused re-wrap is not reported", rotation)
		}
		if rotation.Scanned != rotation.Rewrapped+rotation.AlreadyCurrent+rotation.Skipped {
			t.Errorf("rotation = %+v: the counts do not add up to Scanned", rotation)
		}

		// The newer payload is the one that survived. Read with both keys, because
		// the process that wrote it is on the retired key — that is P1-1.
		both, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
		if err != nil {
			t.Fatal(err)
		}
		if got := mustRead(t, both, id); got != "second" {
			t.Errorf("surviving payload = %q, want the concurrently enrolled one: the rotation rolled the row back", got)
		}

		// And the audit trail must not call the run a success: it is what an
		// operator reads before deciding to drop the retired key. (Later reads append
		// their own events, so the rotation's is found by action, not by position.)
		var rotationEvent *audit.Event
		for i := range logger.Events() {
			if e := logger.Events()[i]; e.Action == "vault.rotate_keys" {
				rotationEvent = &e
			}
		}
		if rotationEvent == nil {
			t.Fatal("no vault.rotate_keys event was written for the rotation")
		}
		if rotationEvent.Outcome != audit.OutcomeError {
			t.Errorf("the rotation event reports outcome=%q, want %q: a run that left a record unre-wrapped "+
				"must not read as a success", rotationEvent.Outcome, audit.OutcomeError)
		}
		if rotationEvent.Detail["skipped"] != "1" {
			t.Errorf("the rotation event carries skipped=%q, want 1", rotationEvent.Detail["skipped"])
		}
	})

	// --- B: the documented procedure, to its conclusion ---------------------

	t.Run("B a late write on the retired key is the operator's gate, not a silent loss", func(t *testing.T) {
		repo := vault.NewMemoryRepo()
		oldPod, err := vault.NewService(repo, old, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := oldPod.Enroll(ctx, id, []byte("a-secret"), nil); err != nil {
			t.Fatal(err)
		}
		rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
		if err != nil {
			t.Fatal(err)
		}
		first, err := rotator.Rotate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if first.Scanned != 1 || first.Rewrapped != 1 || first.Skipped != 0 {
			t.Fatalf("first run = %+v", first)
		}

		// A process still configured with the retired key writes AFTER the run. No
		// rotation can see this; the gate is the re-run.
		if err := oldPod.Enroll(ctx, other, []byte("late-secret"), nil); err != nil {
			t.Fatal(err)
		}
		recs, err := repo.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		onRetired := 0
		for _, rec := range recs {
			if rec.KEKID == "kek-1" {
				onRetired++
			}
		}
		if onRetired != 1 {
			t.Fatalf("%d records are on the retired key, want 1: the probe did not model the late write", onRetired)
		}
		// Removing the key now is what makes it permanent, and that is exactly what
		// the operator is told not to do until a re-run reports nothing to do.
		withoutOld, err := vault.NewService(repo, fresh, logger)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readSecret(t, withoutOld, other); err == nil {
			t.Error("the late write stayed readable without the retired key; the model is wrong")
		}

		// The re-run the report demands converges, and then the key can go.
		second, err := rotator.Rotate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if second.Rewrapped != 1 || second.Skipped != 0 || second.Scanned != 2 {
			t.Fatalf("the converging run = %+v, want Scanned 2 / Rewrapped 1 / Skipped 0", second)
		}
		third, err := rotator.Rotate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if third.Rewrapped != 0 || third.Skipped != 0 || third.AlreadyCurrent != 2 {
			t.Fatalf("the confirming run = %+v, want AlreadyCurrent 2 / Rewrapped 0 / Skipped 0", third)
		}
		if got := mustRead(t, withoutOld, other); got != "late-secret" {
			t.Fatalf("after convergence the late write reads %q", got)
		}
		if got := mustRead(t, withoutOld, id); got != "a-secret" {
			t.Fatalf("after convergence the first record reads %q", got)
		}
	})
}
