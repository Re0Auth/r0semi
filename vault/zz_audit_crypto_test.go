//go:build audit || audit6

package vault

// Round-6 crypto/key-management audit probes (vault area).
//
// These files are TEST-ONLY: no production file is modified. Each probe either
// (a) pins a property that currently holds, so a later change is deliberate, or
// (b) pins a property that currently does NOT hold, in the style of
// zzprobe_crypto_test.go's TestProbeAADIsIdenticalAcrossTheTwoLayers —the point
// is that the defect is executable rather than asserted.
//
// Findings and their file:line evidence are written up in
// C:\git\r0semi\_audit\crypto-vault.md.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// --- K-1: the rotation completeness gate cannot see an insert behind the cursor

// auditCursorRepo fires one hook inside the rotation's compare-and-swap window,
// before the envelope write is attempted. It models the interleaving a live
// deployment produces: an old-key pod writing a NEW credential while a rotation
// page is being processed.
type auditCursorRepo struct {
	*MemoryRepo
	fired bool
	hook  func()
}

func (r *auditCursorRepo) RewrapIfUnchanged(ctx context.Context, id Identity, expect []byte, next Envelope) (bool, error) {
	if !r.fired {
		r.fired = true
		if r.hook != nil {
			r.hook()
		}
	}
	return r.MemoryRepo.RewrapIfUnchanged(ctx, id, expect, next)
}

// TestAuditRotateGateIsBlindToAnInsertBehindTheCursor is the finding.
//
// `-rotate-keys` decides "this run is complete" from Rotation.Skipped alone
// (cmd/re0auth/main.go:1209-1231 -> 1181-1191): skipped==0 means exit 0, and
// vault/rotate.go:78-81 records the audit event as OutcomeOK. Skipped is only
// incremented when the CAS refuses (vault/rotate.go:155-163) —i.e. only for a
// record the run READ and then found changed.
//
// A record first written *behind* the paging cursor, by a process still
// configured with the retired key, is never read by this run. It is not Skipped,
// not Rewrapped and not AlreadyCurrent, so the run reports itself complete, the
// audit trail says ok, and the process exits 0 —while that credential sits on a
// key the operator is told they may now delete. Deleting it makes the credential
// permanently unreadable (demonstrated at the end of this test).
//
// README.md:60-69 now documents the operational remedy (drain the old pods, then
// re-run until rewrapped=0 skipped=0). What this probe shows is that the machine
// -checkable half of that gate —the exit code and the audit outcome —cannot
// express it, so an operator who automates "exit 0 => remove the retired key"
// still destroys data.
func TestAuditRotateGateIsBlindToAnInsertBehindTheCursor(t *testing.T) {
	ctx := context.Background()
	repo := &auditCursorRepo{MemoryRepo: NewMemoryRepo()}
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)

	seeder, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one full page, so the run advances its cursor and then stops: any
	// insert sorting before the cursor is invisible to the second page.
	for i := 0; i < rotatePageSize; i++ {
		id := Identity{Subject: fmt.Sprintf("usr_%03d", i), Provider: "taptap"}
		if err := seeder.Enroll(ctx, id, []byte("seed"), nil); err != nil {
			t.Fatal(err)
		}
	}

	// The pod that has not been rolled yet: its CURRENT key is the one the
	// rotator is retiring. This is what `replicas: 2` + a rolling update produces.
	oldPod, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	latecomer := Identity{Subject: "aaa_late", Provider: "taptap"}
	repo.hook = func() {
		if err := oldPod.Enroll(ctx, latecomer, []byte("late-secret"), nil); err != nil {
			t.Errorf("the still-serving old-key pod could not enroll: %v", err)
		}
	}

	rotator, err := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rotation run reported %+v", rot)

	if rot.Scanned != rotatePageSize || rot.Rewrapped != rotatePageSize {
		t.Fatalf("rotation = %+v, want the %d seeded records scanned and re-wrapped", rot, rotatePageSize)
	}
	// The gate. skipped==0 is exactly the condition main.go turns into exit 0.
	if rot.Skipped != 0 {
		t.Fatalf("rotation = %+v, want skipped=0 (the probe premise is that the gate is silent)", rot)
	}

	// The credential written behind the cursor is still on the retired key.
	rec, err := repo.Get(ctx, latecomer)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KEKID != old.KeyID() {
		t.Fatalf("latecomer KEKID = %q, want %q (probe premise wrong)", rec.KEKID, old.KeyID())
	}

	// And the durable audit trail —the record an operator consults before
	// deleting the key (vault/rotate.go:71-91) —says the run was OK and skipped
	// nothing.
	var sawRotate bool
	for _, e := range logger.Events() {
		if e.Action != "vault.rotate_keys" {
			continue
		}
		sawRotate = true
		if e.Outcome != audit.OutcomeOK {
			t.Errorf("vault.rotate_keys outcome = %q, want ok", e.Outcome)
		}
		if e.Detail["skipped"] != "0" || e.Detail["rewrapped"] != fmt.Sprint(rotatePageSize) {
			t.Errorf("audit detail = %v; the trail reports a complete rotation", e.Detail)
		}
	}
	if !sawRotate {
		t.Fatal("no vault.rotate_keys event was recorded")
	}

	// Step 4 of README.md:45-58: remove [[vault.retired]] and restart. The
	// credential written behind the cursor is now permanently unreadable.
	blind, err := NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	uerr := blind.Use(ctx, latecomer, func([]byte) error { return nil })
	if uerr == nil {
		t.Fatal("the latecomer still opened after the retired key was removed")
	}
	if !strings.Contains(uerr.Error(), "not configured") {
		t.Fatalf("latecomer error = %v, want the unconfigured-key error", uerr)
	}
	t.Logf("CONFIRMED: after removing the retired key the credential written behind the cursor "+
		"is permanently unreadable (%v), while this run reported scanned=%d rewrapped=%d skipped=%d, "+
		"wrote vault.rotate_keys/ok, and (main.go:1216) exited 0",
		uerr, rot.Scanned, rot.Rewrapped, rot.Skipped)
}

// --- K-2: a retired KEK with the same material under a different id is accepted

// TestAuditRetiredKeySharingMaterialIsAcceptedAndRotationIsANoOp is the finding.
//
// WithRetiredKeys only refuses a retired key whose *id* equals the current one
// (vault/service.go:118-122), and main.go builds both wrappers from raw bytes
// without comparing them (cmd/re0auth/main.go:1131-1149). The KeyWrapper
// interface deliberately exposes no material, so the service cannot compare
// either.
//
// Consequence: a deployment that puts the same 32 bytes in RE0AUTH_KEK and in the
// retired key's variable (a copy-paste during the rotation, a secret manager
// entry reused) gets a rotation that reports rewrapped=1 skipped=0 and exits 0 —// and a credential whose envelope is still openable by the material the operator
// believes they have rotated away from.
func TestAuditRetiredKeySharingMaterialIsAcceptedAndRotationIsANoOp(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()

	// The same 32 bytes under two ids: "kek-1" retired, "kek-2" current.
	material := bytes.Repeat([]byte{0x11}, dekSize)
	oldKey, err := NewLocalKeyWrapper("kek-1", material)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := NewLocalKeyWrapper("kek-2", material)
	if err != nil {
		t.Fatal(err)
	}

	id := Identity{Subject: "usr_same", Provider: "taptap"}
	seeder, err := NewService(repo, oldKey, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := seeder.Enroll(ctx, id, []byte("upstream-token"), nil); err != nil {
		t.Fatal(err)
	}

	// WithRetiredKeys accepts the pair: nothing compares the bytes.
	rotator, err := NewService(repo, newKey, logger, WithRetiredKeys(oldKey))
	if err != nil {
		t.Fatalf("WithRetiredKeys refused a retired key with the same material: %v", err)
	}
	rot, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Rewrapped != 1 || rot.Skipped != 0 {
		t.Fatalf("rotation = %+v, want the complete-looking rewrapped=1 skipped=0", rot)
	}

	rec, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KEKID != "kek-2" {
		t.Fatalf("kek_id = %q, want the record relabelled to the current id", rec.KEKID)
	}

	// The material the operator just "retired" still opens the current envelope.
	// A wrapper carrying only the old bytes under a third id is enough, which is
	// the whole threat model of a leaked KEK.
	leaked, err := NewLocalKeyWrapper("attacker-copy", material)
	if err != nil {
		t.Fatal(err)
	}
	aad := bindingAAD(rec.Version, id.Subject, id.Provider)
	if _, err := leaked.Unwrap(ctx, rec.WrappedDEK, aad); err != nil {
		t.Fatalf("control: the re-wrapped envelope no longer opens under the material: %v", err)
	}
	t.Log("CONFIRMED: the rotation reported rewrapped=1 skipped=0 (=> -rotate-keys exits 0) " +
		"while the envelope is still openable by the material of the retired key: the run is a no-op " +
		"that looks like a completed rotation")
}

// --- K-3: Scrub does not remove the key's expanded form

// TestAuditScrubDoesNotRevokeTheExpandedKeySchedule is the finding, stated as the
// strongest thing that is actually observable.
//
// vault.Scrub(dek) overwrites the DEK slice (service.go:195, :284; rotate.go:118,
// :134). It does not and cannot reach the AES *key schedule* that
// sealSecret/openSecret built from that DEK (vault/envelope.go:127 and :144:
// aes.NewCipher(dek) + cipher.NewGCM(block)). That schedule is a 240-byte
// expansion on the heap that remains useful after every Scrub call: a live
// cipher object keeps working, so a heap dump taken after Use returns still
// yields the DEK's effect.
//
// Mitigation that limits the impact today, and the reason this is reported as low
// rather than high: with LocalKeyWrapper the KEK itself is resident in the
// process for its whole life (envelope.go:52-55), so a heap dump is already
// total. The residual matters for the deployment the design points at —a
// KMS-backed KeyWrapper, where the per-credential DEK is the only key in the
// process and Scrub is supposed to be the thing that ends its life.
func TestAuditScrubDoesNotRevokeTheExpandedKeySchedule(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, dekSize)
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("upstream-token"), nil)

	// What the vault does when the operation ends.
	Scrub(dek)
	if !bytes.Equal(dek, make([]byte, dekSize)) {
		t.Fatal("control: Scrub did not zero the slice it was handed")
	}

	// The cipher is still live. This is the copy Scrub cannot reach.
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("the expanded key schedule did not survive Scrub: %v", err)
	}
	if string(pt) != "upstream-token" {
		t.Fatalf("plaintext = %q", pt)
	}
	t.Log("CONFIRMED: after Scrub(dek) the aes/cipher.GCM object built from that DEK still " +
		"decrypts, because aes.NewCipher expanded the key into a schedule Scrub has no handle on; " +
		"vault/envelope.go:127 and :144 build one of those per seal/open operation")
}

// --- K-4: concurrent writers + rotator (run with -race)

// TestAuditConcurrentRotateEnrollUseConverges runs the two-process interleaving
// this area is about in one process, with -race: a not-yet-rolled pod still
// writing under the retired key, a rolled pod serving reads, and a rotator
// re-wrapping pages underneath both. The invariant asserted is the one an
// operator needs: once the writers stop, a final rotation converges to
// rewrapped=0 skipped=0 and no record is left on the retired key.
func TestAuditConcurrentRotateEnrollUseConverges(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := keyFor(t, "kek-1", 0xA1)
	fresh := keyFor(t, "kek-2", 0xB2)

	oldPod, err := NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	both, err := NewService(repo, fresh, logger, WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}

	const seed = 32
	ids := make([]Identity, 0, seed)
	for i := 0; i < seed; i++ {
		id := Identity{Subject: fmt.Sprintf("usr_%03d", i), Provider: "taptap"}
		if err := oldPod.Enroll(ctx, id, []byte("seed"), nil); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	var wg sync.WaitGroup
	// The writer that has not been rolled: every row it touches is on the
	// retired key.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			id := Identity{Subject: fmt.Sprintf("late_%03d", i), Provider: "taptap"}
			if err := oldPod.Enroll(ctx, id, []byte("late"), nil); err != nil {
				t.Errorf("old-pod enroll: %v", err)
				return
			}
			if err := oldPod.Enroll(ctx, ids[i%seed], []byte("late-rewrite"), nil); err != nil {
				t.Errorf("old-pod re-enroll: %v", err)
				return
			}
		}
	}()
	// The rolled pod serving reads and re-enrolls.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			id := ids[i%seed]
			if err := both.Enroll(ctx, id, []byte("served"), nil); err != nil {
				t.Errorf("rolled-pod enroll: %v", err)
				return
			}
			if err := both.Use(ctx, id, func([]byte) error { return nil }); err != nil {
				t.Errorf("rolled-pod use: %v", err)
				return
			}
		}
	}()
	// Two concurrent rotations, which is what a retried or two-replica run is.
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				if _, err := both.Rotate(ctx); err != nil {
					t.Errorf("concurrent rotate: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Writers have stopped. One final run must reach the gate.
	final, err := both.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if final.Skipped != 0 || final.Rewrapped != 0 {
		t.Fatalf("after the writers stopped the rotation did not converge: %+v", final)
	}
	records, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.KEKID != fresh.KeyID() {
			t.Errorf("%s is still on %q after the convergence run", rec.Identity, rec.KEKID)
		}
	}
	// And a deployment with only the current key can read all of them.
	onlyFresh, err := NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if err := onlyFresh.Use(ctx, rec.Identity, func([]byte) error { return nil }); err != nil {
			t.Errorf("%s does not open under the current key alone: %v", rec.Identity, err)
		}
	}
}
