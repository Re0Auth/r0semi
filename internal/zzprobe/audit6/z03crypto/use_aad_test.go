//go:build audit6

// Use / AAD / zeroization / error-text probes for the vault, written against
// the exported surface only (the round-5 in-package probes live behind the
// audit5 tag in package vault itself).
package z03crypto

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// TestProbeAADRejectsRowTransplants re-checks, from outside the package, that a
// ciphertext cannot be moved between rows: the DEK envelope and the payload
// are each bound to the record's own (subject, provider).
func TestProbeAADRejectsRowTransplants(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	svc := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())

	alice := vault.Identity{Subject: "usr_alice", Provider: "taptap"}
	bob := vault.Identity{Subject: "usr_bob", Provider: "taptap"}
	if err := svc.Enroll(ctx, alice, []byte("alice-token"), nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enroll(ctx, bob, []byte("bob-token"), nil); err != nil {
		t.Fatal(err)
	}
	// Positive control: both rows open.
	for _, id := range []vault.Identity{alice, bob} {
		if _, err := useSecret(t, svc, id); err != nil {
			t.Fatalf("control: %s does not open: %v", id, err)
		}
	}

	a, err := repo.Get(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.Get(ctx, bob)
	if err != nil {
		t.Fatal(err)
	}

	// Move Alice's wrapped DEK onto Bob's row, keeping Bob's payload.
	swapped := b
	swapped.WrappedDEK = append([]byte(nil), a.WrappedDEK...)
	swapped.KEKID = a.KEKID
	if err := repo.Put(ctx, swapped); err != nil {
		t.Fatal(err)
	}
	if _, err := useSecret(t, svc, bob); err == nil {
		t.Error("a wrapped DEK moved between rows opened: the KEK envelope is not bound to the record identity")
	}

	// Move Alice's payload onto Bob's row, keeping Bob's own envelope.
	swapped2 := b
	swapped2.Nonce = append([]byte(nil), a.Nonce...)
	swapped2.Ciphertext = append([]byte(nil), a.Ciphertext...)
	if err := repo.Put(ctx, swapped2); err != nil {
		t.Fatal(err)
	}
	if _, err := useSecret(t, svc, bob); err == nil {
		t.Error("a payload ciphertext moved between rows opened: the DEK layer is not bound to the record identity")
	}
}

// TestProbeUseCallbackRunsNoVaultLockHeld pins the lock semantics the brief
// asks about: vault.Use holds no repository lock across the caller's callback,
// so a callback that re-enters the repo (a refresh, another read, a sweep)
// cannot deadlock.
func TestProbeUseCallbackRunsNoVaultLockHeld(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	svc := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())

	ids := []vault.Identity{
		{Subject: "usr_lock", Provider: "taptap"},
		{Subject: "usr_other", Provider: "taptap"},
	}
	for _, id := range ids {
		if err := svc.Enroll(ctx, id, []byte("s"), nil); err != nil {
			t.Fatal(err)
		}
	}

	// The callback performs, under the plaintext window, every repo operation
	// a real caller might: a read of the same row, a write of another row, a
	// list, an existence check and a rotation-style CAS on the same identity.
	done := make(chan error, 1)
	go func() {
		done <- svc.Use(ctx, ids[0], func(plain []byte) error {
			if _, err := repo.Get(ctx, ids[0]); err != nil {
				return err
			}
			if err := repo.Put(ctx, vault.Record{Identity: ids[1], Version: 1, KEKID: "kek-1",
				WrappedDEK: []byte("x"), Meta: map[string]string{}}); err != nil {
				return err
			}
			if _, err := repo.List(ctx); err != nil {
				return err
			}
			if ok, err := svc.Exists(ctx, ids[0]); err != nil || !ok {
				return errors.New("exists inside the callback")
			}
			applied, err := repo.RewrapIfUnchanged(ctx, ids[0], []byte("never-matches"), vault.Envelope{
				KEKID: "kek-1", WrappedDEK: []byte("y"),
			})
			if err != nil {
				return err
			}
			if applied {
				return errors.New("a CAS with a bogus expect token applied")
			}
			_ = plain
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the callback could not re-enter the repo: %v (a lock is held across the Use callback)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Use deadlocked: a repository lock is held across the caller's callback")
	}
}

// TestProbeNoncesAreFreshThroughTheRealPath re-checks nonce freshness through
// Enroll: the KEK-layer nonce (wrapped DEK prefix) and the payload nonce must
// both differ on every write of the same plaintext under the same key.
func TestProbeNoncesAreFreshThroughTheRealPath(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	svc := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())
	id := vault.Identity{Subject: "usr_nonce", Provider: "taptap"}

	const rounds = 128
	seenPayload := make(map[string]bool, rounds)
	seenKEK := make(map[string]bool, rounds)
	for i := 0; i < rounds; i++ {
		if err := svc.Enroll(ctx, id, []byte("same plaintext"), nil); err != nil {
			t.Fatal(err)
		}
		rec, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec.Nonce) != 12 || len(rec.WrappedDEK) < 12 {
			t.Fatalf("nonce shapes: %d / %d", len(rec.Nonce), len(rec.WrappedDEK))
		}
		if seenPayload[string(rec.Nonce)] {
			t.Fatalf("payload nonce repeated after %d enrolls", i)
		}
		seenPayload[string(rec.Nonce)] = true
		if seenKEK[string(rec.WrappedDEK[:12])] {
			t.Fatalf("KEK-layer nonce repeated after %d enrolls", i)
		}
		seenKEK[string(rec.WrappedDEK[:12])] = true
	}
}

// TestProbeUseZeroizesWhatItHandedOut re-checks I2 from outside the package:
// after Use returns, the slice the callback saw holds zeros.
func TestProbeUseZeroizesWhatItHandedOut(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	svc := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())
	id := vault.Identity{Subject: "usr_zero", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("upstream-token-material"), nil); err != nil {
		t.Fatal(err)
	}

	var observed []byte
	if err := svc.Use(ctx, id, func(plain []byte) error {
		observed = plain
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, make([]byte, len(observed))) {
		t.Fatalf("the plaintext handed to the callback survived Use: %q", observed)
	}
}

// TestProbeUseFailsClosedWhenTheAuditSinkIsDown re-checks I3 from outside the
// package: when the audit log is unavailable the secret is not handed over.
func TestProbeUseFailsClosedWhenTheAuditSinkIsDown(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	id := vault.Identity{Subject: "usr_i3", Provider: "taptap"}
	seeder := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), logger)
	if err := seeder.Enroll(ctx, id, []byte("secret"), nil); err != nil {
		t.Fatal(err)
	}

	sealed := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), failingLogger{err: errors.New("down")})
	called := false
	if err := sealed.Use(ctx, id, func([]byte) error { called = true; return nil }); err == nil {
		t.Fatal("Use succeeded despite an unavailable audit log")
	}
	if called {
		t.Fatal("the secret was used despite an unavailable audit log")
	}
}

// TestProbeVaultErrorsCarryTheRawSubject is the red probe for the finding that
// vault error strings embed the raw account id (Identity.String renders
// "provider:usr_…"), which reaches the process log on the -rotate-keys failure
// path (die → slog.Error with the error text) and on the unbind/cascade warn
// paths — a channel the round-5 log guard (which only matches slog attribute
// keys) cannot see.
func TestProbeVaultErrorsCarryTheRawSubject(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := mustWrapper(t, "kek-1", 0xA1)
	fresh := mustWrapper(t, "kek-2", 0xB2)
	id := vault.Identity{Subject: "usr_victim", Provider: "taptap"}

	seeder := mustService(t, repo, old, logger)
	if err := seeder.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}

	// A deployment that rotated away from kek-1 without declaring it: the read
	// path's error names the row it cannot open.
	blind := mustService(t, repo, fresh, logger)
	_, err := useSecret(t, blind, id)
	if err == nil {
		t.Fatal("control: the record unexpectedly opened under the wrong key")
	}
	if strings.Contains(err.Error(), "usr_victim") {
		t.Errorf("a vault Use error string carries the raw account id (%q); the same text "+
			"reaches the process log via the unbind/cascade warn paths, which the round-5 "+
			"attr-key guard cannot see", err.Error())
	}

	// And the rotation's own error path, the one -rotate-keys hands to slog
	// (die → slog.Error("cannot start", "err", …)).
	_, rerr := blind.Rotate(ctx)
	if rerr == nil {
		t.Fatal("control: the rotation unexpectedly succeeded without the retired key")
	}
	if strings.Contains(rerr.Error(), "usr_victim") {
		t.Errorf("a vault rotation error string carries the raw account id (%q); -rotate-keys logs "+
			"this text verbatim on its failure path", rerr.Error())
	}
}
