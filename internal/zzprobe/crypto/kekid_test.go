//go:build audit5

package crypto

import (
	"context"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// TestProbeKKKIDSelectsOnlyAmongConfiguredKeys answers the brief's question 4:
// "can an attacker who can write the DB point a record at a KEK id they control?"
//
// The answer is no, and the reason is structural rather than cryptographic: the
// id in the row is a MAP KEY into the set of wrappers the composition root built
// at startup (vault/service.go:256 `s.keys[rec.KEKID]`). There is no path from a
// row to a new key. What an attacker WITH DB WRITE can do is (a) make a record
// unreadable by naming an unconfigured id, and (b) make -rotate-keys abort — both
// availability effects, both already true of simply deleting the row.
func TestProbeKEKIDSelectsOnlyAmongConfiguredKeys(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	writer, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	id := vault.Identity{Subject: "usr_kekid", Provider: "taptap"}
	if err := writer.Enroll(ctx, id, []byte("tok"), nil); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	original := rec.KEKID

	for _, bogus := range []string{"", "attacker-key", "kek-1 ", "KEK-1", "kek-1\x00"} {
		rec.KEKID = bogus
		if err := repo.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
		svc, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
		if err != nil {
			t.Fatal(err)
		}
		err = svc.Use(ctx, id, func([]byte) error { return nil })
		if err == nil {
			t.Errorf("a record naming KEK id %q was still opened: the id is not the key selector", bogus)
			continue
		}
		switch {
		case strings.Contains(err.Error(), "not configured"):
			// The fail-closed direction, and the operator-readable one.
		default:
			t.Errorf("KEK id %q produced an unexpected error: %v", bogus, err)
		}
	}

	// The attacker cannot reach an unconfigured wrapper even by naming one the
	// service WILL have: the set is closed at construction.
	rec.KEKID = original
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	onlyFresh, err := vault.NewService(repo, fresh, logger)
	if err != nil {
		t.Fatal(err)
	}
	err = onlyFresh.Use(ctx, id, func([]byte) error { return nil })
	if err == nil {
		t.Fatal("a record from a retired key opened without the retired key configured")
	}
	if !strings.Contains(err.Error(), original) {
		t.Errorf("the error does not name the missing key: %v", err)
	}
}

// TestProbeRotateRefusesAKEKIDItCannotUnwrap pins the rotation-side consequence
// of the same fact: an attacker-chosen (or corrupted) kek_id aborts a rotation
// with an error naming the key, rather than silently skipping the record.
//
// "Abort" is the safe choice — a skipped record would be left on a key the
// operator is about to delete — but it means a single poisoned row is a
// deployment-wide rotation outage until it is repaired.
func TestProbeRotateRefusesAKEKIDItCannotUnwrap(t *testing.T) {
	ctx := context.Background()
	repo := vault.NewMemoryRepo()
	logger := audit.NewMemoryLogger()
	old := key32(t, "kek-1", 0xA1)
	fresh := key32(t, "kek-2", 0xB2)

	writer, err := vault.NewService(repo, old, logger)
	if err != nil {
		t.Fatal(err)
	}
	// The pager walks in (subject, provider) order, so name the good record
	// AFTER the poison to make the rotation re-wrap it before it aborts.
	good := vault.Identity{Subject: "usr_zzz", Provider: "taptap"}
	poisoned := vault.Identity{Subject: "usr_bad", Provider: "taptap"}
	if err := writer.Enroll(ctx, good, []byte("a"), nil); err != nil {
		t.Fatal(err)
	}
	if err := writer.Enroll(ctx, poisoned, []byte("b"), nil); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.Get(ctx, poisoned)
	if err != nil {
		t.Fatal(err)
	}
	rec.KEKID = "attacker-key"
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}

	rotator, err := vault.NewService(repo, fresh, logger, vault.WithRetiredKeys(old))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotator.Rotate(ctx)
	if err == nil {
		t.Fatalf("rotation succeeded with an unconfigured kek_id in the table: %+v", rot)
	}
	if !strings.Contains(err.Error(), "attacker-key") {
		t.Errorf("the error does not name the poison: %v", err)
	}
	// Atomicity consequence: whatever records the run reached before the poison
	// were already re-wrapped, so the deployment can be left in a mixed state and
	// the retired key cannot be removed. Asserted loosely on purpose — the exact
	// point it aborts depends on the page boundary — and the mixed state itself is
	// demonstrated by TestProbeRotationPublishesPartialProgressOnFailure.
	after, err := repo.Get(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rotation aborted at %+v; %q is on %q, so the retired key cannot be removed "+
		"until the poison is repaired", rot, after.Identity, after.KEKID)
}
