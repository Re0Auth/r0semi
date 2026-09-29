//go:build audit7

package z19secretslifecycle

import (
	"bytes"
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/vault"
)

// Z19-4 — supplement to round 6's G-22 (key material reused with no signal).
//
// G-22 is about the KEK, the OP token key and the audit key sharing one value at
// startup. The rotation path has a sharper instance of the same acceptance
// surface, and it fails in the direction that matters: `WithRetiredKeys`
// (vault/service.go:112-130) rejects a retired key whose *id* equals the current
// key's, but never compares key MATERIAL — so a deployment that introduces the
// old bytes under a second id (`kek-2`) gets a `-rotate-keys` run that reports
// `rewrapped=N` and exits 0, while every re-wrapped record is still protected by
// the very bytes the operator is about to declare retired.
//
// That run is the remediation for a leaked KEK (docs/threat-model.md §6.0:
// rotation is what stops a leaked key from applying to what is written
// afterwards), and it silently does nothing. The gate `rotationReport` prints —
// "run until rewrapped=0 skipped=0, then remove the retired key"
// (cmd/re0auth/main.go:1226-1229) — passes, so the operator removes the retired
// key from the configuration and believes the leak is bounded.
//
// The control is the same code with two DIFFERENT keys: there the old wrapper
// genuinely cannot open the re-wrapped DEK, which is what makes the subject
// assertion a defect signal rather than a tautology.
func TestZ19RotationAwayFromReusedKeyMaterialIsSilent(t *testing.T) {
	ctx := context.Background()
	id := vault.Identity{Subject: "usr_rot", Provider: "taptap"}
	seed := bytes.Repeat([]byte{0x77}, 32)
	other := bytes.Repeat([]byte{0x88}, 32)

	// rotate runs one `-rotate-keys` equivalent: a record is enrolled under
	// (kek-1, oldBytes), then a second service with current (newID, newBytes) and
	// retired (kek-1, oldBytes) re-wraps it. It returns the run's report, the
	// stored wrapped DEK afterwards, and a wrapper holding the retired bytes.
	rotate := func(t *testing.T, newID string, newBytes, oldBytes []byte) (vault.Rotation, []byte, *vault.LocalKeyWrapper) {
		t.Helper()
		repo := vault.NewMemoryRepo()
		log := &switchableAudit{}

		old, err := vault.NewLocalKeyWrapper("kek-1", oldBytes)
		if err != nil {
			t.Fatal(err)
		}
		first, err := vault.NewService(repo, old, log)
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Enroll(ctx, id, []byte("upstream-token"), nil); err != nil {
			t.Fatalf("enroll: %v", err)
		}

		next, err := vault.NewLocalKeyWrapper(newID, newBytes)
		if err != nil {
			t.Fatal(err)
		}
		second, err := vault.NewService(repo, next, log, vault.WithRetiredKeys(old))
		if err != nil {
			t.Fatalf("second service: %v", err)
		}
		rot, err := second.Rotate(ctx)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		rec, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if rot.Rewrapped != 1 || rec.KEKID != newID {
			t.Fatalf("the rotation did not move the record: %+v kek_id=%q", rot, rec.KEKID)
		}
		retired, err := vault.NewLocalKeyWrapper("kek-1", oldBytes)
		if err != nil {
			t.Fatal(err)
		}
		return rot, rec.WrappedDEK, retired
	}

	aad := bindingAAD("usr_rot", "taptap")

	// Control: distinct material. After the rotation the retired wrapper must NOT
	// be able to open the re-wrapped DEK.
	_, ctrlWrapped, ctrlRetired := rotate(t, "kek-2", other, seed)
	if _, err := ctrlRetired.Unwrap(ctx, ctrlWrapped, aad); err == nil {
		t.Fatal("control is wrong: the retired key opened a DEK wrapped under different material")
	}
	t.Logf("control (distinct material): the retired key cannot open the re-wrapped DEK")

	// Subject: the same bytes under a second id.
	rot, wrapped, retired := rotate(t, "kek-2", seed, seed)
	if _, err := retired.Unwrap(ctx, wrapped, aad); err != nil {
		t.Logf("no defect: the retired key no longer opens the record (%v)", err)
		return
	}
	t.Errorf("DISCLOSURE: `-rotate-keys` reported rewrapped=%d (exit 0 on the command path) while the "+
		"retired key STILL unwraps every re-wrapped record, because the \"new\" KEK is the same 32 bytes "+
		"under a different id. vault.WithRetiredKeys compares ids, never material "+
		"(vault/service.go:119-122), so a leaked KEK is declared rotated and then deleted from the "+
		"configuration while remaining the key that protects the vault (rotation=%+v)", rot.Rewrapped, rot)
}

// bindingAAD mirrors vault's unexported AAD encoding (version 1, then
// length-prefixed subject and provider), which the probe needs in order to
// attempt the unwrap itself.
func bindingAAD(subject, provider string) []byte {
	b := []byte{1}
	b = appendU32(b, uint32(len(subject)))
	b = append(b, subject...)
	b = appendU32(b, uint32(len(provider)))
	b = append(b, provider...)
	return b
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
