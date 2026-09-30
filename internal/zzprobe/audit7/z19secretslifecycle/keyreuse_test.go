//go:build audit7

package z19secretslifecycle

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/vault"
)

// Z19-4 — supplement to round 6's G-22 (key material reused with no signal).
//
// G-22 is about the KEK, the OP token key and the audit key sharing one value at
// startup. The rotation path had a sharper instance of the same acceptance
// surface, failing in the direction that matters: `WithRetiredKeys`
// (vault/service.go) rejected a retired key whose *id* equals the current key's,
// but never compared key MATERIAL — so a deployment that introduced the old bytes
// under a second id (`kek-2`) got a `-rotate-keys` run that reported
// `rewrapped=N` and exited 0, while every re-wrapped record was still protected
// by the very bytes the operator was about to declare retired.
//
// That run is the remediation for a leaked KEK (docs/threat-model.md §6.0:
// rotation is what stops a leaked key from applying to what is written
// afterwards), and it silently did nothing. The gate `rotationReport` prints —
// "run until rewrapped=0 skipped=0, then remove the retired key"
// (cmd/re0auth/main.go:1226-1229) — passed, so the operator removed the retired
// key from the configuration and believed the leak was bounded.
//
// The fix makes the reused-material deployment refuse to start: LocalKeyWrapper
// exposes an optional KeyFingerprint (vault/envelope.go) and WithRetiredKeys
// compares it, naming both ids. The subject half below asserts that startup
// refusal; the distinct-material control is kept because it is what makes the
// assertion about material reuse rather than about WithRetiredKeys rejecting
// everything.
func TestZ19RotationAwayFromReusedKeyMaterialIsSilent(t *testing.T) {
	ctx := context.Background()
	id := vault.Identity{Subject: "usr_rot", Provider: "taptap"}
	seed := bytes.Repeat([]byte{0x77}, 32)
	other := bytes.Repeat([]byte{0x88}, 32)

	// setup enrolls one record under a service whose current key is
	// ("kek-1", oldBytes), and returns the repo plus that wrapper.
	setup := func(t *testing.T, oldBytes []byte) (*vault.MemoryRepo, *vault.LocalKeyWrapper) {
		t.Helper()
		repo := vault.NewMemoryRepo()
		old, err := vault.NewLocalKeyWrapper("kek-1", oldBytes)
		if err != nil {
			t.Fatal(err)
		}
		first, err := vault.NewService(repo, old, &switchableAudit{})
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Enroll(ctx, id, []byte("upstream-token"), nil); err != nil {
			t.Fatalf("enroll: %v", err)
		}
		return repo, old
	}

	aad := bindingAAD("usr_rot", "taptap")

	// Control: distinct material. The second service is accepted, the rotation
	// runs, and the retired wrapper can no longer open the re-wrapped DEK. That
	// is what shows the subject assertion is about reused material and not about
	// WithRetiredKeys refusing every retired key.
	ctrlRepo, ctrlOld := setup(t, seed)
	ctrlNext, err := vault.NewLocalKeyWrapper("kek-2", other)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := vault.NewService(ctrlRepo, ctrlNext, &switchableAudit{}, vault.WithRetiredKeys(ctrlOld))
	if err != nil {
		t.Fatalf("control: distinct material was refused: %v", err)
	}
	ctrlRot, err := ctrl.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctrlRec, err := ctrlRepo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if ctrlRot.Rewrapped != 1 || ctrlRec.KEKID != "kek-2" {
		t.Fatalf("control: the rotation did not move the record: %+v kek_id=%q", ctrlRot, ctrlRec.KEKID)
	}
	if _, err := ctrlOld.Unwrap(ctx, ctrlRec.WrappedDEK, aad); err == nil {
		t.Fatal("control is wrong: the retired key opened a DEK wrapped under different material")
	}
	t.Log("control (distinct material): accepted, rotated, and the retired key cannot open the re-wrapped DEK")

	// Subject: the same bytes under a second id. The deployment must not start,
	// and the refusal must name both ids so the misconfiguration is actionable.
	repo, old := setup(t, seed)
	next, err := vault.NewLocalKeyWrapper("kek-2", seed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vault.NewService(repo, next, &switchableAudit{}, vault.WithRetiredKeys(old))
	if err == nil {
		t.Errorf("DISCLOSURE: the same 32 bytes under a new id (kek-2) were accepted as a retired key, " +
			"so `-rotate-keys` would report rewrapped=N and exit 0 while the retired key still unwraps " +
			"every re-wrapped record; vault.WithRetiredKeys must compare material, not ids " +
			"(vault/service.go)")
		return
	}
	for _, want := range []string{"kek-1", "kek-2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	t.Logf("the reused KEK material is refused at startup: %v", err)
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
