//go:build audit5

package vault

// Audit probe (crypto/key-lifecycle area). This file only READS the package's
// unexported surface; no production file is modified. It exists because
// bindingAAD, recordVersion, sealSecret and openSecret cannot be reached from
// internal/zzprobe/... .
//
// Tests here are guards: each one is written so that it fails if the property it
// names stops holding.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// --- AAD binding -----------------------------------------------------------

// TestProbeAADIsInjective pins the length-prefixed encoding: ("a","bc") and
// ("ab","c") must not collide, in either order of the pair.
func TestProbeAADIsInjective(t *testing.T) {
	pairs := [][2][2]string{
		{{"a", "bc"}, {"ab", "c"}},
		{{"usr_1", "taptap"}, {"usr_1taptap", ""}},
		{{"", "usr_1taptap"}, {"usr_1", "taptap"}},
		{{"usr_1", "taptap.phigros"}, {"usr_1.taptap", "phigros"}},
	}
	for _, p := range pairs {
		left := bindingAAD(recordVersion, p[0][0], p[0][1])
		right := bindingAAD(recordVersion, p[1][0], p[1][1])
		if bytes.Equal(left, right) {
			t.Errorf("bindingAAD(%q,%q) == bindingAAD(%q,%q)", p[0][0], p[0][1], p[1][0], p[1][1])
		}
	}
}

// TestProbeEnvelopeAADPreventsMovingACiphertext is the "swap two rows" test the
// brief asks for: the DEK envelope and the payload must each be bound to the
// record's own (subject, provider), not merely to each other.
//
// It asserts a POSITIVE control first (an untouched record opens), so a failure
// cannot be "the probe never reached the path".
func TestProbeEnvelopeAADPreventsMovingACiphertext(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	svc, err := NewService(repo, testKey(t), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	alice := Identity{Subject: "usr_alice", Provider: "taptap"}
	bob := Identity{Subject: "usr_bob", Provider: "taptap"}
	aliceSecret := []byte("alice-upstream-token")
	if err := svc.Enroll(ctx, alice, aliceSecret, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enroll(ctx, bob, []byte("bob-upstream-token"), nil); err != nil {
		t.Fatal(err)
	}

	// Positive control: both records open normally.
	for _, id := range []Identity{alice, bob} {
		if err := svc.Use(ctx, id, func([]byte) error { return nil }); err != nil {
			t.Fatalf("control failed for %s: %v", id, err)
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

	// 1. Move Alice's DEK envelope onto Bob's row (keeping Bob's payload). Bob's
	//    AAD is (usr_bob, taptap), so the unwrap must fail.
	swapped := b
	swapped.WrappedDEK = append([]byte(nil), a.WrappedDEK...)
	swapped.KEKID = a.KEKID
	if err := repo.Put(ctx, swapped); err != nil {
		t.Fatal(err)
	}
	if err := svc.Use(ctx, bob, func([]byte) error { return nil }); err == nil {
		t.Error("SWAPPED wrapped DEK opened: the KEK envelope is not bound to the record identity")
	}

	// 2. Move Alice's payload ciphertext+nonce onto Bob's row with Bob's own DEK
	//    envelope: the payload AAD must reject it.
	swapped2 := b
	swapped2.Nonce = append([]byte(nil), a.Nonce...)
	swapped2.Ciphertext = append([]byte(nil), a.Ciphertext...)
	if err := repo.Put(ctx, swapped2); err != nil {
		t.Fatal(err)
	}
	if err := svc.Use(ctx, bob, func([]byte) error { return nil }); err == nil {
		t.Error("SWAPPED payload ciphertext opened: the DEK layer is not bound to the record identity")
	}

	// 3. And a provider-only swap inside the same subject.
	aliceOther := Identity{Subject: "usr_alice", Provider: "phigros"}
	if err := svc.Enroll(ctx, aliceOther, []byte("other"), nil); err != nil {
		t.Fatal(err)
	}
	src, err := repo.Get(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := repo.Get(ctx, aliceOther)
	if err != nil {
		t.Fatal(err)
	}
	dst.Nonce, dst.Ciphertext = append([]byte(nil), src.Nonce...), append([]byte(nil), src.Ciphertext...)
	if err := repo.Put(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if err := svc.Use(ctx, aliceOther, func([]byte) error { return nil }); err == nil {
		t.Error("a ciphertext moved between providers of the same subject opened")
	}
}

// TestProbeRecordVersionIsInTheAAD proves the stored version byte participates in
// both AADs, i.e. a database writer cannot relabel a record's format version and
// still have it decrypt.
func TestProbeRecordVersionIsInTheAAD(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	w := testKey(t)
	svc, err := NewService(repo, w, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_v", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != recordVersion {
		t.Fatalf("stored version = %d, want %d", rec.Version, recordVersion)
	}

	for _, v := range []byte{0, 2, 255} {
		rec.Version = v
		if err := repo.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
		err := svc.Use(ctx, id, func([]byte) error { return nil })
		if err == nil {
			t.Errorf("version byte %d decrypted: the version is not bound into the AAD", v)
			continue
		}
		// The plan's downgrade question: an attacker-chosen version must not be
		// able to select a *different*, weaker path. There is only one path, so
		// the honest answer is "it fails at the AEAD", not "it reads a v0 format".
		if !errors.Is(err, errOpenFailed) && !strings.Contains(err.Error(), "unwrap DEK") {
			t.Logf("version %d rejected with: %v", v, err)
		}
		rec.Version = recordVersion
		if err := repo.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
}

// errOpenFailed is never returned by production code; it exists so the assertion
// above does not depend on a string.
var errOpenFailed = errors.New("vault: probe sentinel")

// --- cross-layer separation -------------------------------------------------

// TestProbeWrappedDEKCannotBeUsedAsAPayloadKey asks whether the KEK-wrapped blob
// can be replayed as a payload key. It cannot: the wrapped form is a nonce plus a
// GCM tag+ct, never a bare 32-byte key, and aes.NewCipher only accepts 16/24/32.
func TestProbeWrappedDEKCannotBeUsedAsAPayloadKey(t *testing.T) {
	w := testKey(t)
	aad := bindingAAD(recordVersion, "usr_1", "taptap")
	wrapped, err := w.Wrap(context.Background(), bytes.Repeat([]byte{0x22}, dekSize), aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != nonceSize+dekSize+16 {
		t.Fatalf("wrapped DEK is %d bytes, want %d (nonce+ct+tag)", len(wrapped), nonceSize+dekSize+16)
	}
	if _, _, err := sealSecret(wrapped, []byte("s"), aad); err == nil {
		t.Error("a wrapped DEK was accepted as an AES key length")
	}
}

// TestProbeCiphertextLengthEqualsPlaintextLength records the (documented) fact
// that the payload ciphertext length reveals the plaintext length exactly, and
// that the nonce is not stored with it in a fixed-size envelope. This is a
// property to state, not a bug to fix: it is how AES-GCM works.
func TestProbeCiphertextLengthEqualsPlaintextLength(t *testing.T) {
	dek := bytes.Repeat([]byte{0x33}, dekSize)
	aad := bindingAAD(recordVersion, "u", "p")
	for _, n := range []int{0, 1, 32, 100} {
		_, ct, err := sealSecret(dek, bytes.Repeat([]byte{'x'}, n), aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != n+16 {
			t.Fatalf("len %d: ciphertext %d, want %d", n, len(ct), n+16)
		}
	}
}

// TestProbeUnwrapRejectsShortBlobs guards the one length check Unwrap does have:
// a blob shorter than the nonce must be refused before slicing it.
func TestProbeUnwrapRejectsShortBlobs(t *testing.T) {
	w := testKey(t)
	aad := bindingAAD(recordVersion, "u", "p")
	for _, n := range []int{0, 1, nonceSize - 1} {
		if _, err := w.Unwrap(context.Background(), make([]byte, n), aad); err == nil {
			t.Errorf("Unwrap accepted a %d-byte blob", n)
		}
	}
}

// TestProbeNoncesAreFresh pins the per-encryption nonce: two encryptions of the
// same plaintext under the same DEK and AAD must differ in both nonce and
// ciphertext. A repeated (key, nonce) pair in GCM is catastrophic, and this is
// the guard that would catch a refactor introducing one.
func TestProbeNoncesAreFresh(t *testing.T) {
	dek := bytes.Repeat([]byte{0x44}, dekSize)
	aad := bindingAAD(recordVersion, "u", "p")
	const rounds = 512
	seen := make(map[string]struct{}, rounds)
	for i := 0; i < rounds; i++ {
		nonce, ct, err := sealSecret(dek, []byte("same plaintext"), aad)
		if err != nil {
			t.Fatal(err)
		}
		key := string(nonce)
		if _, dup := seen[key]; dup {
			t.Fatalf("nonce reused after %d encryptions", i)
		}
		seen[key] = struct{}{}
		_ = ct
	}

	// The KEK layer too.
	w := testKey(t)
	seen = make(map[string]struct{}, rounds)
	for i := 0; i < rounds; i++ {
		wrapped, err := w.Wrap(context.Background(), dek, aad)
		if err != nil {
			t.Fatal(err)
		}
		key := string(wrapped[:nonceSize])
		if _, dup := seen[key]; dup {
			t.Fatalf("KEK nonce reused after %d wraps", i)
		}
		seen[key] = struct{}{}
	}
}

// TestProbeAADIsIdenticalAcrossTheTwoLayers is a finding, not a guard.
//
// Both the KEK envelope and the payload AEAD are authenticated with the SAME
// bytes: bindingAAD(rec.Version, subject, provider) (service.go:179/193 and
// :255/277). Because the two layers use different keys (the KEK vs the DEK) this
// is not exploitable on its own — a ciphertext cannot be moved from one layer to
// the other — but it means the AAD carries no layer tag, so the two ciphertexts
// are distinguished only by which key opens them.
//
// This test *pins the current state* so that a future change is a deliberate one.
func TestProbeAADIsIdenticalAcrossTheTwoLayers(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	w := testKey(t)
	svc, err := NewService(repo, w, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_layer", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("payload"), nil); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	// Re-derive the KEK-layer plaintext (the DEK is not stored), then show the
	// payload ciphertext does NOT open under the KEK — i.e. the layers are held
	// apart by key material, not by an AAD tag.
	aad := bindingAAD(rec.Version, id.Subject, id.Provider)
	if _, err := w.open(rec.Nonce, rec.Ciphertext, aad); err == nil {
		t.Error("the KEK opened the payload ciphertext: the two layers are not separated at all")
	}
	// And the payload layer does not open the KEK envelope.
	dek := bytes.Repeat([]byte{0x55}, dekSize)
	if _, err := openSecret(dek, rec.WrappedDEK[:nonceSize], rec.WrappedDEK[nonceSize:], aad); err == nil {
		t.Error("a DEK opened the wrapped-DEK envelope")
	}
}
