//go:build audit5

package vault

// Zeroization probe. The project claims plaintext is zeroized after use
// (invariant I2, Scrub's own doc). This file checks what that claim actually
// buys, by holding the slice the callback received and reading it back
// afterwards. It is deliberately scoped to what is observable: the backing array
// the vault handed out.

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// TestProbeScrubZeroesTheBackingArrayItWasGiven is the honest version of the
// zeroization claim: the bytes Scrub is handed really are overwritten, and they
// stay overwritten (KeepAlive + noinline are what make that not a compiler
// artefact).
func TestProbeScrubZeroesTheBackingArrayItWasGiven(t *testing.T) {
	b := bytes.Repeat([]byte{0xAB}, 64)
	alias := b
	Scrub(b)
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatalf("Scrub left %x", alias)
	}
}

// TestProbeUseZeroizesThePlaintextItHandedOut shows the property the project
// does get: after Use returns, the slice the callback saw holds zeros, so a
// later reuse of that slice cannot recover the credential.
//
// The residual — copies made by json.Marshal, []byte(string) conversions, or an
// error message — is NOT covered by this and cannot be, in Go. It is stated in
// the report rather than pretended away here.
func TestProbeUseZeroizesThePlaintextItHandedOut(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()
	svc, err := NewService(repo, testKey(t), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_zero", Provider: "taptap"}
	secret := []byte("super-secret-upstream-token")
	if err := svc.Enroll(ctx, id, secret, nil); err != nil {
		t.Fatal(err)
	}

	var observed []byte
	var atCallback []byte
	if err := svc.Use(ctx, id, func(plain []byte) error {
		atCallback = append([]byte(nil), plain...)
		observed = plain // keep the slice itself, to read it after Use returns
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(atCallback, secret) {
		t.Fatalf("callback saw %q, want %q", atCallback, secret)
	}
	if !bytes.Equal(observed, make([]byte, len(observed))) {
		t.Errorf("the plaintext slice handed to the callback still holds %q after Use returned: "+
			"Scrub did not reach it (len=%d cap=%d)", observed, len(observed), cap(observed))
	}
}

// TestProbeUseZeroizesEvenWhenTheCallbackFails covers "whatever fn returns".
func TestProbeUseZeroizesEvenWhenTheCallbackFails(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(NewMemoryRepo(), testKey(t), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_zero2", Provider: "taptap"}
	if err := svc.Enroll(ctx, id, []byte("tok"), nil); err != nil {
		t.Fatal(err)
	}
	var observed []byte
	sentinel := errors.New("callback failed")
	err = svc.Use(ctx, id, func(plain []byte) error {
		observed = plain
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Use returned %v, want the callback's own error", err)
	}
	if !bytes.Equal(observed, make([]byte, len(observed))) {
		t.Errorf("plaintext survived a failing callback: %q", observed)
	}
}

// TestProbeUseDoesNotZeroizeTheCallersCopy is the boundary, stated as a test so
// it cannot be mistaken for a guarantee: anything the callback copies is outside
// Scrub's reach, and the vault has no way to know about it.
func TestProbeUseDoesNotZeroizeTheCallersCopy(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(NewMemoryRepo(), testKey(t), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_zero3", Provider: "taptap"}
	secret := []byte("tok-copy")
	if err := svc.Enroll(ctx, id, secret, nil); err != nil {
		t.Fatal(err)
	}
	var copyHeld []byte
	if err := svc.Use(ctx, id, func(plain []byte) error {
		copyHeld = append([]byte(nil), plain...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copyHeld, secret) {
		t.Fatal("the probe's own copy was zeroed, which would mean Scrub walks beyond its slice")
	}
	// Deliberately not an error. This is the documented residual: Go cannot
	// reach a copy, and the federation layer's bindingSecret is a string (the
	// same limit, already recorded by round two).
	_ = copyHeld
}

// TestProbeEnrollDoesNotRetainTheCallersSecretBytes checks that Enroll does not
// keep a reference to the caller's slice: it seals into a fresh buffer, so a
// later mutation of the caller's slice cannot change what is stored.
func TestProbeEnrollDoesNotRetainTheCallersSecretBytes(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(NewMemoryRepo(), testKey(t), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "usr_alias", Provider: "taptap"}
	secret := []byte("original-secret")
	if err := svc.Enroll(ctx, id, secret, nil); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's slice after enroll: the stored ciphertext must be
	// unaffected, and the caller's buffer must NOT have been zeroed by Enroll
	// (Enroll has no right to write to it).
	for i := range secret {
		secret[i] = 'X'
	}
	var got []byte
	if err := svc.Use(ctx, id, func(p []byte) error { got = append([]byte(nil), p...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(got) != "original-secret" {
		t.Errorf("stored secret changed when the caller mutated its buffer: got %q", got)
	}
	if string(secret) != "XXXXXXXXXXXXXXX" {
		t.Errorf("Enroll modified the caller's slice: %q", secret)
	}
}
