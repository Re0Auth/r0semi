package vault

import (
	"bytes"
	"context"
	"testing"
)

func testKey(t *testing.T) *LocalKeyWrapper {
	t.Helper()
	w, err := NewLocalKeyWrapper("test-kek", bytes.Repeat([]byte{0x11}, dekSize))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestLocalKeyWrapperRoundTrip(t *testing.T) {
	w := testKey(t)
	dek := bytes.Repeat([]byte{0x22}, dekSize)
	aad := bindingAAD(recordVersion, "user-1", "taptap")

	wrapped, err := w.Wrap(context.Background(), dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped DEK contains the plaintext DEK")
	}

	got, err := w.Unwrap(context.Background(), wrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unwrap = %x, want %x", got, dek)
	}
}

func TestLocalKeyWrapperBindsAAD(t *testing.T) {
	w := testKey(t)
	dek := bytes.Repeat([]byte{0x22}, dekSize)
	wrapped, err := w.Wrap(context.Background(), dek, bindingAAD(recordVersion, "user-1", "taptap"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(context.Background(), wrapped, bindingAAD(recordVersion, "user-2", "taptap")); err == nil {
		t.Fatal("unwrapped a DEK under a different identity")
	}
}

func TestLocalKeyWrapperRejectsBadKEKSize(t *testing.T) {
	if _, err := NewLocalKeyWrapper("k", make([]byte, 16)); err == nil {
		t.Fatal("accepted a 16-byte KEK")
	}
	if _, err := NewLocalKeyWrapper("", bytes.Repeat([]byte{0x11}, dekSize)); err == nil {
		t.Fatal("accepted an empty id")
	}
}

func TestSealSecretRoundTripAndTamper(t *testing.T) {
	dek := bytes.Repeat([]byte{0x33}, dekSize)
	aad := bindingAAD(recordVersion, "u", "p")
	plaintext := []byte("stoken")

	nonce, ct, err := sealSecret(dek, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openSecret(dek, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0xff
	if _, err := openSecret(dek, nonce, tampered, aad); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
}
