package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// recordVersion is folded into the AAD so that a future format change
	// cannot be confused with the current one.
	recordVersion byte = 1

	dekSize   = 32 // AES-256
	nonceSize = 12 // standard GCM nonce
)

// KeyWrapper is the KEK boundary.
//
// It wraps and unwraps per-credential data encryption keys (DEKs) without ever
// revealing the key encryption key (KEK). Implementations may be in-process
// (development), a cloud KMS, or an HSM. The AAD is the credential identity; a
// wrapper must bind it so that a wrapped DEK cannot be moved between
// credentials.
type KeyWrapper interface {
	KeyID() string
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// LocalKeyWrapper is an in-process AES-256-GCM KeyWrapper.
//
// It is what every deployment currently uses, and what it gives is narrower than
// "in production use a KMS" makes it sound:
//
//   - A dump of the database alone cannot be decrypted, because the KEK is not in
//     it. That is the property the envelope design exists for, and it holds.
//   - A leak of the KEK itself — the environment variable, a memory dump, a
//     compromised process — exposes everything that KEK wrapped, present and
//     future. Rotating the KEK bounds that to "whatever existed when it leaked",
//     and nothing local can undo the rest.
//
// A KMS-backed KeyWrapper would keep the key material out of the process and make
// every unwrap auditable and revocable. It would **not** stop a compromised
// process from decrypting, because that process can ask the KMS in its own name —
// a claim this comment used to make, and one not worth repeating.
type LocalKeyWrapper struct {
	id   string
	aead cipher.AEAD
}

// NewLocalKeyWrapper builds a wrapper from a 32-byte KEK.
func NewLocalKeyWrapper(id string, kek []byte) (*LocalKeyWrapper, error) {
	if id == "" {
		return nil, errors.New("vault: KeyWrapper id is required")
	}
	if len(kek) != dekSize {
		return nil, fmt.Errorf("vault: KEK must be %d bytes, got %d", dekSize, len(kek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("vault: KEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: KEK: %w", err)
	}
	return &LocalKeyWrapper{id: id, aead: aead}, nil
}

// KeyID implements KeyWrapper.
func (w *LocalKeyWrapper) KeyID() string { return w.id }

// Wrap implements KeyWrapper.
func (w *LocalKeyWrapper) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	nonce, ct, err := w.seal(dek, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// Unwrap implements KeyWrapper.
func (w *LocalKeyWrapper) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < nonceSize {
		return nil, errors.New("vault: wrapped DEK is too short")
	}
	return w.open(wrapped[:nonceSize], wrapped[nonceSize:], aad)
}

func (w *LocalKeyWrapper) seal(plaintext, aad []byte) (nonce, ct []byte, err error) {
	nonce = make([]byte, w.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, w.aead.Seal(nil, nonce, plaintext, aad), nil
}

func (w *LocalKeyWrapper) open(nonce, ct, aad []byte) ([]byte, error) {
	pt, err := w.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: open wrapped DEK: %w", err)
	}
	return pt, nil
}

// bindingAAD encodes the credential identity unambiguously. Length prefixes
// make "a" + "bc" differ from "ab" + "c".
func bindingAAD(version byte, subject, provider string) []byte {
	b := make([]byte, 0, 1+4+len(subject)+4+len(provider))
	b = append(b, version)
	b = binary.BigEndian.AppendUint32(b, uint32(len(subject)))
	b = append(b, subject...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(provider)))
	b = append(b, provider...)
	return b
}

// sealSecret encrypts plaintext under dek, returning the nonce and ciphertext
// separately.
func sealSecret(dek, plaintext, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: DEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: DEK: %w", err)
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// openSecret reverses sealSecret.
func openSecret(dek, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("vault: DEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: DEK: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt credential: %w", err)
	}
	return pt, nil
}

// zeroize overwrites b and keeps it alive until the write is observed, so the
// compiler cannot elide the clearing of a dead buffer.
//
//go:noinline

func readRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func fillRandom(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}
