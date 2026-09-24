// Guards for the findings of the second adversarial audit (docs/security-audit-2.md).
//
// Each of these failed before its fix and passes now. They live together so the
// audit and its guards stay in one place, and each test names the finding it pins.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Finding A6-1: a 32-byte key supplied as HEX is always rejected.
//
// decodeKEK tries base64 first, and 64 hex characters are also valid base64 — so
// the input decodes to 48 bytes, the length check refuses it, and the hex branch
// below it is dead code. The process still fails closed, but the operator is told
// the KEY is the wrong size when the problem is the FORMAT, and the obvious
// remedy (generate a new key) silently makes every stored credential unreadable.
func TestAdversarialHexKeyIsAccepted(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}

	hexKey := hex.EncodeToString(raw) // 64 chars: valid hex AND valid base64
	got, err := decodeKEK32(hexKey)
	if err != nil {
		t.Fatalf("a 32-byte hex key was rejected: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("decoded to %d bytes, want 32", len(got))
	}

	// The documented formats must all work.
	if _, err := decodeKEK32(base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Errorf("standard base64 rejected: %v", err)
	}
	if _, err := decodeKEK32(base64.RawStdEncoding.EncodeToString(raw)); err != nil {
		t.Errorf("raw base64 rejected: %v", err)
	}
}
