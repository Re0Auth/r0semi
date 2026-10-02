package vault

import (
	"bytes"
	"testing"
)

func TestScrubClearsEveryByte(t *testing.T) {
	b := []byte("a session token that must not stay in memory")
	Scrub(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("Scrub left %q", b)
	}
}

func TestScrubToleratesNilAndEmpty(t *testing.T) {
	// Both are ordinary: a login that produced no credential, a zero-length
	// payload. Panicking on them would turn a cleanup path into a crash.
	check := func(name string, b []byte) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Scrub(%s) must be a no-op; it panicked: %v", name, r)
			}
		}()
		Scrub(b)
	}
	check("nil", nil)
	check("empty", []byte{})
}
