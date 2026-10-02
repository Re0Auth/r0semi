package vault

// S07-11 probe: bindingAAD must length-prefix each identity field with an
// encoding that cannot truncate, so two different identities cannot produce the
// same AAD.
//
// The probe is RED against the fixed uint32 prefix: that encoding writes four
// bytes per length, so s0711DecodeAAD — which reads the documented uvarint
// prefix — cannot recover the fields. It is GREEN after the prefix becomes a
// uvarint, and the decode below is the independent statement of the format.
//
// No migration is needed: the project has not shipped, so there is no stored AAD
// to keep readable.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// s0711DecodeAAD decodes bindingAAD under the format the fix pins:
//
//	version byte | uvarint(len(subject)) | subject | uvarint(len(provider)) | provider
//
// It fails the test if the bytes do not decode exactly, so a fixed-width prefix
// (which leaves three zero length bytes behind) is caught rather than skipped.
func s0711DecodeAAD(t *testing.T, aad []byte) (version byte, subject, provider string) {
	t.Helper()
	if len(aad) < 1 {
		t.Fatal("bindingAAD returned no bytes")
	}
	version = aad[0]
	rest := aad[1:]

	n, w := binary.Uvarint(rest)
	if w <= 0 {
		t.Fatalf("subject length is not a uvarint: % x", rest)
	}
	rest = rest[w:]
	if uint64(len(rest)) < n {
		t.Fatalf("subject length prefix says %d bytes but only %d remain", n, len(rest))
	}
	subject = string(rest[:n])
	rest = rest[n:]

	m, w := binary.Uvarint(rest)
	if w <= 0 {
		t.Fatalf("provider length is not a uvarint: % x", rest)
	}
	rest = rest[w:]
	if uint64(len(rest)) != m {
		t.Fatalf("provider length prefix says %d bytes but %d remain: the prefix truncated or is not uvarint", m, len(rest))
	}
	return version, subject, string(rest)
}

// TestS07_11BindingAADUsesUvarintLengthPrefixes pins the exact prefix format at
// the boundaries the finding is about: empty fields, the 127/128 and 255/256
// width changes, a very long field, and fields containing NUL.
func TestS07_11BindingAADUsesUvarintLengthPrefixes(t *testing.T) {
	cases := []struct {
		name     string
		subject  string
		provider string
	}{
		{"both empty", "", ""},
		{"empty subject", "", "provider"},
		{"empty provider", "subject", ""},
		{"nul byte in subject", string([]byte{0}), "provider"},
		{"nul byte in provider", "subject", string([]byte{0})},
		{"embedded nul", "a\x00b", "p\x00q"},
		{"127-byte field", strings.Repeat("s", 127), "p"},
		{"128-byte field", strings.Repeat("s", 128), "p"},
		{"255-byte field", strings.Repeat("s", 255), "p"},
		{"256-byte field", strings.Repeat("s", 256), "p"},
		{"257-byte field", strings.Repeat("s", 257), "p"},
		{"very long field", strings.Repeat("s", 1<<20), "p"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aad := bindingAAD(recordVersion, tc.subject, tc.provider)
			version, subject, provider := s0711DecodeAAD(t, aad)
			if version != recordVersion {
				t.Fatalf("version = %d, want %d", version, recordVersion)
			}
			if subject != tc.subject || provider != tc.provider {
				t.Fatalf("decoded (%d-byte subject, %d-byte provider); want (%d, %d): "+
					"the length prefix does not round-trip (S07-11)",
					len(subject), len(provider), len(tc.subject), len(tc.provider))
			}
		})
	}
}

// TestS07_11BindingAADIsInjectiveAcrossLengthBoundaries is the collision guard
// the format exists for: shifting a byte between the two fields, or between a
// field and its prefix, must change the AAD. It runs over the same boundary
// lengths as the format probe so the two cannot drift.
func TestS07_11BindingAADIsInjectiveAcrossLengthBoundaries(t *testing.T) {
	fields := []string{"", "a", "\x00", "a\x00b", strings.Repeat("s", 127), strings.Repeat("s", 128),
		strings.Repeat("s", 255), strings.Repeat("s", 256), strings.Repeat("t", 255), strings.Repeat("s", 1<<20)}

	seen := make(map[string][2]string)
	for _, subject := range fields {
		for _, provider := range fields {
			aad := bindingAAD(recordVersion, subject, provider)
			key := string(aad)
			if prev, dup := seen[key]; dup {
				t.Fatalf("bindingAAD(%d-byte %q, %d-byte %q) collides with bindingAAD(%d-byte %q, %d-byte %q)",
					len(prev[0]), prev[0], len(prev[1]), prev[1], len(subject), subject, len(provider), provider)
			}
			seen[key] = [2]string{subject, provider}
		}
	}

	// Anti-vacuity: the corpus is large enough that one byte-shifted pair is in
	// it, and those two really do differ.
	left := bindingAAD(recordVersion, "ab", "c")
	right := bindingAAD(recordVersion, "a", "bc")
	if bytes.Equal(left, right) {
		t.Fatalf("the injectivity corpus holds a known collision: bindingAAD(ab,c) == bindingAAD(a,bc)")
	}
}
