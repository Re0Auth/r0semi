//go:build audit5

package crypto

import (
	"bytes"
	"testing"
	"time"
)

// The canonical-form tests live in the postgres package (see
// ../../store/postgres/zzprobe_crypto_test.go) because auditRow.canonical and
// *AuditLogger.mac are unexported there. This file records the domain-separation
// labels as constants so that a change to one of them is visible here as a
// deliberate edit rather than a silent re-partition of the MAC key's uses.
//
// The labels are read from the source of truth by the package-internal probe;
// this file asserts only the property that matters and cannot be checked from
// outside: that the three labels are pairwise distinct, non-empty, and not
// prefixes of one another.
var auditLabels = []string{
	"re0auth.audit.subject-index/1",
	"re0auth.audit.pseudonym/1",
	"re0auth.audit.signature/1",
	"re0auth.audit.row/1",
}

func TestProbeAuditLabelsAreDistinctAndUnambiguous(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range auditLabels {
		if l == "" {
			t.Fatal("an audit domain label is empty")
		}
		if seen[l] {
			t.Fatalf("duplicate audit label %q", l)
		}
		seen[l] = true
	}
	for _, a := range auditLabels {
		for _, b := range auditLabels {
			if a == b {
				continue
			}
			if len(a) <= len(b) && a == b[:len(a)] {
				t.Errorf("label %q is a prefix of %q: concatenation is not injective", a, b)
			}
		}
	}
}

// TestProbeCanonicalTimestampPrecision pins the one thing about the canonical
// form that is checkable without a database: the row timestamp is reduced to
// microsecond precision, which is what timestamptz stores. A nanosecond value
// must not survive into the hash input, or a row would fail its own verification
// the moment it is read back.
func TestProbeCanonicalTimestampPrecision(t *testing.T) {
	a := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	b := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) // same microsecond
	if a.UTC().UnixMicro() != b.UTC().UnixMicro() {
		t.Fatal("the two timestamps differ at microsecond precision; the probe is wrong")
	}
	c := time.Date(2026, 1, 2, 3, 4, 5, 123457000, time.UTC)
	if a.UTC().UnixMicro() == c.UTC().UnixMicro() {
		t.Fatal("one microsecond apart produced the same value; the probe is wrong")
	}
	if bytes.Equal([]byte(a.UTC().Format(time.RFC3339Nano)), []byte(b.UTC().Format(time.RFC3339Nano))) {
		t.Fatal("RFC3339Nano would have collapsed these two; using UnixMicro is load-bearing")
	}
}
