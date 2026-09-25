package federation

import (
	"strings"
	"testing"
)

// A path that cleanRawPath accepts must be a safe relative path: no segment may
// begin with "..". That is the property the whole join rests on, so it is the one
// the fuzzer checks — a crafted input that slips an escaping segment through is a
// request to an endpoint the operator never configured.
func FuzzCleanRawPath(f *testing.F) {
	for _, s := range []string{
		"", "/", "a/b", "a//b", "/a/b", "a/../b", "..", "../..", "%2e%2e/x",
		"%252e%252e/x", "a/..;/b", `a\b`, "a/b?c=d", "a/b%00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		cleaned, err := cleanRawPath(raw)
		if err != nil {
			return
		}
		for _, seg := range strings.Split(cleaned, "/") {
			if strings.HasPrefix(seg, "..") {
				t.Fatalf("cleanRawPath(%q) = %q, which still has an escaping segment", raw, cleaned)
			}
		}
	})
}

// rejectEscapingPath guards a caller-supplied path, so its own robustness is part
// of the boundary: it must not panic on arbitrary input. A panic is a failed
// fuzz exec, which is the assertion.
func FuzzRejectEscapingPath(f *testing.F) {
	for _, s := range []string{"", "/", "..", "%2e%2e", `a\b`, "a/..;/b", "%"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_ = rejectEscapingPath(raw)
	})
}

// validateRawBase parses an operator-supplied base URL at startup; arbitrary
// bytes go through the same parser so a panic is a startup crash avoided rather
// than one discovered in a config.
func FuzzValidateRawBase(f *testing.F) {
	for _, s := range []string{"", "https://x.example", "http://", "://", "ftp://x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_ = validateRawBase(raw)
	})
}
