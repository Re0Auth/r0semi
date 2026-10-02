package federation

import (
	"strings"
	"testing"
)

// TestValidateSourceNameLengthIsBounded is the default-build guard for the
// length half of validateSourceName (22-2).
//
// Before it, a path-safe name of any length was accepted: a 4096-byte
// source name passed the charset rule and was then joined into the bind callback
// path, the vault identity and the registry key verbatim. The values below are
// all-'a', so the charset rule is satisfied by construction and the only
// possible reason for a refusal is the length — an over-long name cannot pass by
// being rejected for some other cause, and a firm refusal at the boundary is what
// this pins.
func TestValidateSourceNameLengthIsBounded(t *testing.T) {
	if err := validateSourceName("name", strings.Repeat("a", maxSourceNameBytes)); err != nil {
		t.Errorf("a name exactly at the %d-byte cap was refused: %v", maxSourceNameBytes, err)
	}
	for _, n := range []int{maxSourceNameBytes + 1, 4096} {
		value := strings.Repeat("a", n)
		err := validateSourceName("name", value)
		if err == nil {
			t.Errorf("validateSourceName accepted a %d-byte name (cap %d): the value is joined into a URL "+
				"path, a vault identity and the registry key, so it is bounded rather than carried",
				n, maxSourceNameBytes)
			continue
		}
		// The refusal must be about the length, not the characters: all-'a' is
		// inside the charset. Matching the limit keeps this from passing on a
		// message that says something else.
		if !strings.Contains(err.Error(), "byte") {
			t.Errorf("the %d-byte name was refused with %q, which does not name the length limit", n, err)
		}
	}
}

// TestNewRegistryRefusesOverLongNames drives the same cap through NewRegistry,
// for the three values it validates: the game, the source name and a declared
// resource name.
func TestNewRegistryRefusesOverLongNames(t *testing.T) {
	overLong := strings.Repeat("a", maxSourceNameBytes+1)

	// Positive control: the same shape with a short name is accepted, so the
	// refusals below are about the length and not a registry that refuses
	// everything.
	if _, err := NewRegistry(Source{
		Game: "phigros", Name: "src", Issuer: "https://api.example",
		Resources: []Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	}); err != nil {
		t.Fatalf("NewRegistry refused a well-formed source: %v", err)
	}

	cases := []struct {
		name string
		src  Source
	}{
		{"source name", Source{Game: "phigros", Name: overLong, Issuer: "https://api.example"}},
		{"game", Source{Game: overLong, Name: "src", Issuer: "https://api.example"}},
		{"resource name", Source{
			Game: "phigros", Name: "src", Issuer: "https://api.example",
			Resources: []Resource{{Name: overLong, Scope: "phigros.profile.read"}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewRegistry(c.src); err == nil {
				t.Errorf("NewRegistry accepted an over-long %s (%d bytes, cap %d)", c.name, len(overLong), maxSourceNameBytes)
			}
		})
	}
}
