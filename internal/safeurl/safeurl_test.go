package safeurl

import (
	"strings"
	"testing"
)

func TestRelativePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
		why  string
	}{
		{"empty", "", "/", "nothing to go back to"},

		// Somewhere else entirely.
		{"absolute", "https://evil.example/cb", "/", "a full URL has its own host"},
		{"scheme relative", "//evil.example", "/", "// is an authority, not a path"},
		{"four slashes", "////evil.example", "/", "still starts with //"},
		{"scheme", "javascript:alert(1)", "/", "no leading slash, and a scheme"},

		// A path by inspection, a host by the time a browser acts on it.
		{"tab", "/\t/evil.example", "/", "browsers strip TAB before parsing, so this becomes //evil.example"},
		{"carriage return", "/\r/evil.example", "/", "same, for CR"},
		{"line feed", "/\n/evil.example", "/", "same, for LF"},
		{"delete", "/\x7f/evil.example", "/", "a control byte"},

		// Backslash: a separator to some resolvers, a path byte to others.
		{"backslash prefix", "/\\evil.example", "/", "some resolvers read this as //evil.example"},
		{"backslash alone", "\\/evil.example", "/", "and some read this as /"},
		{"backslash middle", "/app\\..\\evil", "/", "no reason to allow it anywhere"},

		// Legitimate values, unchanged. A guard that broke these would be worse
		// than the bug it fixes.
		{"simple path", "/app/sources", "/app/sources", ""},
		{"with query", "/app/sources?tab=1", "/app/sources?tab=1", ""},
		{"with fragment", "/app/sources#top", "/app/sources#top", ""},
		{"root", "/", "/", ""},
		{"dots", "/../..", "/../..", "a path cannot become an authority"},
		{"encoded control byte", "/%09/evil.example", "/%09/evil.example",
			"percent-encoding is not a control byte and is never decoded into an authority"},
		{"space", "/a b", "/a b", ""},
		{"unicode", "/游戏", "/游戏", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RelativePath(tc.in)
			if got != tc.want {
				t.Errorf("RelativePath(%q) = %q, want %q — %s", tc.in, got, tc.want, tc.why)
			}
		})
	}
}

// A navigation target is not a data channel: a value too large to be one is
// replaced, so a caller that persists the result (the auth flow writes it into
// the session) cannot be made to carry caller-priced bytes.
func TestRelativePathBoundsLength(t *testing.T) {
	atCap := "/" + strings.Repeat("a", MaxRelativePathBytes-1)
	if got := RelativePath(atCap); got != atCap {
		t.Errorf("RelativePath(at the %d-byte cap) was replaced; the cap is too tight", MaxRelativePathBytes)
	}
	over := "/" + strings.Repeat("a", MaxRelativePathBytes)
	if got := RelativePath(over); got != "/" {
		t.Errorf("RelativePath(%d bytes) = %.32q…, want %q", len(over), got, "/")
	}
	// The check is on the whole value, so a short path followed by a huge query
	// is bounded too.
	longQuery := "/app/sources?x=" + strings.Repeat("a", 4<<10)
	if got := RelativePath(longQuery); got != "/" {
		t.Errorf("RelativePath(%d bytes with a long query) was kept", len(longQuery))
	}
}
