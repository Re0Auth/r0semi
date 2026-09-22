package safeurl

import "testing"

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
