package idp

import "testing"

// stripJSONP unwraps a JSONP response from a provider's userinfo endpoint; the
// body is the provider's, so it is attacker-influenced by a compromised or
// hostile IdP. Crash-safety is the property under test.
func FuzzStripJSONP(f *testing.F) {
	for _, s := range []string{"", "{}", `callback({})`, `callback(")");`, "cb(", "()", "cb(  )"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = stripJSONP(s)
	})
}
