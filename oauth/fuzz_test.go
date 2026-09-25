package oauth

import "testing"

// BuildRedirect assembles the redirect whose query carries the authorization
// response; it takes a caller-supplied redirect URI and state. The fuzzer drives
// arbitrary values so an encoding mistake that panics is caught here rather than
// on the wire.
func FuzzBuildRedirect(f *testing.F) {
	f.Add("https://app.example/cb", "s", "c")
	f.Add("https://app.example/cb?x=1", "s", "c")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, uri, state, code string) {
		_ = BuildRedirect(uri, map[string]string{"state": state, "code": code})
	})
}
