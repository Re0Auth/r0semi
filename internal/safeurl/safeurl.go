// Package safeurl holds the guards that keep a value taken from a request from
// being used as somewhere to send the browser.
//
// It is one package because it used to be two copies of the same function, and
// only one of them had a test behind it. That is the shape of the problem: a fix
// applied to one copy leaves the other one open, and nothing says so.
package safeurl

import (
	"net/url"
	"strings"
)

// RelativePath returns v if it is a same-origin absolute path, and "/" otherwise.
//
// "Same-origin absolute path" means: one leading slash and not two, no backslash,
// and no control byte. Everything else — an absolute URL, a scheme-relative
// "//host", an empty value, a Windows path — is replaced rather than rejected,
// because every caller is a redirect and the alternative to a safe value is an
// error page in the middle of a login.
//
// # Why it borrows url.Parse for one of the three rules
//
// The obvious check is the two string tests, and they are not enough. Browsers
// strip TAB, LF and CR from a URL **before** parsing it, so "/\t/evil.example" is
// a path by inspection and "//evil.example" — a different host — by the time
// anyone acts on it. `url.Parse` rejects control bytes outright, and that is
// knowledge worth using rather than re-deriving: it is the same reason this
// package exists instead of three copies of the same eight lines.
//
// What is deliberately *not* rejected: "..", spaces, and percent-encoded control
// bytes. None of them can move a redirection off the origin, because a path is
// not an authority and percent-encoding is not decoded into one.
func RelativePath(v string) string {
	if v == "" {
		// Two slashes are a scheme-relative reference: "//evil.example" names a
		// host. One slash is a path on this host.
		return "/"
	}
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return "/"
	}
	// Browsers treat a backslash as a separator in enough contexts that allowing
	// it means having to know which one is resolving. Refusing it is something a
	// reader can check.
	if strings.Contains(v, "\\") {
		return "/"
	}
	if _, err := url.Parse(v); err != nil {
		return "/"
	}
	return v
}
