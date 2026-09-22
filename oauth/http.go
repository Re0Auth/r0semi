// HTTP-shaped pieces of RFC 6749 that more than one plane needs.
//
// They live here rather than being copied per plane because each is a rule from
// the spec rather than a local preference, and copies of a rule are copies that
// drift. One of them already had: see ClientCredentials.
package oauth

import (
	"net/http"
	"net/url"
)

// ClientCredentials reads a client's id and secret from a request, per RFC 6749
// §2.3.1: either `Authorization: Basic` or the `client_id` / `client_secret` form
// fields.
//
// # The part that is easy to get wrong
//
// The spec requires the id and secret to be **form-urlencoded before being placed
// in the Basic header**, so a server has to undo that. Go's Request.BasicAuth
// returns the base64-decoded values and stops there, and taking it at face value
// rejects every client whose secret contains a character the encoding touches —
// `+`, `/`, `=`, `%`, a space. That is most randomly generated secrets, so the
// failure looks like "the client's secret is wrong" for no reason anyone can see.
//
// The unescaping is best effort, and deliberately cannot fail: a value that is
// not valid form encoding is passed through unchanged so the comparison simply
// fails, rather than turning a wrong secret into a different kind of error. A
// client that never encoded is out of spec, and a secret containing a literal
// `+` will read back as a space — that is the spec's ambiguity, not ours, and
// encoding correctly is the client's side of it.
func ClientCredentials(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		return unescapeForm(u), unescapeForm(p)
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func unescapeForm(v string) string {
	if decoded, err := url.QueryUnescape(v); err == nil {
		return decoded
	}
	return v
}

// BuildRedirect returns redirectURI with params appended to its query, skipping
// empty values.
//
// It is how an authorization response or an error is delivered (RFC 6749 §4.1.2
// and §4.1.2.1). The redirect URI itself is not validated here: that happened
// when the request was accepted, against the client's registered list, and doing
// it a second time in a different place is how two answers to one question start
// to disagree.
func BuildRedirect(redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
