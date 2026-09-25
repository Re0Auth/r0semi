// HTTP-shaped pieces of RFC 6749 that more than one plane needs.
//
// They live here rather than being copied per plane because each is a rule from
// the spec rather than a local preference, and copies of a rule are copies that
// drift. One of them already had: see ClientCredentials.
package oauth

import (
	"net/http"
	"net/url"
	"strings"
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

// BearerToken reads the credential from an `Authorization: Bearer` header, per
// RFC 6750 §2.1. It returns "" when the header is absent or names another
// scheme, which is what lets a caller answer 401 with a challenge.
//
// The scheme is matched case-insensitively because RFC 7235 defines it that way,
// and the value is trimmed because the single space after the scheme is part of
// the grammar rather than of the token.
func BearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// ParseScopes splits a scope value into its members, per RFC 6749 §3.3: a
// space-delimited list, where a blank value means "no scopes" rather than one
// empty scope.
//
// It does not validate. Whether a scope is known, and whether the requesting
// client may ask for it, is Registry.Resolve's question — and answering it here
// would give the parse and the policy two places to disagree.
func ParseScopes(s string) []Scope {
	if s == "" {
		return nil
	}
	fields := strings.Fields(s)
	out := make([]Scope, len(fields))
	for i, f := range fields {
		out[i] = Scope(f)
	}
	return out
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
