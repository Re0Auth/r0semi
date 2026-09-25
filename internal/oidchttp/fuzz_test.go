package oidchttp

import (
	"net/url"
	"strings"
	"testing"
)

// These functions parse attacker-influenced bytes: discovery documents, token
// responses and introspection results come from upstream providers, and the OAuth
// error code is echoed into responses and metrics. The fuzzer's job is
// crash-safety — a panic in any of them is a 500 on the protocol plane — and the
// seed corpus carries the shapes seen in practice. A panic is a failed fuzz exec,
// which is the assertion.
func FuzzTokenErrorCode(f *testing.F) {
	f.Add([]byte(`{"error":"invalid_grant"}`), 400)
	f.Add([]byte(`{"error":"invalid_request","error_description":"x"}`), 400)
	f.Add([]byte(`not json`), 500)
	f.Add([]byte(``), 200)
	f.Fuzz(func(t *testing.T, body []byte, status int) {
		_ = tokenErrorCode(body, status)
	})
}

func FuzzIsOAuthErrorBody(f *testing.F) {
	f.Add("application/json", []byte(`{"error":"invalid_grant"}`))
	f.Add("text/html", []byte(`<html></html>`))
	f.Add("", []byte{})
	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		_ = isOAuthErrorBody(contentType, body)
	})
}

func FuzzStripUnsupportedDiscoveryFields(f *testing.F) {
	f.Add([]byte(`{"issuer":"https://x","dpop_signing_alg_values_supported":["ES256"]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_ = stripUnsupportedDiscoveryFields(body)
	})
}

func FuzzValidPKCEValue(f *testing.F) {
	for _, s := range []string{"", "abc", "a-b._~", "a b", "a\x00b", strings.Repeat("a", 200)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = validPKCEValue(s)
	})
}

func FuzzDuplicatedParam(f *testing.F) {
	f.Add("a", "b")
	f.Fuzz(func(t *testing.T, k, v string) {
		values := url.Values{}
		values.Set(k, v)
		values.Add(k, v) // force a duplicate so the function has something to find
		_ = duplicatedParam(values)
	})
}
