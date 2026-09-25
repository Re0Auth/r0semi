package oauth

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// The spec's encoding rule, from the client's side: it form-urlencodes before
// putting the value in the header. This is the case that a naive server gets
// wrong, and it is the common case for generated secrets.
func TestClientCredentialsUndoesFormEncoding(t *testing.T) {
	// Every character the encoding touches, in one secret.
	const secret = "s+cr/et= %"
	const id = "cli+ent"

	header := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	req.Header.Set("Authorization", header)

	gotID, gotSecret := ClientCredentials(req)
	if gotID != id || gotSecret != secret {
		t.Fatalf("read (%q, %q), want (%q, %q)", gotID, gotSecret, id, secret)
	}
}

// A secret with nothing to encode must be unaffected, because that is what nearly
// every test and most deployments use, and a fix that broke it would be worse
// than the bug.
func TestClientCredentialsLeavesPlainValuesAlone(t *testing.T) {
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("cli:sec"))
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	req.Header.Set("Authorization", header)

	if id, secret := ClientCredentials(req); id != "cli" || secret != "sec" {
		t.Fatalf("read (%q, %q)", id, secret)
	}
}

func TestClientCredentialsFallsBackToTheForm(t *testing.T) {
	req := httptest.NewRequest("POST", "/oauth/token",
		// client_secret holds a literal '+', which is how a form field carries
		// one; the body is not the header and is not double-encoded.
		strings.NewReader("client_id=cli&client_secret=s%2Bcr"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if id, secret := ClientCredentials(req); id != "cli" || secret != "s+cr" {
		t.Fatalf("read (%q, %q)", id, secret)
	}
}

// A value that is not valid form encoding is passed through so the comparison
// fails, rather than becoming a different error than "wrong secret".
func TestClientCredentialsToleratesMalformedEncoding(t *testing.T) {
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("cli:100%secret"))
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	req.Header.Set("Authorization", header)

	if _, secret := ClientCredentials(req); secret != "100%secret" {
		t.Fatalf("secret = %q", secret)
	}
}

// No credentials at all is (empty, empty), not an error: callers decide what a
// missing client means.
func TestClientCredentialsWithNothingPresent(t *testing.T) {
	req := httptest.NewRequest("POST", "/oauth/token", nil)
	if id, secret := ClientCredentials(req); id != "" || secret != "" {
		t.Fatalf("read (%q, %q)", id, secret)
	}
}

func TestBuildRedirectAppendsAndSkipsEmpty(t *testing.T) {
	got := BuildRedirect("https://app.example/cb?existing=1", map[string]string{
		"code":  "abc",
		"state": "xyz",
		"error": "",
	})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("existing") != "1" || q.Get("code") != "abc" || q.Get("state") != "xyz" {
		t.Fatalf("query = %v", q)
	}
	if _, present := q["error"]; present {
		t.Fatalf("an empty parameter was written: %v", q)
	}
}

func TestBearerTokenReadsTheCredential(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"Bearer abc123", "abc123"},
		// RFC 7235: the scheme is case-insensitive.
		{"bearer abc123", "abc123"},
		{"BEARER abc123", "abc123"},
		// The space after the scheme is grammar, so extra whitespace around the
		// token is not part of the credential.
		{"Bearer   abc123  ", "abc123"},
		// Another scheme is not a bearer token, and neither is an empty one.
		{"Basic dXNlcjpwYXNz", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
		{"", ""},
	} {
		req := httptest.NewRequest("GET", "/v1/me", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		if got := BearerToken(req); got != tc.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestParseScopesSplitsOnWhitespace(t *testing.T) {
	got := ParseScopes("account.id  phigros.score.read\topenid")
	want := []Scope{"account.id", "phigros.score.read", "openid"}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseScopes = %v, want %v", got, want)
	}
	// No scopes at all is nil, not one empty scope: a caller that ranges over the
	// result must not see a scope the client never asked for.
	if got := ParseScopes(""); got != nil {
		t.Fatalf("ParseScopes(%q) = %v, want nil", "", got)
	}
}
