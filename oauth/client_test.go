package oauth

import (
	"strings"
	"testing"
	"time"
)

// Registration is the only place the redirect policy is enforced. A URI that
// reaches the registry is what the authorize endpoint will redirect an
// authorization code to, so "does it parse and does it have a scheme" is not
// enough: it accepts http:// for a host nobody can protect and never rejects
// javascript:.
func TestNewClientValidatesRedirectURIs(t *testing.T) {
	accepted := []struct {
		name, uri string
	}{
		{"https anywhere", "https://app.example/cb"},
		{"https with a port", "https://app.example:8443/cb"},
		{"http on localhost", "http://localhost:8080/cb"},
		{"http on an IPv4 loopback", "http://127.0.0.1:1/cb"},
		{"http on the loopback range", "http://127.5.5.5/cb"},
		{"http on an IPv6 loopback", "http://[::1]:8080/cb"},
		{"private-use scheme with a path", "com.example.app:/callback"},
		{"private-use scheme with a host", "com.example.app://cb"},
		{"private-use scheme with an opaque target", "com.example.app:cb"},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			if _, err := NewClient("cli", "App", ClientPublic, "", []string{tc.uri}, nil); err != nil {
				t.Fatalf("NewClient(%q) = %v, want it accepted", tc.uri, err)
			}
		})
	}

	rejected := []struct {
		name, uri, want string
	}{
		{"no scheme", "app/cb", "no scheme"},
		{"empty", "", "no scheme"},
		{"a fragment", "https://app.example/cb#frag", "fragment"},
		{"userinfo", "https://user:pw@app.example/cb", "userinfo"},
		{"plain http off loopback", "http://evil.example/cb", "loopback"},
		{"plain http on a private address", "http://10.0.0.1/cb", "loopback"},
		{"javascript", "javascript:alert(1)", "never a redirect target"},
		{"data", "data:text/html,<script>", "never a redirect target"},
		{"file", "file:///etc/passwd", "never a redirect target"},
		{"another scheme entirely", "ftp://app.example/cb", "reverse-DNS"},
		{"a scheme with no dot", "myapp:/cb", "reverse-DNS"},
		{"a private-use scheme with no target", "com.example.app:", "names no target"},
	}
	for _, tc := range rejected {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			_, err := NewClient("cli", "App", ClientPublic, "", []string{tc.uri}, nil)
			if err == nil {
				t.Fatalf("NewClient(%q) accepted a URI it must refuse", tc.uri)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Every URI in a registration is checked, not just the first: a client with one
// good entry and one bad one is a client whose worst entry is reachable.
func TestNewClientValidatesEveryRedirectURI(t *testing.T) {
	_, err := NewClient("cli", "App", ClientPublic, "",
		[]string{"https://app.example/cb", "javascript:alert(1)"}, nil)
	if err == nil {
		t.Fatal("a good entry let a bad one through")
	}
}

// Restoring is deliberately exempt: a URI already in the registry was accepted
// under the policy in force when it was written, and rejecting it here would turn
// a tightened rule into a deployment that cannot start.
func TestRestoreClientDoesNotRevalidateRedirectURIs(t *testing.T) {
	got, err := RestoreClient("cli", "App", ClientConfidential, NewSecretHash("s"),
		[]string{"http://legacy.example/cb"}, []Scope{ScopeAccountID}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("RestoreClient rejected a stored redirect URI: %v", err)
	}
	if !got.AllowsRedirect("http://legacy.example/cb") {
		t.Fatal("the restored client lost its redirect URI")
	}
}

// KIT-6: a row an older policy admitted is still not usable as a redirect.
// RestoreClient keeps the URI — a tightened registration rule must not turn into
// a deployment that cannot start — but nothing may be redirected to a scheme a
// document interpreter runs, and the authorize path has no second check of its
// own.
func TestARestoredForbiddenSchemeRedirectIsNeverUsable(t *testing.T) {
	c, err := RestoreClient("cli", "App", ClientPublic, nil,
		[]string{"javascript:alert(1)", "data:text/html,<script>1</script>", "https://app.example/cb"},
		nil, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("RestoreClient rejected a stored redirect URI: %v", err)
	}
	for _, bad := range []string{"javascript:alert(1)", "data:text/html,<script>1</script>"} {
		if c.AllowsRedirect(bad) {
			t.Errorf("AllowsRedirect(%q) = true: a forbidden scheme is never a redirect target", bad)
		}
		if got := c.RegisteredRedirect(bad); got != "" {
			t.Errorf("RegisteredRedirect(%q) = %q, want \"\"", bad, got)
		}
	}
	// The usable entry is unaffected: this is a scheme check, not a refusal of
	// restored clients.
	if !c.AllowsRedirect("https://app.example/cb") {
		t.Error("the https entry stopped working")
	}
}

// RegisteredRedirect is the value half of AllowsRedirect, and the difference is
// the point: a caller that redirects must send the URI the client registered, not
// the string the request carried. The two are equal whenever the check passes, so
// the property to pin is what a NEAR-miss resolves to — nothing, never the closest
// entry — because an exact match is the only thing that may reach a Location.
func TestRegisteredRedirectReturnsOnlyAnExactMatch(t *testing.T) {
	c, err := NewClient("cli", "App", ClientPublic, "",
		[]string{"https://app.example/cb", "https://app.example/other"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, uri := range []string{"https://app.example/cb", "https://app.example/other"} {
		if got := c.RegisteredRedirect(uri); got != uri {
			t.Fatalf("RegisteredRedirect(%q) = %q, want the registered URI", uri, got)
		}
	}

	for _, near := range []string{
		"https://app.example/cb/",           // a trailing slash
		"https://APP.example/cb",            // different case
		"https://app.example/cb?x=1",        // an appended query
		"https://app.example/",              // a prefix of a registered URI
		"https://app.example/cb/../../evil", // resolves elsewhere
		"javascript:alert(1)",
		"",
	} {
		if got := c.RegisteredRedirect(near); got != "" {
			t.Errorf("RegisteredRedirect(%q) = %q, want \"\" — only an exact match may be used", near, got)
		}
	}
}
