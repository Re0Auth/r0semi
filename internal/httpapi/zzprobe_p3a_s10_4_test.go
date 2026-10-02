package httpapi

// Probe for S10-4: business-plane responses that carry the session's CSRF token
// must not be compressed.
//
// Before the fix every success response on the business plane went through
// writeJSON and was eligible for compression, including the four that hand the
// browser a CSRF token. A compressed body carrying a secret beside text the caller
// influenced is the BREACH precondition, and the defence cannot be "the body is
// usually under the 1 KiB threshold": the threshold is crossed the day one of
// these responses grows, which is exactly what the inflated walk below arranges.
//
// The walk is paired so it cannot pass for the wrong reason: a token-FREE response
// of the same size class must still come back gzip-encoded, so "compression is
// broken for the whole plane" fails the control rather than passing the assertion.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/oauth"
)

// p3aNoTransform is the directive the response must carry; compression is skipped
// because of it (internal/compress.hasNoTransform).
const p3aNoTransform = "no-transform"

// p3aInflate links identities with long names to the signed-in account, so the
// per-account JSON bodies cross the compressor's 1 KiB threshold.
func p3aInflate(t *testing.T, env deleteEnv) {
	t.Helper()
	ctx := context.Background()
	uid, err := env.accounts.FindByIdentity(ctx, idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := env.accounts.LinkIdentity(ctx, uid, idp.Identity{
			Provider:    idp.GitHub,
			Subject:     fmt.Sprintf("p3a-probe-%d", i),
			DisplayName: strings.Repeat("n", 200),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// p3aGet sends a GET that demands gzip and returns the response together with the
// raw bytes on the wire. The header is set by hand, so Go's transport does not
// transparently decompress and the Content-Encoding is the server's own.
func p3aGet(t *testing.T, c *http.Client, target string, gzip bool) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gzip {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	resp := doReq(t, c, req)
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

// TestP3S10_4CSRFTokenResponseIsNotCompressed is the size-crossing half: the
// session bootstrap is inflated past the threshold and must still arrive
// unencoded, while the token-free account export — inflated by the same
// identities — must still arrive gzip-encoded.
func TestP3S10_4CSRFTokenResponseIsNotCompressed(t *testing.T) {
	env := newDeleteEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	p3aInflate(t, env)

	// Size first, uncompressed: without this the "not encoded" result below could
	// be the compressor's ordinary small-body skip rather than the fix.
	if _, raw := p3aGet(t, browser, env.base+"/v1/account/export", false); len(raw) <= 1024 {
		t.Fatalf("the export body is %d bytes; it must exceed the 1 KiB threshold for this probe to test anything", len(raw))
	}
	if _, raw := p3aGet(t, browser, env.base+"/v1/sessions/current", false); len(raw) <= 1024 {
		t.Fatalf("the session body is %d bytes; it must exceed the 1 KiB threshold for this probe to test anything", len(raw))
	}

	// Control: a token-free body of the same size class still compresses.
	resp, _ := p3aGet(t, browser, env.base+"/v1/account/export", true)
	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("control: /v1/account/export Content-Encoding = %q over %d bytes, want gzip; "+
			"compression is off for the whole plane, so the assertion below proves nothing",
			enc, resp.ContentLength)
	}

	// Target: the session bootstrap carries the CSRF token.
	resp, _ = p3aGet(t, browser, env.base+"/v1/sessions/current", true)
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("/v1/sessions/current Content-Encoding = %q, want none: a compressed body that "+
			"carries the CSRF token is the BREACH precondition (S10-4)", enc)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, p3aNoTransform) {
		t.Errorf("/v1/sessions/current Cache-Control = %q, want it to contain %q", cc, p3aNoTransform)
	}
}

// TestP3S10_4EveryCSRFResponseCarriesNoTransform reaches the other three handlers
// that emit a csrf_token through their real flows and asserts the directive that
// makes the compressor skip them. Their bodies are small today, so this is a
// header assertion rather than a compression one; the size-crossing proof above
// shows what the directive does when the body grows.
func TestP3S10_4EveryCSRFResponseCarriesNoTransform(t *testing.T) {
	t.Run("consent view", func(t *testing.T) {
		base, _ := newFlowEnv(t)
		browser := newBrowser(t)
		signIn(t, browser, base)

		handle := authorize(t, browser, base, strings.Repeat("a", 43), "account.id phigros.score.read", "st-s104")
		view := decodeResp(t, getURL(t, browser, base+"/v1/authorization_requests/"+handle))
		if view["csrf_token"] == "" {
			t.Fatalf("the consent view carried no CSRF token; the walk is vacuous: %v", view)
		}
		req, _ := http.NewRequest(http.MethodGet, base+"/v1/authorization_requests/"+handle, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp := doReq(t, browser, req)
		resp.Body.Close()
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, p3aNoTransform) {
			t.Errorf("GET /v1/authorization_requests/{id} Cache-Control = %q, want %q", cc, p3aNoTransform)
		}
	})

	t.Run("device verification view", func(t *testing.T) {
		base, _ := newFlowEnv(t)
		browser := newBrowser(t)

		start := decodeResp(t, postForm(t, browser, base+"/oauth/device_authorization", url.Values{
			"client_id": {"cli"}, "scope": {"account.id"},
		}))
		code, _ := start["user_code"].(string)
		if code == "" {
			t.Fatalf("device_authorization issued no user_code: %v", start)
		}
		signIn(t, browser, base)

		resp, raw := p3aGet(t, browser, base+"/v1/device/verification?user_code="+code, true)
		if !strings.Contains(string(raw), "csrf_token") {
			t.Fatalf("the verification view carried no CSRF token; the walk is vacuous: %s", raw)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, p3aNoTransform) {
			t.Errorf("GET /v1/device/verification Cache-Control = %q, want %q", cc, p3aNoTransform)
		}
	})

	t.Run("admin client list", func(t *testing.T) {
		env := newAdminEnv(t, true)
		browser := newBrowser(t)
		signIn(t, browser, env.base)

		// Enough clients that the body crosses the threshold, so this handler is
		// checked against a body the compressor would otherwise have encoded.
		ctx := context.Background()
		for i := 0; i < 40; i++ {
			extra, err := oauth.NewClient(
				fmt.Sprintf("p3a-%d", i), "P3A probe client with a name of some length",
				oauth.ClientPublic, "", []string{"https://app.example/cb"},
				[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile})
			if err != nil {
				t.Fatal(err)
			}
			if err := env.clients.Create(ctx, extra); err != nil {
				t.Fatal(err)
			}
		}

		if _, raw := p3aGet(t, browser, env.base+"/v1/admin/clients", false); len(raw) <= 1024 {
			t.Fatalf("the admin client list is %d bytes; it must exceed the threshold for this probe to test anything", len(raw))
		}
		resp, raw := p3aGet(t, browser, env.base+"/v1/admin/clients", true)
		if !strings.Contains(string(raw), "csrf_token") {
			t.Fatalf("the admin client list carried no CSRF token; the walk is vacuous: %s", raw)
		}
		if enc := resp.Header.Get("Content-Encoding"); enc != "" {
			t.Errorf("/v1/admin/clients Content-Encoding = %q, want none: it carries the CSRF token", enc)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, p3aNoTransform) {
			t.Errorf("/v1/admin/clients Cache-Control = %q, want %q", cc, p3aNoTransform)
		}
	})
}
