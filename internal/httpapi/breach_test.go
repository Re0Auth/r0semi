package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/oauth"
)

// BREACH needs three things at once: a response the server compresses, a secret
// in that response, and a value the attacker chose echoed into it. This service
// compresses the business plane (the protocol plane is excluded on purpose) and
// that plane hands the browser a CSRF token in a body, so the ingredient to guard
// is the third: no response on this plane may carry caller-supplied text back
// beside a secret.
//
// The check is deliberately independent of whether a given response happened to be
// compressed. The compression decision depends only on body size, so a field could
// cross the line the day a response grows past the 1 KiB threshold; asserting the
// invariant on every response catches that instead of waiting for the size to
// change. When a response is compressed it is decoded first, so the assertion is
// about the bytes a client would actually receive.
func TestBusinessResponsesNeverCarryASecretBesideEchoedInput(t *testing.T) {
	p := newBindEnvParts(t)
	signIn(t, p.client, p.base)

	// The CSRF token is the secret this plane actually hands a browser.
	csrf, _ := decodeResp(t, getURL(t, p.client, p.base+"/v1/sessions/current"))["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("the session view carried no CSRF token; the walk would be vacuous")
	}

	secrets := []string{csrf}
	// The session cookie must never appear in a body at all.
	base, err := url.Parse(p.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.client.Jar.Cookies(base) {
		secrets = append(secrets, c.Value)
	}
	// A bearer token, so the routes that take one are exercised authenticated and
	// the token itself is scanned for.
	uid, err := p.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	access := mintToken(t, p.handler, p.store, "cli", string(uid), oauth.ScopePhigrosProfile)
	secrets = append(secrets, access)

	const canary = "breachCanary7Q2"
	subst := strings.NewReplacer(
		"{game}", "phigros",
		"{resource}", "profile",
		"{source}", "fake",
		"{client_id}", "cli",
		"{path}", "x",
		"{id}", "req_1",
	)

	scanned, withSecret := 0, 0
	for _, rt := range p.api.specRoutes() {
		u, err := url.Parse(p.base + subst.Replace(rt.Pattern))
		if err != nil {
			t.Fatal(err)
		}
		// The canary goes in the query, a header and (for writes) the body — the
		// places a caller controls. Not the path: that is the resource identity, and
		// a problem body's `instance` legitimately echoes it.
		q := u.Query()
		q.Set("breach_canary", canary)
		u.RawQuery = q.Encode()

		var body io.Reader
		if rt.Method != http.MethodGet {
			body = bytes.NewReader([]byte(`{"breach_canary":"` + canary + `"}`))
		}
		req, err := http.NewRequest(rt.Method, u.String(), body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Breach-Canary", canary)
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Accept-Encoding", "gzip")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := p.client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", rt.Method, rt.Pattern, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		decoded := raw
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("%s %s declared gzip but did not encode gzip: %v", rt.Method, rt.Pattern, err)
			}
			if decoded, err = io.ReadAll(zr); err != nil {
				t.Fatal(err)
			}
		}
		scanned++

		text := string(decoded)
		carriesSecret := false
		for _, s := range secrets {
			if s != "" && strings.Contains(text, s) {
				carriesSecret = true
				break
			}
		}
		if carriesSecret {
			withSecret++
			if strings.Contains(text, canary) {
				t.Errorf("%s %s: a secret and the caller's own text (%q) are in one response — the BREACH precondition:\n%s",
					rt.Method, rt.Pattern, canary, text)
			}
		}
		// The compressed half spelled out: a compressed response that echoes
		// caller-supplied text is the other half of the precondition, whether or not
		// it currently carries a secret.
		if resp.Header.Get("Content-Encoding") != "" && strings.Contains(text, canary) {
			t.Errorf("%s %s: a compressed response echoed the caller's own text (%q)", rt.Method, rt.Pattern, canary)
		}
	}

	if scanned < 15 {
		t.Fatalf("only %d routes scanned; the walk is not reaching handlers", scanned)
	}
	if withSecret < 1 {
		t.Fatal("no response carried a secret; the walk proves nothing about BREACH")
	}
}
