//go:build audit7

package z07authsessionlifecycle

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// describeConsent asks the business plane for the consent view of a handle.
func (b *browser) describeConsent(id string) (int, string) {
	b.t.Helper()
	resp := b.get("/v1/authorization_requests/" + url.PathEscape(id))
	return resp.StatusCode, bodyOf(b.t, resp)
}

// approveConsent records an approval and returns the redirect the browser is
// told to follow.
func (b *browser) approveConsent(id, csrf string) (int, string) {
	b.t.Helper()
	resp := b.do(http.MethodPost, "/v1/authorization_requests/"+url.PathEscape(id)+"/decision",
		`{"decision":"approve"}`,
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
	body := bodyOf(b.t, resp)
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return resp.StatusCode, out.RedirectTo
}

// TestZ07ExpiredPendingConsentHandleIsStillDescribable.
//
// The pending consent handle has a deadline: cmd/re0auth sets
// authorizationRequestTTL = 30m, and the store records it in
// authRequestExpiry / oidc_auth_requests.expires_at. The deadline is enforced
// only by the periodic janitor. The read the consent screen performs —
// storage.AuthRequestByID — carries no expiry predicate in either backend
// (internal/store/memory/oidc.go:402 vs :418, internal/store/postgres/oidc.go:207
// vs :220), so between the deadline and the next sweep the handle is still
// describable, and a stalled sweep (cmd/re0auth/main.go:1111 logs and proceeds)
// means it never expires at all.
//
// The three steps are the positive control, the finding, and the proof that the
// record really was past its deadline.
func TestZ07ExpiredPendingConsentHandleIsStillDescribable(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)

	id, _ := b.authorize("verifier-describe", "st-ttl")

	// Control: inside the lifetime the handle is describable, so the probe is
	// not satisfied by a plane that refuses everything.
	if code, body := b.describeConsent(id); code != http.StatusOK {
		t.Fatalf("describe inside the TTL = %d (%s), want 200", code, body)
	}

	env.clock.Advance(probeTTL + time.Minute)

	code, body := b.describeConsent(id)
	if code == http.StatusOK {
		t.Errorf("a consent handle %v past its %v deadline is still described as live: "+
			"GET /v1/authorization_requests/{id} = 200 (%s); AuthRequestByID has no expiry predicate, "+
			"so the only thing that ends the handle is the next sweep",
			probeTTL+time.Minute, probeTTL, body)
	} else {
		t.Logf("describe past the deadline = %d (%s)", code, body)
	}

	// Proof that the record was genuinely expired and not merely abandoned by the
	// fixture: the production janitor removes it, and only then does the read
	// refuse.
	removed := env.opStore.SweepExpired()
	if removed == 0 {
		t.Fatalf("the janitor removed nothing: the record was not past its deadline after all")
	}
	if code, body := b.describeConsent(id); code == http.StatusOK {
		t.Errorf("even the janitor's removal did not end the handle: %d (%s)", code, body)
	}
}

// TestZ07ExpiredPendingConsentHandleIsStillApprovable is the same deadline on the
// decision path, driven to the end: an approval of a handle far past its
// lifetime completes the login and mints an authorization code, i.e. tokens.
func TestZ07ExpiredPendingConsentHandleIsStillApprovable(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()

	id, _ := b.authorize("verifier-approve", "st-ttl-2")
	if code, body := b.describeConsent(id); code != http.StatusOK {
		t.Fatalf("describe inside the TTL = %d (%s), want 200", code, body)
	}

	// Far past the deadline — an hour beyond the configured 30 minutes.
	env.clock.Advance(probeTTL + time.Hour)

	code, redirect := b.approveConsent(id, csrf)
	if code != http.StatusOK || redirect == "" {
		t.Logf("approving the stale handle was refused: %d %q", code, redirect)
		return
	}
	t.Errorf("a consent handle %v past its %v deadline was approved and handed the browser a next URL (%s)",
		probeTTL+time.Hour, probeTTL, redirect)

	// Follow it: the OP completes the authorize request and returns a code to the
	// client, so the stale handle reaches real token issuance.
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("the approval returned an unparseable URL %q: %v", redirect, err)
	}
	resp := b.get(u.RequestURI())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the authorize callback = %d (%s), want 302", resp.StatusCode, bodyOf(t, resp))
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := cb.Query().Get("code"); got == "" {
		t.Errorf("no code was issued from the stale handle: %s", cb.String())
	} else {
		t.Logf("the stale handle produced an authorization code %s…", got[:8])
	}
}
