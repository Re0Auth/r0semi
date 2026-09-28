//go:build audit5

package zzprobe_federationhttp

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// The dedicated guard for P1-5, on the real HTTP surface: the scope gate and the
// read it guards must be the same decision.
//
// The finding: `handleGameResource` resolved the required scope with
// `federation.ResourceScope(game, resource)` — the FIRST source, in config-name
// order, that declares the resource — while `Fetch` picked a source by binding and
// status. Measured with two sources of one game, a token minted for the official
// source's scope (the only scope its client was registered for) was served the
// COMMUNITY source's copy of the same resource name.
//
// Both directions were wrong, which is what makes it a real defect rather than a
// conservative one: it admitted a source's data under another source's scope, and
// it refused a token holding the scope of the source that actually served.
//
// The gate now asks the federation service for EVERY source that could serve the
// read and requires all of their scopes, so the decision precedes the read and the
// refusal names the source whose scope is missing.
func TestZZProbeScopeGateJudgesByTheServingSource(t *testing.T) {
	base, at, asked, mint := zzTwoSourceHTTP(t)

	get := func(target, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// The token holds the OFFICIAL source's scope. The source that can serve the
	// read is the community one, the only one this user is bound to.
	status, body := get("/v1/games/phigros/profile", at)
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403: a token holding only the official source's scope must not read "+
			"another source's copy of the resource (body: %s)", status, body)
	}
	for _, want := range []string{"phigros.community.read", "zz-community"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not name %q, so it does not tell the caller whose scope is missing: %s", want, body)
		}
	}

	// Pinning the source does not loosen the criterion: it narrows it to the pinned
	// source, whose scope is the community one.
	if status, body := get("/v1/games/phigros/profile?source=zz-community", at); status != http.StatusForbidden {
		t.Errorf("pinned to the community source, status = %d, want 403 (body: %s)", status, body)
	}

	// And a token holding the PINNED source's own scope is admitted by the gate —
	// the other direction the old criterion got wrong. The request stops at the next
	// layer (409: nothing is bound to that source), which is the point: a 403 here
	// would mean the gate refused a token that holds what the source requires.
	if status, body := get("/v1/games/phigros/profile?source=aa-official", mint("phigros.profile.read")); status == http.StatusForbidden {
		t.Errorf("the gate refused a token holding the pinned source's own scope: %s", body)
	}

	// Nothing above reached an upstream: the decision is made before the read, which
	// is why the fix is a criterion rather than a post-hoc check on the response.
	if got := *asked; len(got) != 0 {
		t.Errorf("the upstream was asked for %v although every request above was refused by the gate", got)
	}
}
