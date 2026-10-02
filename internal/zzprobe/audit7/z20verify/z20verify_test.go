//go:build audit7

// Independent verification probes for zone 20. Each probe is written so that it
// can fail: the "X is refused / yields nothing" claims carry a positive control
// that proves the probe reaches the path.
package zzprobe_z20verify

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ20VBothPlanesAddressTheSameUpstreamEndpoint is the structural half of
// Z20-2 that the reviewed probe asserted from configuration but never observed:
// with raw_base == issuer, the normalized fetch for `scores` and the raw
// passthrough of `resources/scores` must both hit `<issuer>/resources/scores`.
//
// The finding has since been fixed: the raw leg now needs the explicit
// `<game>.raw.read` scope, so the guard uses that token for the raw half and keeps
// a negative control (a score-only token is refused on the raw path) — reverting
// the scope gate turns that control red.
func TestZ20VBothPlanesAddressTheSameUpstreamEndpoint(t *testing.T) {
	e := newVEnv(t, vOptions{})
	score := e.mintToken(vSubject, "phigros.score.read")
	raw := e.mintToken(vSubject, oauth.RawScope(vGame))

	st, _, body := e.vGet("/v1/games/phigros/scores", score)
	if st != http.StatusOK {
		t.Fatalf("control: normalized path with the score scope = %d: %s", st, body)
	}
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/resources/scores", raw)
	if st != http.StatusOK {
		t.Fatalf("control: raw path with the %s scope = %d: %s", oauth.RawScope(vGame), st, body)
	}

	// Negative control: the resource scope that names this very path is not
	// enough for raw. Before the Z20-2 fix this was 200 and the endpoint below
	// saw a third call.
	before := e.upstream.count("/resources/scores")
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/resources/scores", score)
	t.Logf("raw path with only the score scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("a score-only token reached the raw path (%d): %s", st, body)
	}
	if !strings.Contains(string(body), oauth.RawScope(vGame)) {
		t.Errorf("the raw refusal did not name required_scope=%s: %s", oauth.RawScope(vGame), body)
	}
	if after := e.upstream.count("/resources/scores"); after != before {
		t.Errorf("a refused raw read reached the upstream: before=%d after=%d", before, after)
	}

	urls := e.upstream.snapshot()
	t.Logf("upstream saw: %v", urls)
	if e.upstream.count("/resources/scores") != 2 {
		t.Errorf("the two entrances did not address the same upstream endpoint: %v", urls)
	}
}

// TestZ20VProfileOnlyTokenReachesAnyNativePath is the flipped impact half of
// Z20-2. The finding was that a token the user granted only profile for reached a
// native path no Re0Auth resource describes at all. The fix gates raw on the
// explicit `<game>.raw.read` scope, so the guard asserts the opposite: the profile
// token is refused on that native path, while the raw token reaches it (the
// control that the path itself is servable). The name is kept for the matrix.
func TestZ20VProfileOnlyTokenReachesAnyNativePath(t *testing.T) {
	e := newVEnv(t, vOptions{})
	profile := e.mintToken(vSubject, "phigros.profile.read")

	// Control 1: the normalized gate refuses the score resource.
	st, _, body := e.vGet("/v1/games/phigros/scores", profile)
	t.Logf("normalized scores (profile-only) -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control: normalized gate = %d, want 403", st)
	}

	// Control 2: the raw gate is alive — no scope at all is refused.
	identity := e.mintToken(vSubject, "account.id")
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/admin/wipe", identity)
	t.Logf("raw admin/wipe (account.id only) -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control: raw gate = %d for a token with no scope, want 403", st)
	}
	if e.upstream.count("/admin/wipe") != 0 {
		t.Fatalf("control: a refused raw read reached the upstream")
	}

	// Control 3: the raw scope DOES reach the arbitrary native path, so a
	// refusal below is the scope gate rather than a broken proxy.
	raw := e.mintToken(vSubject, oauth.RawScope(vGame))
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/admin/wipe", raw)
	t.Logf("raw admin/wipe (%s) -> %d %s", oauth.RawScope(vGame), st, body)
	if st != http.StatusOK || e.upstream.count("/admin/wipe") == 0 {
		t.Fatalf("control: the raw scope did not reach the native path (%d %s): %v", st, body, e.upstream.snapshot())
	}

	// The fixed fact: the profile scope no longer opens an arbitrary native path.
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/admin/wipe", profile)
	t.Logf("raw admin/wipe (profile-only) -> %d %s", st, body)
	if st == http.StatusOK && e.upstream.count("/admin/wipe") > 0 {
		t.Errorf("a profile-only token reached the source's native admin path (%d): %s. "+
			"Upstream: %v", st, body, e.upstream.snapshot())
	}
	if st != http.StatusForbidden {
		t.Errorf("the raw gate answered %d for a profile-only token, want 403", st)
	}
}

// TestZ20VDenyEventAppearsOnlyAtTokenExchange pins Z20-1's fix (the name is the
// finding it used to assert): no deny event is written by the consent decision,
// the callback, or a successful token exchange. The library's post-mint
// DeleteAuthRequest call reaches a store that now records a refusal only for a
// request still awaiting a decision, so the field-empty event every success used
// to write is gone. A real refusal arrives through the interaction API, before a
// code exists.
func TestZ20VDenyEventAppearsOnlyAtTokenExchange(t *testing.T) {
	e := newVEnv(t, vOptions{})
	id := e.vStartAuthorize(vSubject, "account.id")
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("authorize alone recorded %d deny events", n)
	}
	e.vComplete(id, vSubject, "account.id")
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("the consent approval recorded %d deny events", n)
	}
	approves := e.vEvents("oidc.consent.approve")
	if len(approves) != 1 || approves[0].Detail["scopes"] != "account.id offline_access" {
		t.Fatalf("control: the approval event is not the interactive-face shape: %+v", approves)
	}
	code := e.vCallback(id)
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("the callback recorded %d deny events", n)
	}
	st, body := e.vExchange(code, vClientID)
	if st != http.StatusOK {
		t.Fatalf("token = %d: %s", st, body)
	}
	// The finding is gone: a successful exchange must record ZERO deny events.
	// Before the Z20-1 fix this was exactly 1, a field-empty row.
	if denies := e.vEvents("oidc.consent.deny"); len(denies) != 0 {
		t.Fatalf("the successful exchange recorded %d deny events, want 0: %+v", len(denies), denies)
	}
	// Non-vacuity: the same store does record events, so an empty deny stream is
	// not the result of an unwired sink.
	if len(approves) != 1 {
		t.Fatalf("control: the approval event vanished while checking the deny stream")
	}
}

// TestZ20VEncodedIntrospectionKeepsTheRawCallerIdentity is the positive control
// Z20-6's impact statement needs, rewritten against the shape the fix produced.
//
// Before the fix the guard read the RAW Basic userinfo while the library
// percent-decoded it, so `co%6ef` was a different identity on the two sides: the
// guard let it past and the exit filter could not match it, rewriting the body to
// `{"active":false}` — P-01's mechanism, with no impact.
//
// `basicClientID` now decodes exactly as the library does (url.QueryUnescape), so
// the same spelling resolves to the SAME client everywhere: an encoded PUBLIC
// caller is refused 401 like the plain one, and an encoded allowlisted
// CONFIDENTIAL caller gets exactly the body the plain spelling gets. The guard
// pins that coherence — a revert to raw-bytes reading makes the encoded 401
// assertion fail, and re-introduces the mismatch this test exists to catch.
func TestZ20VEncodedIntrospectionKeepsTheRawCallerIdentity(t *testing.T) {
	e := newVEnv(t, vOptions{
		IntrospectionClients: []string{"conf"},
		ConfidentialID:       "conf", ConfidentialSecret: "conf-secret",
	})
	own := e.mintToken(vSubject, "account.id")

	// Control 1: the token owner (public, plain spelling) is refused by the
	// runtime guard.
	st, body := e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("cli", ""))
	t.Logf("plain public owner -> %d %s", st, body)
	if st != http.StatusUnauthorized {
		t.Fatalf("control: plain public owner = %d, want 401", st)
	}

	// Control 2: the same public client, percent-encoded, is the SAME identity —
	// so it is refused identically. A raw-bytes guard would let it through here.
	st, body = e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("c%6ci", ""))
	t.Logf("encoded public owner -> %d %s", st, body)
	if st != http.StatusUnauthorized {
		t.Errorf("the encoded public caller answered %d, want 401: the guard and the library no "+
			"longer agree on the caller identity: %s", st, body)
	}

	// Control 3: an allowlisted CONFIDENTIAL client spelled plainly sees the token.
	st, body = e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("conf", "conf-secret"))
	t.Logf("allowlisted confidential -> %d %s", st, body)
	var ok map[string]any
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatalf("control body is not JSON: %s", body)
	}
	if active, _ := ok["active"].(bool); !active || ok["client_id"] != "cli" {
		t.Fatalf("control: the allowlisted caller did not get the live body: %s", body)
	}

	// The same identity, spelled to decode to itself: the answer must be the same
	// body, not a hidden one.
	st, encodedBody := e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("co%6ef", "conf-secret"))
	t.Logf("encoded allowlisted conf -> %d %s", st, encodedBody)
	if st != http.StatusOK {
		t.Fatalf("the encoded allowlisted caller answered %d, want the same 200 as the plain spelling: %s",
			st, encodedBody)
	}
	var enc map[string]any
	if err := json.Unmarshal(encodedBody, &enc); err != nil {
		t.Fatalf("introspection body is not JSON: %s", encodedBody)
	}
	if active, _ := enc["active"].(bool); !active {
		t.Errorf("the encoded spelling resolved to the allowlisted caller but was answered inactive: %s", encodedBody)
	}
	if enc["client_id"] != ok["client_id"] || enc["sub"] != ok["sub"] {
		t.Errorf("the encoded and plain spellings of one client disagreed: plain=%s encoded=%s", body, encodedBody)
	}
}

// TestZ20VNormalizedGateRequiresEveryCandidateSourcesScope tests the reviewed
// report's guard claim with TWO sources that declare different scopes for the
// same resource — the shape its own single-source guard cannot distinguish from
// "first source wins".
func TestZ20VNormalizedGateRequiresEveryCandidateSourcesScope(t *testing.T) {
	crit := oauth.Descriptor{
		Scope: "phigros.score2.read", Title: "第二成绩", Description: "verify",
		Risk: oauth.RiskMedium,
	}
	e := newVEnv(t, vOptions{
		Sources:  vTwoSources,
		Registry: vRegistryWith(t, crit),
		ClientScopes: []oauth.Scope{
			oauth.ScopeAccountID, "phigros.score.read", "phigros.score2.read",
		},
	})

	onlyA := e.mintToken(vSubject, "phigros.score.read")
	st, _, body := e.vGet("/v1/games/"+vGame+"/scores", onlyA)
	t.Logf("only alpha's scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("a token holding only one candidate source's scope was served (%d): %s", st, body)
	}

	onlyB := e.mintToken(vSubject, "phigros.score2.read")
	st, _, body = e.vGet("/v1/games/"+vGame+"/scores", onlyB)
	t.Logf("only beta's scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("a token holding only the other candidate's scope was served (%d): %s", st, body)
	}

	both := e.mintToken(vSubject, "phigros.score.read", "phigros.score2.read")
	st, hdr, body := e.vGet("/v1/games/"+vGame+"/scores", both)
	t.Logf("both scopes -> %d source=%s", st, hdr.Get("Re0Auth-Source"))
	if st != http.StatusOK {
		t.Errorf("control: a token holding both scopes was refused (%d): %s", st, body)
	}
}

// TestZ20VExportedEntranceEnforcesExplicitConsent checks Z20V-2 / P-02: the
// exported approval entrance is DecideDeviceAuthorization and it enforces
// explicit consent. The former residual — a direct caller of the engine method
// approving an ExplicitConsent scope with no tick — is no longer reachable,
// because approval was de-exported (approveDevice) and the only exported path
// runs RequireExplicitConsent.
func TestZ20VExportedEntranceEnforcesExplicitConsent(t *testing.T) {
	const crit = oauth.Scope("phigros.secret.read")
	e := newVEnv(t, vOptions{
		Registry: vRegistryWith(t, oauth.Descriptor{
			Scope: crit, Title: "机密", Description: "verify",
			Risk: oauth.RiskCritical, ExplicitConsent: true,
		}),
		ClientScopes: []oauth.Scope{oauth.ScopeAccountID, crit},
	})

	newCode := func(t *testing.T) string {
		t.Helper()
		form := url.Values{"client_id": {vClientID}, "scope": {crit.String()}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("device_authorization = %d: %s", rec.Code, rec.Body.String())
		}
		var dev struct {
			UserCode string `json:"user_code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &dev); err != nil || dev.UserCode == "" {
			t.Fatalf("no user code: %s (err=%v)", rec.Body.String(), err)
		}
		return dev.UserCode
	}

	// Z20V-2: the raw approval is no longer an exported entrance. A package-external
	// caller cannot bypass RequireExplicitConsent by calling it directly.
	if _, ok := reflect.TypeOf(e.store).MethodByName("ApproveDevice"); ok {
		t.Error("OIDCStore still exports ApproveDevice, which skips RequireExplicitConsent; approval " +
			"must have exactly one exported entrance")
	}

	// The exported entrance refuses an ExplicitConsent scope without its tick.
	uc := newCode(t)
	err := e.store.DecideDeviceAuthorization(t.Context(), uc, vSubject, true, nil, nil)
	t.Logf("DecideDeviceAuthorization without a tick -> %v", err)
	var oe *oauth.Error
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("the exported entrance did not refuse with access_denied: %v", err)
	}

	// Positive control: with the scope ticked, the same entrance approves — so the
	// refusal above is the ExplicitConsent gate, not an unrelated failure.
	uc2 := newCode(t)
	if err := e.store.DecideDeviceAuthorization(t.Context(), uc2, vSubject, true, nil,
		[]oauth.Scope{crit}); err != nil {
		t.Fatalf("with the explicit tick the exported entrance refused: %v", err)
	}
}
