//go:build audit7

// Z20-INDEPENDENT cross-check of the six findings in
// scratchpad/audit7/findings/Z20-authz-isolation-matrix.md (Z20-1 .. Z20-6).
//
// Each probe here is written from the claim, not from the author's probe: it
// reaches the same observable through this package's own fixture. A green result
// that the author's probe reports red (or vice versa) is the whole point.
package zzprobe_z20independent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// --- Z20-1: a successful code exchange writes oidc.consent.deny ---------------

// TestZ20I001SpuriousConsentDenyOnSuccessfulExchange checks Z20-1 (P2).
//
// Claim: every successful authorization-code exchange records
// `oidc.consent.deny` with an empty subject and an empty client_id, because the
// library calls DeleteAuthRequest after minting and the store records an
// unconditional refusal there.
//
// AGREES if a successful exchange adds a deny event whose subject is empty.
func TestZ20I001SpuriousConsentDenyOnSuccessfulExchange(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	deniesBefore := len(e.zEvents("oidc.consent.deny"))
	code, _, _ := e.zConsentCode(b, zClientPublic, "account.id", []string{"account.id"})
	status, tok, body := e.zExchange(zClientPublic, "", code)
	if status != http.StatusOK {
		t.Fatalf("control: the exchange failed (%d %s)", status, body)
	}
	if tok["access_token"] == nil {
		t.Fatalf("control: no access token: %s", body)
	}

	// Positive control: the approval leg really was driven, so a missing deny
	// cannot be explained by "the flow never got that far".
	if got := len(e.zEvents("oidc.consent.approve")); got != 1 {
		t.Fatalf("control: %d approve events, want 1", got)
	}

	after := e.zEvents("oidc.consent.deny")
	t.Logf("deny events: before=%d after=%d", deniesBefore, len(after))
	for _, d := range after[deniesBefore:] {
		t.Logf("  deny: subject=%q outcome=%s detail=%v", d.Subject, d.Outcome, d.Detail)
	}
	if len(after) > deniesBefore && after[len(after)-1].Subject == "" {
		t.Logf("AGREES with Z20-1: a SUCCESSFUL code exchange recorded oidc.consent.deny "+
			"with an empty subject (detail=%v)", after[len(after)-1].Detail)
		return
	}
	if len(after) > deniesBefore {
		t.Logf("UNCLEAR vs Z20-1: a deny was recorded but it names a subject (%q)", after[len(after)-1].Subject)
		return
	}
	t.Logf("CONTRADICTS Z20-1: no deny event on the success path")
}

// --- Z20-2: the raw passthrough gate is per source, not per resource ----------

// TestZ20I002RawPassthroughIgnoresWhichResourceTheScopeNames checks Z20-2 (P2),
// the security-relevant one.
//
// Claim: with `raw_base` equal to the source's issuer, the raw passthrough
// addresses the same upstream URL as the normalized route, but its gate is "the
// token holds ANY of the source's resource scopes", so a token granted only
// `phigros.profile.read` reads the scores resource that the normalized route
// refuses with 403.
func TestZ20I002RawPassthroughIgnoresWhichResourceTheScopeNames(t *testing.T) {
	e := newZAEnv(t, zAOpts{})

	profileOnly := e.zMintToken(zClientPublic, zVictim, "phigros.profile.read")
	if profileOnly == "" {
		t.Fatal("control: no token")
	}
	identityOnly := e.zMintToken(zClientPublic, zVictim, "account.id")
	scoreOnly := e.zMintToken(zClientPublic, zVictim, "phigros.score.read")

	// Control A: the normalized route enforces per-resource scope.
	st, _, body := e.zGet("/v1/games/"+zGame+"/scores", profileOnly)
	t.Logf("CANDIDATE: normalized /v1/games/%s/scores (profile-only) -> %d %s", zGame, st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control A: the normalized route answered %d, want 403", st)
	}

	// Control B: the raw gate is alive — no resource scope of this source at all.
	st, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", identityOnly)
	t.Logf("control: raw .../resources/scores (account.id only) -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control B: the raw gate answered %d, want 403", st)
	}

	// Control C: the score scope really does open that raw path.
	st, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", scoreOnly)
	t.Logf("control: raw .../resources/scores (score) -> %d %s", st, body)
	if st != http.StatusOK || !bytes.Contains(body, []byte(zScoresMarker)) {
		t.Fatalf("control C: a score token was not served (%d %s)", st, body)
	}
	if !e.up.hit("/resources/scores") {
		t.Fatalf("control C: upstream never saw /resources/scores: %v", e.up.calls())
	}

	// The claim: the withheld resource is reachable through the raw entrance.
	st, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", profileOnly)
	t.Logf("CANDIDATE: raw .../resources/scores (PROFILE-only, same URL) -> %d %s", st, body)
	if st == http.StatusOK && bytes.Contains(body, []byte(zScoresMarker)) {
		t.Errorf("AGREES with Z20-2 (probe is RED): a profile-only token read the scores "+
			"resource through the raw passthrough (%d): %s\nupstream calls: %v", st, body, e.up.calls())
		return
	}
	t.Logf("CONTRADICTS Z20-2: the raw gate refused the withheld resource (%d %s)", st, body)
}

// TestZ20I002bRawGateIsBoundToTheNamedSource is the guard half.
func TestZ20I002bRawGateIsBoundToTheNamedSource(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	score := e.zMintToken(zClientPublic, zVictim, "phigros.score.read")
	st, _, body := e.zGet("/v1/games/"+zGame+"/sources/nosuchsource/raw/resources/scores", score)
	t.Logf("raw unknown source -> %d %s", st, body)
	if st != http.StatusNotFound {
		t.Errorf("an unknown source answered %d, want 404", st)
	}
	if len(e.up.calls()) != 0 {
		t.Errorf("an unknown source reached the upstream: %v", e.up.calls())
	}
}

// TestZ20I002cRawBaseSubPathDecidesWhetherTheWithheldResourceOverlaps is the
// severity check for Z20-2.
//
// Z20-2's impact rests on raw_base and the normalized resource URL naming the
// SAME upstream endpoint. That is true when `raw_base` is the source's issuer (or
// an ancestor of `{issuer}/resources`), and false for the shape
// `config/re0auth.example.toml:363` actually ships (`raw_base = {issuer}/v1`,
// while the source's normalized resources live at `{issuer}/resources/{name}`,
// docs/upstream-protocol.md:227). This probe measures both, so the finding's
// precondition is stated rather than assumed.
func TestZ20I002cRawBaseSubPathDecidesWhetherTheWithheldResourceOverlaps(t *testing.T) {
	// (1) raw_base == issuer: the two entrances address one upstream endpoint.
	same := newZAEnv(t, zAOpts{})
	profile := same.zMintToken(zClientPublic, zVictim, "phigros.profile.read")
	st, _, body := same.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", profile)
	t.Logf("raw_base == issuer: profile-only token on the raw scores path -> %d %s", st, body)
	overlaps := st == http.StatusOK && bytes.Contains(body, []byte(zScoresMarker))
	t.Logf("  upstream calls: %v", same.up.calls())
	if !overlaps {
		t.Errorf("expected the overlap case to be reachable with raw_base == issuer")
	}

	// (2) raw_base == {issuer}/v1, the shipped example: the raw path lands on the
	// source's NATIVE surface, not on /resources/{name}.
	sub := newZAEnv(t, zAOpts{RawBaseSuffix: "/v1"})
	profile2 := sub.zMintToken(zClientPublic, zVictim, "phigros.profile.read")
	st, _, body = sub.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", profile2)
	t.Logf("raw_base == issuer+/v1: profile-only token on the raw scores path -> %d %s", st, body)
	t.Logf("  upstream calls: %v", sub.up.calls())
	// Control: the normalized path still resolves to /resources/scores.
	score := sub.zMintToken(zClientPublic, zVictim, "phigros.score.read")
	if st2, _, b2 := sub.zGet("/v1/games/"+zGame+"/scores", score); st2 != http.StatusOK ||
		!bytes.Contains(b2, []byte(zScoresMarker)) {
		t.Fatalf("control: the normalized read under a sub-path raw_base = %d %s", st2, b2)
	}
	t.Logf("  upstream calls after the normalized read: %v", sub.up.calls())
	if bytes.Contains(body, []byte(zScoresMarker)) {
		t.Errorf("the sub-path raw_base still reached the normalized scores endpoint")
	}
	t.Logf("SEVERITY INPUT for Z20-2: overlap=%v with raw_base==issuer; no overlap with the "+
		"shipped sub-path shape", overlaps)
}

// --- Z20-3: the device approval records no scopes ----------------------------

// TestZ20I003DeviceApprovalAuditOmitsTheGrantedScopes checks Z20-3 (P3).
func TestZ20I003DeviceApprovalAuditOmitsTheGrantedScopes(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	uc := e.zDeviceStart(t, "phigros.profile.read phigros.score.read")
	// The device route's own two legs: load the code (which binds it), decide.
	if st, _, body := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc)); st != http.StatusOK {
		t.Fatalf("device verification = %d %s", st, body)
	}
	_, viewBody := e.zDeviceView(t, b, uc)
	csrf, _ := zJSON(t, viewBody)["csrf_token"].(string)
	st, db := e.zPostJSON(b, "/v1/device/decision",
		map[string]any{"user_code": uc, "decision": "approve", "scopes": []string{"phigros.profile.read"}}, csrf)
	if st != http.StatusOK {
		t.Fatalf("device decision = %d %s", st, db)
	}

	events := e.zEvents("oidc.device.approve")
	if len(events) != 1 {
		t.Fatalf("control: %d device approve events, want 1 (all actions: %v)",
			len(events), zActions(e))
	}
	if got := events[0].Detail["client_id"]; got != zClientPublic {
		t.Errorf("the device approval names the wrong client: %q", got)
	}
	if _, ok := events[0].Detail["scopes"]; ok {
		t.Logf("CONTRADICTS Z20-3: the device approval records scopes (%v)", events[0].Detail)
		return
	}
	t.Logf("AGREES with Z20-3: the narrowing (profile approved, score withheld) is invisible: %v",
		events[0].Detail)
}

// --- Z20-4: the device entrance DOES enforce ExplicitConsent -----------------

// zCriticalScope is a catalogue scope the shipped descriptor set deliberately
// does not have, so a probe can put an ExplicitConsent descriptor in play.
const zCriticalScope = oauth.Scope("phigros.secret.read")

func zRegistryWithCritical(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope: zCriticalScope, Title: "读取 Phigros 机密", Description: "probe descriptor",
		Risk: oauth.RiskCritical, ExplicitConsent: true,
	})...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

// TestZ20I004DeviceApprovalEnforcesExplicitConsent checks Z20-4, which REFUTES
// `_audit/protocol.md` P-02 for the device face.
//
// The device route calls DeviceStore.DecideDeviceAuthorization
// (httpapi/device_routes.go:114), which resolves the descriptors and calls
// oidcstore.RequireExplicitConsent before it writes. An approval that omits the
// individual tick must be refused; one that includes it must succeed.
func TestZ20I004DeviceApprovalEnforcesExplicitConsent(t *testing.T) {
	e := newZAEnv(t, zAOpts{
		Registry:     zRegistryWithCritical(t),
		ClientScopes: []oauth.Scope{oauth.ScopeAccountID, zCriticalScope},
	})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	start := func(scope string) string {
		t.Helper()
		st, body := e.zPostForm("/oauth/device_authorization",
			url.Values{"client_id": {zClientPublic}, "scope": {scope}}, "")
		if st != http.StatusOK {
			t.Fatalf("device_authorization = %d: %s", st, body)
		}
		var dev struct {
			UserCode string `json:"user_code"`
		}
		if err := json.Unmarshal(body, &dev); err != nil || dev.UserCode == "" {
			t.Fatalf("no user code: %s (%v)", body, err)
		}
		return dev.UserCode
	}
	decide := func(uc string, scopes, explicit []string) (int, []byte) {
		t.Helper()
		if st, _, body := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc)); st != http.StatusOK {
			t.Fatalf("device verification = %d %s", st, body)
		}
		_, viewBody := e.zDeviceView(t, b, uc)
		csrf, _ := zJSON(t, viewBody)["csrf_token"].(string)
		payload := map[string]any{"user_code": uc, "decision": "approve"}
		if scopes != nil {
			payload["scopes"] = scopes
		}
		if explicit != nil {
			payload["explicit"] = explicit
		}
		return e.zPostJSON(b, "/v1/device/decision", payload, csrf)
	}

	// Control: ticking the critical scope succeeds.
	if st, body := decide(start(zCriticalScope.String()), nil, []string{zCriticalScope.String()}); st != http.StatusOK {
		t.Fatalf("control: a ticked approval = %d %s", st, body)
	}
	// P-02's prediction: approval with no individual tick.
	st, body := decide(start(zCriticalScope.String()), nil, nil)
	t.Logf("device approval without the explicit tick -> %d %s", st, body)
	if st == http.StatusOK {
		t.Errorf("CONTRADICTS Z20-4 (probe is RED): the device entrance approved an " +
			"ExplicitConsent scope with no individual tick")
		return
	}
	t.Logf("AGREES with Z20-4: the device entrance refused (%d) — P-02 does not hold on "+
		"the device face, which also refutes the proposed fix's premise", st)
}

// --- Z20-5: /oauth/revoke is a liveness oracle on the deployment plane -------

// TestZ20I005RevocationOracleForForeignTokens checks Z20-5 (P3).
func TestZ20I005RevocationOracleForForeignTokens(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	foreign := e.zMintToken(zClientOther, zVictim, "account.id")
	if foreign == "" {
		t.Fatal("control: no foreign token")
	}

	unknownStatus, unknownBody := e.zRevoke(t, zClientPublic, "", "a-string-this-server-never-issued")
	foreignStatus, foreignBody := e.zRevoke(t, zClientPublic, "", foreign)
	t.Logf("revoke unknown string         -> %d %s", unknownStatus, unknownBody)
	t.Logf("revoke another client's live  -> %d %s", foreignStatus, foreignBody)

	// Control: the refusal did not delete it.
	if st, _, _ := e.zGet("/v1/me", foreign); st != http.StatusOK {
		t.Fatalf("control: the foreign token stopped working (%d); cannot tell refusal from revocation", st)
	}
	if unknownStatus == http.StatusOK && foreignStatus != http.StatusOK {
		t.Logf("AGREES with Z20-5: unknown->%d, foreign live->%d (distinguishable)", unknownStatus, foreignStatus)
		return
	}
	t.Logf("CONTRADICTS Z20-5: unknown->%d, foreign live->%d", unknownStatus, foreignStatus)
}

// --- Z20-6: the escaped public introspection caller discloses nothing --------

// TestZ20I006EscapedPublicIntrospectionDisclosesNothing checks Z20-6 (P3).
//
// Claim: the percent-encoded public caller DOES bypass the confidential-client
// guard (it is not refused with the guard's message) but still learns nothing,
// because filterIntrospection is handed the same raw bytes and rewrites the body
// to {"active":false}.
func TestZ20I006EscapedPublicIntrospectionDisclosesNothing(t *testing.T) {
	e := newZAEnv(t, zAOpts{IntrospectionClients: []string{zClientPublic}})

	// A live token held by a DIFFERENT client: the thing an oracle would leak.
	victim := e.zMintToken(zClientOther, zVictim, "account.id")
	if victim == "" {
		t.Fatal("control: no token")
	}

	plainStatus, plainBody := e.zIntrospect(t, zBasicHeader(zClientPublic, ""), victim)
	encStatus, encBody := e.zIntrospect(t, zBasicHeader("c%6ci", ""), victim)
	t.Logf("plain public caller           -> %d %s", plainStatus, plainBody)
	t.Logf("percent-encoded public caller -> %d %s", encStatus, encBody)

	// Whatever the status, no token field may reach the caller.
	var m map[string]any
	if err := json.Unmarshal(encBody, &m); err == nil {
		if active, _ := m["active"].(bool); active {
			t.Errorf("CONTRADICTS Z20-6 (probe is RED): the encoded caller saw an ACTIVE "+
				"token it does not own: %s", encBody)
			return
		}
		if _, leaked := m["sub"]; leaked {
			t.Errorf("CONTRADICTS Z20-6: a subject reached the encoded caller: %s", encBody)
			return
		}
	}
	if plainStatus == http.StatusUnauthorized && encStatus != http.StatusUnauthorized {
		t.Logf("AGREES with Z20-6: the guard is bypassed (401 -> %d) but the body discloses "+
			"nothing: %s", encStatus, encBody)
		return
	}
	t.Logf("UNCLEAR vs Z20-6: plain->%d encoded->%d body=%s", plainStatus, encStatus, encBody)
}

// --- helpers ------------------------------------------------------------------

func zActions(e *zAEnv) []string {
	var out []string
	for _, ev := range e.audit.Events() {
		out = append(out, ev.Action+"("+ev.Subject+")")
	}
	return out
}

// zDeviceStart starts a device authorization and returns the user code.
func (e *zAEnv) zDeviceStart(t *testing.T, scope string) string {
	t.Helper()
	status, body := e.zPostForm("/oauth/device_authorization",
		url.Values{"client_id": {zClientPublic}, "scope": {scope}}, "")
	if status != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", status, body)
	}
	var dev struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(body, &dev); err != nil || dev.UserCode == "" {
		t.Fatalf("no user code: %s (%v)", body, err)
	}
	return dev.UserCode
}

// zDeviceView returns the verification page's payload for a bound code.
func (e *zAEnv) zDeviceView(t *testing.T, b *http.Client, uc string) (int, []byte) {
	t.Helper()
	st, _, body := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc))
	return st, body
}

// zRevoke calls RFC 7009 with a raw Basic header.
func (e *zAEnv) zRevoke(t *testing.T, clientID, secret, token string) (int, []byte) {
	t.Helper()
	form := url.Values{"token": {token}}
	auth := ""
	if secret != "" {
		auth = zBasicHeader(clientID, secret)
		form.Set("client_id", clientID)
	} else {
		form.Set("client_id", clientID)
	}
	return e.zPostForm("/oauth/revoke", form, auth)
}

// zIntrospect calls RFC 7662 with a raw Basic header.
func (e *zAEnv) zIntrospect(t *testing.T, rawAuth, token string) (int, []byte) {
	t.Helper()
	return e.zPostForm("/oauth/introspect", url.Values{"token": {token}}, rawAuth)
}

// keep the unused-import checker honest while the probe set evolves.
var (
	_ = context.Background
	_ = httptest.NewRequest
	_ = strings.TrimSpace
	_ = oauth.ScopeAccountID
)
