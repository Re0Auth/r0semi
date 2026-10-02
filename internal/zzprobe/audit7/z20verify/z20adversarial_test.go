//go:build audit7

// Adversarial-review probes added by the zone-20 verification pass on top of the
// probes already in this package. They are kept in the same package so they can
// reuse the independent fixture; the symbols are all prefixed z20adv to stay out
// of the way of the sibling probe files.
package zzprobe_z20verify

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// z20advNewUserCode creates a device authorization through the real protocol
// route and returns its user code.
func z20advNewUserCode(t *testing.T, e *vEnv, scope string) string {
	t.Helper()
	st, body := e.vPostForm("/oauth/device_authorization",
		url.Values{"client_id": {vClientID}, "scope": {scope}}, "")
	if st != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", st, body)
	}
	var dev struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(body, &dev); err != nil || dev.UserCode == "" {
		t.Fatalf("no user code: %s (err=%v)", body, err)
	}
	return dev.UserCode
}

// TestZ20AdvDeviceDenialAuditDropsTheSubject is the new-finding probe.
//
// `handleDeviceDecision` resolves the signed-in account and hands it to
// `DecideDeviceAuthorization` (httpapi/device_routes.go:114-115), but the denial
// branch forwards only the user code to `DenyDevice`
// (internal/store/memory/oidc.go:1381-1382 → 1112-1127, postgres
// internal/store/postgres/oidc.go:1195-1196 → 908-921), so the resulting
// `oidc.device.deny` event has an empty Subject on both backends — the store had
// the account and threw it away. The approve branch on the memory backend DOES
// record the subject, which is the control that the sink and the same call path
// can carry it.
func TestZ20AdvDeviceDenialAuditDropsTheSubject(t *testing.T) {
	e := newVEnv(t, vOptions{})

	// Control: the approval branch records the subject.
	approveCode := z20advNewUserCode(t, e, "account.id")
	if err := e.store.DecideDeviceAuthorization(t.Context(), approveCode, vSubject, true, nil, nil); err != nil {
		t.Fatalf("control: device approval failed: %v", err)
	}
	approves := e.vEvents("oidc.device.approve")
	if len(approves) != 1 {
		t.Fatalf("control: %d device approve events, want 1: %+v", len(approves), approves)
	}
	if approves[0].Subject != vSubject {
		t.Fatalf("control: the approval did not record the subject (%q), so the sink cannot "+
			"carry it and this probe proves nothing", approves[0].Subject)
	}

	// The finding: the denial branch loses the same account.
	denyCode := z20advNewUserCode(t, e, "account.id")
	if err := e.store.DecideDeviceAuthorization(t.Context(), denyCode, vSubject, false, nil, nil); err != nil {
		t.Fatalf("device denial failed: %v", err)
	}
	denies := e.vEvents("oidc.device.deny")
	if len(denies) != 1 {
		t.Fatalf("control: %d device deny events, want 1: %+v", len(denies), denies)
	}
	d := denies[0]
	t.Logf("device deny event: subject=%q detail=%v outcome=%s", d.Subject, d.Detail, d.Outcome)
	if d.Subject == "" {
		t.Errorf("the device denial recorded no subject although the route resolved %q and "+
			"passed it into DecideDeviceAuthorization: detail=%v. Who refused is unanswerable "+
			"from the event (DenyDevice never receives the subject; postgres DenyDevice also "+
			"records an empty client_id — G-17)", vSubject, d.Detail)
	}
}

// TestZ20AdvRawEscapeIsRefusedWith400AndNoUpstreamCall is the stronger guard for
// the half the reviewed report claims holds. Its own guard only fails when the
// escaping path answers 200 AND the upstream was called
// (`scopegate_test.go:94`), so a regression that answered 502 after dialling, or
// 200 without recording a call, would pass it. This one names the expected
// refusal and proves no dial happened.
func TestZ20AdvRawEscapeIsRefusedWith400AndNoUpstreamCall(t *testing.T) {
	e := newVEnv(t, vOptions{})
	// The explicit raw scope: the control must reach the proxy's path handling, and
	// since Z20-2 the resource scope would be refused by the scope gate first.
	raw := e.mintToken(vSubject, oauth.RawScope(vGame))

	// Control: the same token is served on a path inside the base, so the probe
	// reaches the proxy rather than a gate that rejects everything.
	st, _, body := e.vGet("/v1/games/"+vGame+"/sources/fake/raw/resources/scores", raw)
	if st != http.StatusOK {
		t.Fatalf("control: an in-base raw read = %d: %s", st, body)
	}
	before := len(e.upstream.snapshot())

	st, _, body = e.vGet("/v1/games/"+vGame+"/sources/fake/raw/..%2f..%2fetc", raw)
	t.Logf("escaping raw path -> %d %s", st, body)
	if st != http.StatusBadRequest {
		t.Errorf("an escaping raw path answered %d, want 400: %s", st, body)
	}
	if after := e.upstream.snapshot(); len(after) != before {
		t.Errorf("an escaping raw path reached the upstream: before=%v after=%v", before, after)
	}
	if strings.Contains(string(body), "Z20V") {
		t.Errorf("the upstream marker leaked from an escaping path: %s", body)
	}
}
