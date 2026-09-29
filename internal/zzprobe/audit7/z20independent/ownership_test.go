//go:build audit7

// Z20-INDEPENDENT follow-up probes: client x scope registration, and subject x
// flow-handle ownership (the two cells the zone-20 report lists as "probed but
// held" without naming a probe).
package zzprobe_z20independent

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

// TestZ20I111ClientCannotObtainAScopeItIsNotRegisteredFor (matrix cell: client x scope).
//
// zClientOther is registered for account.id only. Every entrance that can start a
// grant must refuse a scope it is not registered for, and must refuse BEFORE a
// grant exists.
func TestZ20I111ClientCannotObtainAScopeItIsNotRegisteredFor(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	// Control: the client can get what it IS registered for.
	code, ds, db := e.zConsentCode(b, zClientOther, "account.id", []string{"account.id"})
	if ds != http.StatusOK || code == "" {
		t.Fatalf("control: %s could not obtain account.id (%d %s)", zClientOther, ds, db)
	}
	if st, _, _ := e.zExchange(zClientOther, "", code); st != http.StatusOK {
		t.Fatalf("control: exchange for %s = %d", zClientOther, st)
	}

	// The claim: the authorize entrance refuses an unregistered scope.
	handle, status, body := e.zAuthorize(b, zClientOther, "account.id phigros.score.read", "st-unregistered")
	t.Logf("authorize %s with an unregistered scope -> %d handle=%q body=%s",
		zClientOther, status, handle, body)
	if !bytes.Contains(body, []byte("invalid_scope")) {
		t.Errorf("the authorize entrance did not name invalid_scope: %s", body)
	}
	if handle != "" {
		t.Errorf("the authorize entrance produced a consent handle for an unregistered scope: %q", handle)
	}

	// The claim: the device entrance refuses it too, rather than minting a grant.
	st, dbody := e.zPostForm("/oauth/device_authorization", url.Values{
		"client_id": {zClientOther}, "scope": {"phigros.score.read"},
	}, "")
	t.Logf("device_authorization %s with an unregistered scope -> %d %s", zClientOther, st, dbody)
	if st == http.StatusOK {
		t.Errorf("the device entrance minted a grant for an unregistered scope: %s", dbody)
	}

	// And the code is bound to the client that requested it.
	code, ds, db = e.zConsentCode(b, zClientOther, "account.id", []string{"account.id"})
	if ds != http.StatusOK {
		t.Fatalf("control: %s could not obtain account.id (%d %s)", zClientOther, ds, db)
	}
	if st, _, xbody := e.zExchange(zClientPublic, "", code); st == http.StatusOK {
		t.Errorf("client %s exchanged a code issued to %s: %s", zClientPublic, zClientOther, xbody)
	} else {
		t.Logf("cross-client code exchange refused: %d %s", st, xbody)
	}
}

// TestZ20I112ConsentHandleIsNotUsableAfterAnAccountSwitch (matrix cell: subject x consent handle).
//
// A handle created while account V held the browser must not be readable or
// decidable by account A after A signs in on the same browser — the exact
// scenario the OwnerMatches comment describes.
func TestZ20I112ConsentHandleIsNotUsableAfterAnAccountSwitch(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")
	owner := e.zCurrentSessionID(b)

	handle, status, body := e.zAuthorize(b, zClientPublic, "account.id", "st-owner")
	if status != http.StatusFound || handle == "" {
		t.Fatalf("authorize = %d %s", status, body)
	}

	// Control: the account that created it can read and decide it.
	st, _, viewBody := e.zGetBrowser(b, "/v1/authorization_requests/"+url.PathEscape(handle))
	if st != http.StatusOK {
		t.Fatalf("control: the owner's consent view = %d %s", st, viewBody)
	}
	csrf, _ := zJSON(t, viewBody)["csrf_token"].(string)

	// A second account signs into the same browser.
	e.zSignInAs(b, "other-account")
	other := e.zCurrentSessionID(b)
	if other == owner {
		t.Fatalf("control: the account switch did not change the subject")
	}

	st, _, gbody := e.zGetBrowser(b, "/v1/authorization_requests/"+url.PathEscape(handle))
	t.Logf("handle created by %s read by %s -> %d %s", owner, other, st, gbody)
	if st != http.StatusNotFound {
		t.Errorf("the new account read another account's consent handle (%d): %s\n"+
			"annotation: a handle that answers 'forbidden' has confirmed it exists", st, gbody)
	}

	st, dbody := e.zPostJSON(b, "/v1/authorization_requests/"+url.PathEscape(handle)+"/decision",
		map[string]any{"decision": "approve", "scopes": []string{"account.id"}}, csrf)
	t.Logf("handle created by %s decided by %s -> %d %s", owner, other, st, dbody)
	if st != http.StatusNotFound {
		t.Errorf("the new account decided another account's consent handle (%d): %s", st, dbody)
	}
}

// TestZ20I113DeviceHandleIsNotUsableAfterAnAccountSwitch (matrix cell: subject x device handle).
func TestZ20I113DeviceHandleIsNotUsableAfterAnAccountSwitch(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")
	owner := e.zCurrentSessionID(b)

	uc, dc := e.zDeviceStartFull(t, "account.id")
	st, _, viewBody := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc))
	if st != http.StatusOK {
		t.Fatalf("control: device verification = %d %s", st, viewBody)
	}
	csrf, _ := zJSON(t, viewBody)["csrf_token"].(string)

	// A second account signs into the same browser, then decides the loaded code.
	e.zSignInAs(b, "other-account")
	other := e.zCurrentSessionID(b)
	if other == owner {
		t.Fatalf("control: the account switch did not change the subject")
	}
	st, dbody := e.zPostJSON(b, "/v1/device/decision",
		map[string]any{"user_code": uc, "decision": "approve", "scopes": []string{"account.id"}}, csrf)
	t.Logf("device code loaded by %s decided by %s -> %d %s", owner, other, st, dbody)
	if st != http.StatusNotFound {
		t.Errorf("the new account decided another account's device code (%d): %s", st, dbody)
	}
	// No token may have been minted for it either.
	if dst, _, dbody := e.zDevicePoll(dc); dst == http.StatusOK {
		t.Errorf("a device code decided by the wrong account still minted tokens: %s", dbody)
	} else {
		t.Logf("the undecided device code does not redeem: %d %s", dst, dbody)
	}
}
