//go:build audit6

package z05memstore

// Falsification probes for finding 05-2 (an approved device_code past its
// advertised expiry still mints). The original probe established the mint
// through the real token endpoint; these attack the finding's side claims,
// which a wrong finding would have gotten wrong too:
//
//   - the late redemption is still SINGLE USE (c13effa) — if an expired code
//     could mint twice, the impact write-up would be materially worse;
//   - the janitor/sweep closes the window — if a swept code still minted, the
//     window would not be bounded by the sweep interval the report names;
//   - a new device authorization start purges expired device records in
//     memory mode (StoreDeviceAuthorization purges under its own lock), so
//     the memory window is at most the janitor interval and often shorter.
//
// All three are expected GREEN today: they pin the claims around the finding,
// not the finding itself (the original red probe carries that).

import (
	"net/http"
	"testing"
	"time"
)

// rev2ApprovedExpiredCode drives the original finding's setup: start a device
// authorization, approve it through the production decision method while it is
// live, then push the store clock past the advertised expiry.
func rev2ApprovedExpiredCode(t *testing.T, e *env) string {
	t.Helper()
	start := e.deviceStart(t, "openid account.id")
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	expiresIn, _ := start["expires_in"].(float64)
	if deviceCode == "" || userCode == "" || expiresIn <= 0 {
		t.Fatalf("device_authorization response lacks codes: %v", start)
	}
	if err := e.store.DecideDeviceAuthorization(t.Context(), userCode, "usr_probe", true, nil, nil); err != nil {
		t.Fatalf("approving the pending device code failed: %v", err)
	}
	e.clock.Advance(time.Duration(expiresIn)*time.Second + time.Minute)
	return deviceCode
}

func TestRev2TheLateRedemptionIsStillSingleUse(t *testing.T) {
	e := newEnv(t, nil)
	deviceCode := rev2ApprovedExpiredCode(t, e)

	first := e.devicePoll(deviceCode)
	if first.Code != http.StatusOK {
		t.Fatalf("control failed: the late redemption did not mint, so there is nothing to replay: %d %s",
			first.Code, first.Body.String())
	}
	second := e.devicePoll(deviceCode)
	if second.Code == http.StatusOK {
		t.Error("the expired device_code minted a SECOND token pair: the late redemption is not single use — " +
			"finding 05-2's impact write-up (c13effa intact) is wrong and the finding is worse than reported")
	}
}

func TestRev2TheSweepClosesTheLateRedemptionWindow(t *testing.T) {
	e := newEnv(t, nil)
	deviceCode := rev2ApprovedExpiredCode(t, e)

	if removed := e.store.SweepExpired(); removed == 0 {
		t.Fatal("control failed: the sweep removed nothing — the fixture never reached the expired device")
	}
	if rec := e.devicePoll(deviceCode); rec.Code == http.StatusOK {
		t.Error("the expired device_code minted AFTER a sweep: the window is not bounded by the janitor — " +
			"finding 05-2's window claim ([expiry, next sweep]) is wrong")
	}
}

func TestRev2ANewDeviceStartPurgesExpiredCodes(t *testing.T) {
	e := newEnv(t, nil)
	deviceCode := rev2ApprovedExpiredCode(t, e)

	// Any new device authorization purges expired device records first
	// (StoreDeviceAuthorization -> purgeExpiredDevicesLocked), so in memory
	// mode ordinary traffic also closes the late-redemption window.
	e.deviceStart(t, "account.id")
	if rec := e.devicePoll(deviceCode); rec.Code == http.StatusOK {
		t.Error("the expired device_code minted after another device authorization purged expired records: " +
			"the memory window is wider than the janitor interval the report names")
	}
}
