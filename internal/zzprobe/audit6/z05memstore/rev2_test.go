//go:build audit6

package z05memstore

// Falsification probes for finding 05-2 (an approved device_code past its
// advertised expiry still mints). G-7 landed, so the finding's premise is gone;
// these probes now pin the fixed behaviour and its surrounding claims:
//
//   - the expired code mints NOTHING, on the first poll or any later one (the
//     former "the late redemption is single use" control assumed a first mint,
//     which no longer exists);
//   - the janitor/sweep still removes the row;
//   - a new device authorization start purges expired device records in
//     memory mode (StoreDeviceAuthorization purges under its own lock).
//
// All three are expected GREEN today.

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

func TestRev2TheLateRedemptionIsRefusedAndNeverMints(t *testing.T) {
	e := newEnv(t, nil)
	deviceCode := rev2ApprovedExpiredCode(t, e)

	// G-7: the expired approved code is not handed back as consumable, so the
	// first poll is refused and there is no pair to replay.
	first := e.devicePoll(deviceCode)
	if first.Code == http.StatusOK {
		t.Fatalf("the expired approved device_code minted on the first poll: %d %s",
			first.Code, first.Body.String())
	}
	second := e.devicePoll(deviceCode)
	if second.Code == http.StatusOK {
		t.Errorf("the expired device_code minted on a later poll: %d %s",
			second.Code, second.Body.String())
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
