package postgres

// device_export_surface_guard_test.go is the probe for Z20V-2=B.
//
// Z20V-2: the exported ApproveDevice did not run the ExplicitConsent gate the
// route's entrance does, so a direct caller could approve a critical scope with no
// tick. Decision B removes the second entrance: approval is reachable only
// through DecideDeviceAuthorization, and the implementation becomes unexported.

import (
	"reflect"
	"strings"
	"testing"
)

func TestApproveDeviceIsNoLongerAnExportedEntrance(t *testing.T) {
	typ := reflect.TypeOf(&OIDCStore{})
	if _, ok := typ.MethodByName("ApproveDevice"); ok {
		t.Error("OIDCStore still exports ApproveDevice, which skips RequireExplicitConsent; a direct " +
			"caller can approve a critical scope with no individual tick (Z20V-2)")
	}
	if _, ok := typ.MethodByName("DecideDeviceAuthorization"); !ok {
		t.Fatal("control failed: DecideDeviceAuthorization is not exported, so this probe is looking at " +
			"the wrong type")
	}

	body := sourceOf(t, "oidc.go")
	if !strings.Contains(body, "func (s *OIDCStore) approveDevice(") {
		t.Error("the unexported approveDevice implementation is gone; DecideDeviceAuthorization must " +
			"still have an implementation to call")
	}
	decide := oidcStoreMethod(t, body, "DecideDeviceAuthorization")
	if strings.Contains(decide, "s.ApproveDevice(") {
		t.Error("DecideDeviceAuthorization still calls the exported ApproveDevice; the entrance is not single")
	}
	if !strings.Contains(decide, "s.approveDevice(") {
		t.Error("DecideDeviceAuthorization does not call approveDevice; approval has no path")
	}
}
