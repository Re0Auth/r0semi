package memory

// device_export_surface_probe_test.go is the probe for Z20V-2=B.
//
// Z20V-2: the exported ApproveDevice did not run the ExplicitConsent gate the
// route's entrance does, so a direct caller could approve a critical scope
// without a tick (the finding's "exported footgun"). Decision B removes the
// second entrance: approval is reachable only through DecideDeviceAuthorization,
// and the implementation becomes unexported.

import (
	"os"
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

	body, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read oidc.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "func (s *OIDCStore) approveDevice(") {
		t.Error("the unexported approveDevice implementation is gone; DecideDeviceAuthorization must " +
			"still have an implementation to call")
	}
	if strings.Contains(src, "s.ApproveDevice(") {
		t.Error("an internal call still uses the exported ApproveDevice; the entrance is not single")
	}
}
