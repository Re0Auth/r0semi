package postgres

// device_display_superset_guard_test.go is the database-free half of
// A-FE-3 / A-FE-V1 (B) for the Postgres device page.
//
// The displayed set must cover the granted set: DescribeDeviceAuthorization used
// to strip the protocol scopes before resolving, so the page never showed the
// `openid`/`profile`/... an approval re-attaches, and the screen showed less than
// the token carried. The live rows are asserted by the CI integration test; this
// guard pins the call site and the placeholder construction.

import (
	"strings"
	"testing"
)

func TestDeviceDescriptionCoversEveryRequestedScope(t *testing.T) {
	body := sourceOf(t, "oidc.go")

	describe := oidcStoreMethod(t, body, "DescribeDeviceAuthorization")
	if interpreted := strings.Count(describe, "deviceDisplayDescriptors("); interpreted != 1 {
		t.Errorf("DescribeDeviceAuthorization builds its scope list %d times through "+
			"deviceDisplayDescriptors, want exactly 1; if it still calls registry.Resolve on the "+
			"described subset the page drops the protocol scopes (A-FE-3 / A-FE-V1)", interpreted)
	}
	if strings.Contains(describe, "SplitProtocolScopes") {
		t.Error("DescribeDeviceAuthorization still splits off the protocol scopes itself; the display " +
			"set must be built by the shared helper so it cannot drop them")
	}

	helper := functionBody(t, body, "func deviceDisplayDescriptors(")
	if !strings.Contains(helper, "系统必需") {
		t.Error("the undescribed scopes get no system-required placeholder; skipping them is exactly " +
			"the 'displayed less than granted' defect")
	}
	if !strings.Contains(helper, "byScope[s]") {
		t.Error("deviceDisplayDescriptors does not look each requested scope up against the resolved " +
			"catalogue descriptors, so it cannot decide which ones are undescribed")
	}
	if !strings.Contains(helper, "SplitProtocolScopes") {
		t.Error("the helper does not separate described from protocol scopes; it cannot know which " +
			"requested scopes the registry can resolve")
	}
}
