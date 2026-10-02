package memory

// device_display_superset_probe_test.go is the probe for A-FE-3 / A-FE-V1 (B).
//
// The device verification page's displayed set was the catalogue scopes only:
// DescribeDeviceAuthorization stripped `openid`/`profile`/... before resolving, so
// the page showed less than the approval would grant, and DecideDeviceAuthorization
// re-attached exactly those scopes. The adjudication is that the displayed set must
// cover the granted set, with a system-required placeholder for a scope the
// catalogue does not describe.

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/oauth"
)

func TestDevicePageDisplaysEveryGrantedScope(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	requested := []string{"openid", "profile", "email", "account.id", "phigros.score.read"}

	if err := store.StoreDeviceAuthorization(ctx, "cli", "dc-display", "DISP-0001",
		time.Now().Add(10*time.Minute), requested); err != nil {
		t.Fatal(err)
	}
	auth, err := store.DescribeDeviceAuthorization(ctx, "DISP-0001")
	if err != nil {
		t.Fatalf("DescribeDeviceAuthorization: %v", err)
	}

	displayed := make(map[string]string, len(auth.Scopes))
	for _, d := range auth.Scopes {
		displayed[d.Scope.String()] = d.Title
	}
	for _, want := range requested {
		if _, ok := displayed[want]; !ok {
			t.Errorf("the device page does not display %q, which an approval will grant: displayed=%v "+
				"(A-FE-3 / A-FE-V1)", want, displayed)
		}
	}
	// The protocol scopes are not catalogue permissions: they must appear as the
	// explicit system-required placeholder, never as an invented title.
	for _, protocol := range []string{"openid", "profile", "email"} {
		if got := displayed[protocol]; got != "系统必需" {
			t.Errorf("protocol scope %q renders as %q, want the system-required placeholder", protocol, got)
		}
	}
	// And the catalogue scopes keep their real descriptions.
	if displayed["account.id"] == "系统必需" || displayed["account.id"] == "" {
		t.Errorf("catalogue scope account.id lost its descriptor: %q", displayed["account.id"])
	}

	// The invariant itself: after approval, every granted scope (offline_access
	// is an internal trigger the OP does not expose) was displayed beforehand.
	if err := store.DecideDeviceAuthorization(ctx, "DISP-0001", "usr_1", true,
		[]oauth.Scope{oauth.ScopeAccountID}, nil); err != nil {
		t.Fatalf("DecideDeviceAuthorization: %v", err)
	}
	st, err := store.DeviceByUserCode(ctx, "DISP-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Scopes) == 0 {
		t.Fatal("fixture failed: the approval granted nothing, so the invariant is vacuous")
	}
	for _, granted := range st.Scopes {
		if granted == oidc.ScopeOfflineAccess {
			continue
		}
		if _, ok := displayed[granted]; !ok {
			t.Errorf("granted scope %q was never displayed: the page showed less than it granted "+
				"(A-FE-3 / A-FE-V1). displayed=%v granted=%v", granted, displayed, st.Scopes)
		}
	}
}
