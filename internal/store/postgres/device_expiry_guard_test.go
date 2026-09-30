package postgres

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDeviceConsumeClaimChecksExpiry is the database-free half of G-7
// (docs/issues/P2-medium.md). No Postgres is available in this environment, so
// the property is pinned by reading the shipped statement — the same shape
// revoke_predicate_test.go and refresh_family_guard_test.go use.
//
// Why it matters: the library's CheckDeviceAuthorizationState (zitadel/oidc
// pkg/op/device.go) checks Done BEFORE Expires, so a store that hands back an
// approved state past its deadline mints tokens for a device_code whose
// advertised expires_in has passed (RFC 8628 §3.5).
func TestDeviceConsumeClaimChecksExpiry(t *testing.T) {
	body, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	consume := oidcStoreMethod(t, string(body), "GetDeviceAuthorizatonState")

	claim := regexp.MustCompile(`(?s)DELETE FROM oidc_devices.*?RETURNING`).FindString(consume)
	if claim == "" {
		t.Fatal("the device consume claim was not found; the guard is reading the wrong statement")
	}
	if !strings.Contains(claim, "expires_at >") {
		t.Errorf("GetDeviceAuthorizatonState's claim DELETE has no `expires_at >` predicate: an approved device " +
			"code stays mintable past its advertised expires_in because the library checks Done before Expires " +
			"(G-7, docs/issues/P2-medium.md). AuthRequestByCode's claim in the same file is the shape to copy")
	}
	// The predicate alone is not enough: an expired approved row misses the
	// DELETE and falls through to deviceState, which would still report Done.
	if !strings.Contains(consume, "st.Done = false") {
		t.Errorf("GetDeviceAuthorizatonState's fall-through does not clear Done for an expired approved row: the " +
			"claim predicate routes that row here and the library would still mint (G-7)")
	}
}
