//go:build audit7

package z21migrationsschemaintegrity

import (
	"strings"
	"testing"
)

// TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable is the constraint-parity
// check the two device tables never had.
//
// oidc_devices.user_code carries a UNIQUE index (0008_oidc.sql:57-60) and
// oidc.go:720-730 turns the resulting 23505 back into op.ErrDuplicateUserCode,
// because a user code is the handle a human types to approve a device flow:
// two live rows sharing one is exactly the ambiguity that makes an approval
// land on the wrong flow. oauth_device_authorizations.user_code — the legacy
// engine's table — has only a NON-unique expression index (0001_init.sql:105-106).
//
// The legacy engine compensates in Go with a check-then-insert loop
// (oauth/device.go:432-443), which is where the guarantee is weaker: the lookup
// and the INSERT are separate statements with no uniqueness constraint between
// them, so two concurrent device flows can both be told a code is free. The
// in-memory backend shares that shape (oauth/device.go:161 byUser map written
// after the lookup), so the race is not merely a Postgres artefact — but the
// schema is where it could be closed cheaply.
func TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable(t *testing.T) {
	s := parseSchema(t, readAll(t, migrationFiles(t)))

	// Re-read the migration text for the UNIQUE keyword specifically: the parsed
	// index lists do not carry the keyword, and "is there a unique index on this
	// column" is the whole question.
	raw := readAll(t, migrationFiles(t))
	uniqueOn := func(table, col string) bool {
		for _, body := range raw {
			up, _ := splitDirection(body)
			for _, m := range reIndex.FindAllStringSubmatch(up, -1) {
				if !strings.Contains(strings.ToUpper(m[0]), "UNIQUE") {
					continue
				}
				if unquote(m[2]) != table {
					continue
				}
				if strings.Contains(strings.ToLower(m[0]), col) {
					return true
				}
			}
		}
		return false
	}

	if !uniqueOn("oidc_devices", "user_code") {
		t.Fatal("control failed: oidc_devices.user_code is not seen as UNIQUE, so this probe proves nothing")
	}
	// The unique expression index is `upper(replace(user_code, '-', ''))`; the
	// substring check above must have matched it.
	if _, ok := s.columns["oauth_device_authorizations"]["user_code"]; !ok {
		t.Fatal("control failed: the legacy device table has no user_code column")
	}
	if uniqueOn("oauth_device_authorizations", "user_code") {
		t.Fatalf("oauth_device_authorizations.user_code is now UNIQUE; this finding is fixed")
	}
	t.Errorf("UNIQUENESS PARITY GAP: oidc_devices.user_code has a UNIQUE index but " +
		"oauth_device_authorizations.user_code has only a non-unique expression index. " +
		"The legacy engine relies on a check-then-insert in Go (oauth/device.go:432-443), " +
		"so two concurrent device authorizations can share a user code and a human typing " +
		"it resolves (GetDeviceByUserCode, postgres/oauth.go:355-361) to whichever row the " +
		"scan reaches first.")
}
