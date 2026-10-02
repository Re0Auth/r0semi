//go:build audit7

package z21migrationsschemaintegrity

import (
	"strings"
	"testing"
)

// TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable is the constraint-parity
// check the two device tables never had, kept in the enforce-direction after the
// gap it reported was closed by 0033_oauth_device_user_code_unique.sql.
//
// oidc_devices.user_code carries a UNIQUE expression index (0008_oidc.sql) and
// oidc.go turns the resulting 23505 back into op.ErrDuplicateUserCode, because a
// user code is the handle a human types to approve a device flow: two live rows
// sharing one is exactly the ambiguity that makes an approval land on the wrong
// flow. oauth_device_authorizations.user_code — the legacy engine's table — had
// only a NON-unique expression index, so the legacy engine compensated in Go with
// a check-then-insert loop (freeUserCode, oauth/device.go): the lookup and the
// INSERT are separate statements with no uniqueness constraint between them, and
// two concurrent device flows could both be told a code is free.
//
// The probe asserts the constraint now, on both tables, and it reads the index's
// key expression rather than only the UNIQUE keyword — so a UNIQUE index on the
// raw column (which would still let ABC-D and abcd collide) does not satisfy it.
func TestUserCodeUniquenessIsEnforcedOnEveryDeviceTable(t *testing.T) {
	raw := readAll(t, migrationFiles(t))
	s := parseSchema(t, raw)

	// uniqueKeyOn returns the key expression of a UNIQUE index on table whose key
	// mentions col, or "" when there is none.
	uniqueKeyOn := func(table, col string) string {
		for _, body := range raw {
			up, _ := splitDirection(body)
			for _, m := range reIndex.FindAllStringSubmatchIndex(up, -1) {
				if !strings.Contains(strings.ToUpper(up[m[0]:m[1]]), "UNIQUE") {
					continue
				}
				if unquote(up[m[4]:m[5]]) != table {
					continue
				}
				open := strings.IndexByte(up[m[5]:], '(')
				if open < 0 {
					continue
				}
				start := m[5] + open
				end := matchClosingParen(up, start)
				if end < 0 {
					continue
				}
				spec := up[start+1 : end]
				if strings.Contains(strings.ToLower(spec), col) {
					return strings.TrimSpace(spec)
				}
			}
		}
		return ""
	}

	// Controls in both directions: both device tables really have the column, the
	// checker can see a known UNIQUE expression index, and it does not invent one
	// where the schema has none. Without these, a broken extractor could pass the
	// assertions below vacuously.
	const oidcDevices, legacyDevices = "oidc_devices", "oauth_device_authorizations"
	for _, table := range []string{oidcDevices, legacyDevices} {
		if _, ok := s.columns[table]["user_code"]; !ok {
			t.Fatalf("control failed: %s has no user_code column", table)
		}
	}
	if uniqueKeyOn(oidcDevices, "user_code") == "" {
		t.Fatal("control failed: oidc_devices.user_code is not seen as UNIQUE, so this probe proves nothing")
	}
	if uniqueKeyOn(legacyDevices, "client_id") != "" {
		t.Fatal("control failed: the checker reports a UNIQUE index where the schema has none")
	}

	for _, table := range []string{oidcDevices, legacyDevices} {
		key := strings.ToLower(strings.Join(strings.Fields(uniqueKeyOn(table, "user_code")), " "))
		if key == "" {
			t.Errorf("UNIQUENESS GAP: %s.user_code has no UNIQUE index, so two concurrent device "+
				"flows can share a user code and a human typing it resolves to whichever row the "+
				"scan reaches first", table)
			continue
		}
		// The key must be the canonical form the lookups compare, not the raw
		// column: codes are case- and separator-insensitive.
		var missing []string
		for _, want := range []string{"upper", "replace", "user_code"} {
			if !strings.Contains(key, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			t.Errorf("UNIQUENESS GAP: %s.user_code's UNIQUE index key is %q (missing %v); it must "+
				"canonicalise with upper(replace(user_code, '-', '')) so the case- and "+
				"separator-insensitive lookups (GetDeviceByUserCode) can use it",
				table, key, missing)
		}
	}
}
