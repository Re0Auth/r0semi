package postgres

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// erasureHandledTables are the account-linked tables that lifecycle.Deleter
// clears, each mapped to the step that clears it. The map is the contract the
// static check below enforces: a table with a `subject` or `user_id` column that
// appears in neither this map nor accountTablesIgnored fails the build.
var erasureHandledTables = map[string]string{
	"accounts_identities":         "accounts.DeleteUser (ON DELETE CASCADE)",
	"vault_credentials":           "vault.DeleteSubject",
	"federation_bindings":         "bindings.RevokeUserBindings",
	"federation_bind_flows":       "flows.PurgeUserFlows",
	"session_subjects":            "sessions.RevokeSubjectSessions",
	"oidc_auth_requests":          "oidc.PurgeSubject",
	"oidc_devices":                "oidc.PurgeSubject",
	"oidc_access_tokens":          "tokens.RevokeTokens",
	"oidc_refresh_tokens":         "tokens.RevokeTokens",
	"oauth_access_tokens":         "tokens.RevokeTokens (legacy)",
	"oauth_refresh_tokens":        "tokens.RevokeTokens (legacy)",
	"oauth_codes":                 "legacy.PurgeLegacySubject",
	"oauth_device_authorizations": "legacy.PurgeLegacySubject",
}

// createTableRE captures a table name and its column block from a CREATE TABLE.
// Column bodies contain no nested parentheses in this schema, so a non-greedy
// match to the first `);` is sufficient and stays readable.
var createTableRE = regexp.MustCompile(`(?is)CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\((.*?)\);`)

// TestEverySubjectColumnIsHandledByErasure is the database-free half of the
// account-deletion guard.
//
// TestAccountDeletionLeavesNoOrphans proves the erasure is complete, but it needs
// Postgres. This one parses the migrations and answers a different question at PR
// time: does any table carry an account reference that nobody clears? Adding a
// table with a `subject` or `user_id` column without teaching the erasure about it
// fails here, with the fix in the message — rather than surfacing as a compliance
// gap nobody notices.
func TestEverySubjectColumnIsHandledByErasure(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	found := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range createTableRE.FindAllStringSubmatch(string(body), -1) {
			table, cols := m[1], m[2]
			if hasAccountColumn(cols) {
				found[table] = true
			}
		}
	}
	if len(found) < 8 {
		t.Fatalf("parsed only %d account-linked tables; the parser is broken", len(found))
	}

	for table := range found {
		_, handled := erasureHandledTables[table]
		_, ignored := accountTablesIgnored[table]
		if !handled && !ignored {
			t.Errorf("table %q has a subject/user_id column but nothing clears it on account deletion.\n"+
				"Add a step to lifecycle.Deleter and list it in erasureHandledTables, "+
				"or add it to accountTablesIgnored with the reason it must survive.", table)
		}
	}
	// And the reverse: a name in the map that no migration defines is stale.
	// accountTablesIgnored is shared with the integration test, so both directions
	// stay honest.
	for table := range erasureHandledTables {
		if !found[table] {
			t.Errorf("erasureHandledTables names %q, which no migration defines (stale entry?)", table)
		}
	}
}

// hasAccountColumn reports whether a CREATE TABLE column block declares a
// `subject` or `user_id` column. It matches the column name at the start of a
// line and requires the whole word, so `subject_x` does not match.
func hasAccountColumn(cols string) bool {
	for _, line := range strings.Split(cols, "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(line, "--") {
			continue
		}
		for _, col := range []string{"subject", "user_id"} {
			if line == col {
				return true
			}
			rest := strings.TrimPrefix(line, col)
			if rest != line {
				// The column name must be followed by whitespace then a type.
				if r := strings.TrimLeft(rest, " \t"); r != rest && len(r) > 0 {
					return true
				}
			}
		}
	}
	return false
}
