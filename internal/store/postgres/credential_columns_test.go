package postgres

import (
	"io/fs"
	"strings"
	"testing"
)

// credentialColumnWords are the substrings that mark a column as able to hold a
// credential. Matching is on the whole lowercased column name.
var credentialColumnWords = []string{"token", "secret", "credential", "password", "verifier", "key"}

// credentialColumnAllowed lists every column that matches one of those words and
// is still correct, with the reason. Anything else is a finding.
//
// The list is keyed by `table.column` so adding a table cannot silently inherit an
// exemption, and it is deliberately explicit: the point of the test is that a new
// credential-shaped column has to be justified here, in writing, by whoever adds
// it.
var credentialColumnAllowed = map[string]string{
	// The upstream token's CLASS (revocable / long_lived), not the token.
	"federation_bindings.token_type": "holds the token class, not a token",

	// Hashes, not values: the store keys records by TokenHash(value) precisely so a
	// dump yields no usable credential.
	"oauth_codes.token_hash":          "sha256 of the code",
	"oauth_access_tokens.token_hash":  "sha256 of the access token",
	"oauth_refresh_tokens.token_hash": "sha256 of the refresh token",
	"oidc_refresh_tokens.token_hash":  "sha256 of the refresh token",
	"sessions.token_hash":             "sha256 of the session cookie",
	"session_subjects.token_hash":     "sha256 of the session cookie",
	"oauth_clients.secret_hash":       "sha256 of the client secret",

	// A PKCE verifier cannot be stored as a hash: the exchange has to send it. It is
	// short-lived, single-use, and useless alone — completing the exchange also
	// needs the authorization code, which only goes to the registered redirect URI.
	// Documented in migration 0003 and docs/threat-model.md §6.1.
	"federation_bind_flows.pkce_verifier": "PKCE verifier, necessarily readable for the exchange",

	// The per-subject pseudonym key (migration 0014). It is what makes an account's
	// audit history resolvable, which is why deleting it IS the erasure; it is not a
	// credential for anything and grants no access.
	"audit_subject_keys.key": "per-subject audit pseudonym key; deleting it is the erasure",
}

// TestNoColumnCanHoldACredential enumerates EVERY column in every table and refuses
// any credential-shaped name that is not on the allowlist above.
//
// The previous version of this check inspected one table — `federation_bindings` —
// while its comment read as a general guarantee. A migration adding
// `oidc_devices.device_secret`, or a whole new table of upstream tokens, would have
// passed every guard in the repository.
//
// It runs without a database, so it fails on a pull request rather than only in the
// integration job.
func TestNoColumnCanHoldACredential(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	inspected := 0
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
			for _, col := range columnNames(cols) {
				inspected++
				if reason, ok := credentialColumnAllowed[table+"."+col]; ok {
					_ = reason
					continue
				}
				for _, word := range credentialColumnWords {
					if strings.Contains(col, word) {
						t.Errorf("%s.%s looks like it can hold a credential (%q).\n"+
							"If it does not, add it to credentialColumnAllowed with the reason. "+
							"If it does, it belongs in the vault.", table, col, word)
						break
					}
				}
			}
		}
	}
	// Anti-vacuous: a parser that stopped matching would otherwise pass silently.
	if inspected < 50 {
		t.Fatalf("inspected only %d columns; the parser is broken", inspected)
	}
}

// columnNames pulls the column names out of a CREATE TABLE column block, skipping
// constraint lines and comments.
func columnNames(cols string) []string {
	var out []string
	for _, line := range strings.Split(cols, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		switch name {
		case "primary", "unique", "foreign", "constraint", "check", "exclude":
			continue // table-level constraints are not columns
		}
		out = append(out, strings.Trim(name, `"`))
	}
	return out
}
