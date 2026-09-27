//go:build audit5

package pgstore

// Two properties of the adapter that are decidable from the source and that the
// package's own tests do not check:
//
//  1. how a Postgres error becomes a domain error (and what it carries), and
//  2. which multi-statement mutations run in a transaction.
//
// Both are source-level, so both are executable here. Neither claims to have
// been run against a database.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestUniqueViolationMappingDropsNoSQLDetail pins what the adapter does with a
// 23505: it maps it to a domain error and passes nothing else along.
//
// The disclosure question matters because a pgconn.PgError's Error() is
// "ERROR: duplicate key value violates unique constraint \"accounts_identities_provider_subject_key\"
// (SQLSTATE 23505)" 鈥?the constraint name, and in some shapes the failing row's
// values. So the check is that the mapping is by CODE only, and that the
// original error is not wrapped into the value that travels onward.
func TestUniqueViolationMappingDropsNoSQLDetail(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(adapterDir, "postgres.go"))
	if err != nil {
		t.Fatal(err)
	}
	code := stripGoComments(string(body))

	if !strings.Contains(code, `pgErr.Code == "23505"`) {
		t.Error("isUniqueViolation no longer compares against SQLSTATE 23505 by code; check it is not matching " +
			"a constraint NAME (which is deployment-specific and would break silently on a renamed index)")
	}
	if strings.Contains(code, "pgErr.ConstraintName") {
		t.Error("isUniqueViolation now reads the constraint name; that string is schema detail an error " +
			"message could carry outward")
	}
	if !strings.Contains(code, "var pgErr *pgconn.PgError") || !strings.Contains(code, "errors.As(err, &pgErr)") {
		t.Error("isUniqueViolation does not unwrap through errors.As, so a wrapped 23505 would be missed " +
			"and surface as a 500 instead of the domain error")
	}

	// The mapping sites: a 23505 must become a domain error, not a bare return.
	sites := map[string]string{
		"account.go": "ErrIdentityTaken",
		"oidc.go":    "op.ErrDuplicateUserCode",
	}
	for file, want := range sites {
		src, err := os.ReadFile(filepath.Join(adapterDir, file))
		if err != nil {
			t.Fatal(err)
		}
		s := stripGoComments(string(src))
		if !strings.Contains(s, "isUniqueViolation(") {
			t.Errorf("%s no longer consults isUniqueViolation", file)
			continue
		}
		if !strings.Contains(s, want) {
			t.Errorf("%s does not map a unique violation to %s", file, want)
		}
	}
	t.Log("isUniqueViolation matches SQLSTATE 23505 only, and both call sites map it to a domain error " +
		"(account.ErrIdentityTaken / op.ErrDuplicateUserCode) without wrapping the driver error")
}

// TestTokenTablesHaveNoRowLevelSecurityOrTrigger records what the schema does
// NOT enforce, because the audit chain's own migration says it plainly: the
// append-only property is a convention plus the chain, not a database control.
//
// This is a *documented* limitation (docs/architecture.md 搂4.16: "杩佺Щ閲屾病鏈?// trigger銆佹病鏈夋潈闄愰檺鍒?), so it is not reported as a defect. The probe exists so
// that the claim "there is no trigger and no GRANT/REVOKE in this schema" is a
// checkable fact rather than a reading, and so that adding one later fails here
// and forces the documentation to be updated with it.
func TestTokenTablesHaveNoRowLevelSecurityOrTrigger(t *testing.T) {
	featureRE := regexp.MustCompile(`(?is)\b(GRANT|REVOKE|CREATE\s+TRIGGER|CREATE\s+POLICY|ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+ROLE)\b`)
	found := 0
	for _, name := range migrationFiles(t) {
		body := stripLineComments(readMigration(t, name))
		for _, m := range featureRE.FindAllStringSubmatch(body, -1) {
			found++
			t.Logf("%s declares %s 鈥?docs/architecture.md 搂4.16 says the schema has no triggers and no "+
				"privilege restrictions; update that text if this is deliberate", name, strings.ToUpper(m[1]))
		}
	}
	if found == 0 {
		t.Log("CONFIRMED: no migration declares a trigger, a policy, row-level security, a role or any " +
			"GRANT/REVOKE 鈥?the append-only property of audit_events is the chain plus convention, exactly " +
			"as docs/architecture.md 搂4.16 states")
	}
}

// --- multi-statement atomicity ----------------------------------------------

// TestMultiStatementMutationsRunInATransaction compares the store methods that
// issue more than one write against the ones that wrap them in a transaction.
//
// The adapter is inconsistent here, and the inconsistency is invisible from the
// outside: every one of these methods reports an error when a statement fails,
// so a partial application looks like an ordinary failure. What differs is what
// the retry has to reason about 鈥?and for the Kill Switch the count it returns is
// the operator's evidence that the account is contained.
//
// The probe reads the method bodies out of the source and asserts the set of
// multi-write methods that are NOT protected, so the list cannot silently grow.
func TestMultiStatementMutationsRunInATransaction(t *testing.T) {
	// Methods that issue two or more writes and DO open a transaction. If one of
	// these loses its Begin, the probe fails.
	protected := map[string][]string{
		"sessions.go":   {}, // asserted empty below: see the note
		"oauth.go":      {"DeleteBySubjectClient"},
		"oidc.go":       {"RevokeGrant", "TerminateSession", "PurgeSubject", "RevokeTokens", "revokeInOneTx", "DeleteAuthRequest"},
		"account.go":    {"CreateWithIdentity", "LinkIdentity", "UnlinkIdentity"},
		"sweep.go":      {"SweepExpired"},
		"auditchain.go": {"appendBatch"},
	}

	for file, methods := range protected {
		src, err := os.ReadFile(filepath.Join(adapterDir, file))
		if err != nil {
			t.Fatal(err)
		}
		code := stripGoComments(string(src))
		for _, m := range methods {
			body := methodBody(t, code, m)
			if !strings.Contains(body, ".Begin(") {
				t.Errorf("%s: %s no longer opens a transaction, but it issues more than one write", file, m)
			}
		}
	}

	// The unprotected set. Each entry is a method that issues two statements with
	// no transaction; the report states the interleaving that breaks for each.
	unprotected := map[string][]string{
		"sessions.go": {"RevokeAllSessions", "RevokeSubjectSessions", "SweepExpired"},
		"oauth.go":    {"RevokeTokens", "PurgeLegacySubject"},
	}
	for file, methods := range unprotected {
		src, err := os.ReadFile(filepath.Join(adapterDir, file))
		if err != nil {
			t.Fatal(err)
		}
		code := stripGoComments(string(src))
		for _, m := range methods {
			body := methodBody(t, code, m)
			if strings.Contains(body, ".Begin(") {
				t.Errorf("%s: %s now opens a transaction 鈥?remove it from this list and from the report", file, m)
				continue
			}
			// Count the writes, not the Exec calls: RevokeTokens routes through
			// revokeMatching, which loops over a table list, so the statements are
			// not lexically inside this method. The keywords are what decides "more
			// than one write", and the helper calls are named so the count is
			// legible.
			writes := countWrites(body)
			if writes < 2 {
				t.Errorf("%s: %s issues only %d write(s); the entry is stale", file, m, writes)
				continue
			}
			t.Logf("CONFIRMED NOT ATOMIC: %s %s issues %d write(s) with no transaction", file, m, writes)
		}
	}
}

// countWrites counts the statements that modify data in a method body: each
// INSERT/UPDATE/DELETE, plus one for each call to a named multi-table helper
// (revokeMatching loops over its table list), plus each string literal in a
// `[]string{...}` of statements, which is how the adapter writes a batch of
// deletes.
func countWrites(body string) int {
	upper := strings.ToUpper(body)
	n := strings.Count(upper, "INSERT INTO") +
		strings.Count(upper, "UPDATE ") +
		strings.Count(upper, "DELETE FROM")
	n += strings.Count(body, "revokeMatching(")
	n += strings.Count(body, "revokePendingAuthorizations(")
	// A statement literal that is not the first one (the first was already counted
	// by its keyword) means the method issues a batch.
	n += strings.Count(body, "`DELETE FROM") - 1
	if n < 0 {
		n = 0
	}
	return n
}

// methodBody returns the source of one method, from its `func (鈥? Name(` line to
// the next top-level `func ` or `// ` block comment, which is enough to see
// whether a transaction is opened inside it.
func methodBody(t *testing.T, code, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \([^)]*\) ` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(code)
	if loc == nil {
		t.Fatalf("method %s not found; the probe is not reading the file (was it renamed?)", name)
	}
	rest := code[loc[0]:]
	// Cut at the next top-level func declaration.
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	if strings.TrimSpace(rest) == "" {
		t.Fatalf("method %s extracted as empty text", name)
	}
	return rest
}

// TestSweepStatementListMatchesExpiredTables checks the one piece of the sweep
// that a schema change can silently invalidate: expiredTables names a table and a
// column per entry, and Sprintf puts them straight into a DELETE. A typo is a
// runtime error on a scheduled job (the failure mode 0017's comment describes),
// and nothing asserts that every name is a real table with a real deadline
// column.
func TestSweepStatementListMatchesExpiredTables(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adapterDir, "sweep.go"))
	if err != nil {
		t.Fatal(err)
	}
	code := stripGoComments(string(src))

	entryRE := regexp.MustCompile(`\{"([a-z_]+)",\s*"([a-z_]+)"\}`)
	entries := entryRE.FindAllStringSubmatch(code, -1)
	if len(entries) < 8 {
		t.Fatalf("parsed only %d expiredTables entries; the parser is broken (there are ten)", len(entries))
	}

	cols := probeTableCols(t)
	seen := map[string]bool{}
	for _, m := range entries {
		table, col := m[1], m[2]
		seen[table] = true
		block, ok := cols[table]
		if !ok {
			t.Errorf("expiredTables names table %q, which no migration creates: the sweep would fail at "+
				"runtime with `relation does not exist`", table)
			continue
		}
		if !strings.Contains(block, col) {
			t.Errorf("expiredTables names %s.%s, but the CREATE TABLE for %s has no such column: "+
				"`DELETE FROM %s WHERE %s < $1` would fail every sweep", table, col, table, table, col)
		}
	}
	// The reverse direction: a dated table added later and left out of the sweep is
	// the failure 0017 was about, and this is where it would show up.
	dated := []string{}
	for table, block := range cols {
		if strings.Contains(block, "expires_at") && !seen[table] {
			dated = append(dated, table)
		}
	}
	sort.Strings(dated)
	for _, table := range dated {
		t.Logf("NOTE: %s has an expires_at column but is not swept by SweepExpired; if that is deliberate "+
			"(sessions has its own sweep), no action", table)
	}
	if len(seen) < 8 {
		t.Fatalf("the sweep covers only %d tables; check that entries were not lost", len(seen))
	}
}
