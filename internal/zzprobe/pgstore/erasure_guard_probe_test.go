//go:build audit5

package pgstore

// This file probes the reach of the account-erasure guard
// (TestEverySubjectColumnIsHandledByErasure in
// internal/store/postgres/erasure_schema_test.go) rather than re-testing its
// conclusions.
//
// The guard is the only thing that makes "no table with a subject column is
// forgotten by the erasure" true at pull-request time — TestAccountDeletionLeavesNoOrphans
// is the real check but it needs Postgres, and CI is the only place it runs. So
// the guard's *coverage* is load-bearing, and coverage is exactly what a guard
// test cannot assert about itself. That is what these probes measure.
//
// The synthetic migrations below are deliberately INLINE and are not written to
// any file: a probe must not add a real migration to the embeds (that would
// change what ships and what every other test sees), and the question here is
// what the guard would do with a given piece of DDL, which an inline string
// answers exactly.

import (
	"strings"
	"testing"
)

// erasureGuardMatches is the guard's detector, reproduced in helpers_test.go and
// held honest by TestGuardReproductionAgreesWithTheGuard below.
func erasureGuardMatches(cols string) bool {
	return guardAccountColumn(cols)
}

// --- 1. what the guard does see ---------------------------------------------

// guardExpectedTables is the set of tables the erasure guard must flag, taken
// from the union of two places in internal/store/postgres that state it:
// erasureHandledTables (the tables the erasure clears) and accountTablesIgnored
// (the one table the erasure deliberately leaves: audit_events, whose erasure is
// the pseudonym-key destruction instead).
//
// It is spelled out rather than computed from those maps so that a drift in
// either direction fails here: if the guard stops seeing a handled table, this
// probe says so; if the guard starts seeing a table nobody classified, the guard
// itself fails.
var guardExpectedTables = []string{
	"accounts_identities",
	"vault_credentials",
	"federation_bindings",
	"federation_bind_flows",
	"session_subjects",
	"oidc_auth_requests",
	"oidc_devices",
	"oidc_access_tokens",
	"oidc_refresh_tokens",
	"oidc_refresh_token_tombstones",
	"oauth_access_tokens",
	"oauth_refresh_tokens",
	"oauth_codes",
	"oauth_device_authorizations",
	"audit_events",
}

// TestGuardReproductionAgreesWithTheGuard is the drift control for
// guardAccountColumn: it asserts the reproduced detector reaches exactly the
// verdicts the two in-package maps already state. Without it the coverage probes
// below would be measuring my copy of the guard rather than the guard.
func TestGuardReproductionAgreesWithTheGuard(t *testing.T) {
	cols := probeTableCols(t)
	if len(cols) < 15 {
		t.Fatalf("parsed only %d tables; the probe parser is broken", len(cols))
	}
	for _, table := range guardExpectedTables {
		block, ok := cols[table]
		if !ok {
			t.Errorf("table %q is named as account-linked but no CREATE TABLE defines it", table)
			continue
		}
		if !guardAccountColumn(block) {
			t.Errorf("the reproduced detector does not flag %q, but the in-package maps say it is "+
				"account-linked — the reproduction has drifted from the guard", table)
		}
	}
	// The negative direction: a table that is account-linked only through a
	// non-subject column must NOT be flagged, or the reproduction is over-matching.
	for _, table := range []string{"accounts_users", "oauth_clients", "audit_subject_keys", "audit_chain"} {
		if block, ok := cols[table]; ok && guardAccountColumn(block) {
			t.Errorf("the reproduced detector flags %q, which the guard does not treat as subject-linked "+
				"(its account link is `id`/`idx`); the reproduction over-matches", table)
		}
	}
}

// TestErasureGuardSeesEverySubjectColumnInTheRealSchema is the control. Without
// it, "the guard missed X" could be a parser that matches nothing at all.
//
// The probe parses the same migrations independently (probeTableCols, which does
// not share the package's regex) and asserts the guard's verdict agrees with it
// for every table in the shipped schema.
func TestErasureGuardSeesEverySubjectColumnInTheRealSchema(t *testing.T) {
	found, tables := accColumnsInAllMigrations(t)
	if tables < 15 {
		t.Fatalf("parsed only %d CREATE TABLE statements; the probe parser is broken", tables)
	}
	if len(found) < 10 {
		t.Fatalf("found only %d account-linked tables; the probe parser is broken (the real schema has more)", len(found))
	}
	// The tables whose subject column the erasure path actually clears. If the
	// guard stopped seeing one of these, the guard would still pass and the table
	// would silently become unguarded.
	for _, must := range []string{
		"oauth_access_tokens", "oauth_refresh_tokens", "oauth_codes",
		"oidc_access_tokens", "oidc_refresh_tokens", "oidc_auth_requests",
		"oidc_devices", "vault_credentials", "federation_bindings",
		"federation_bind_flows", "session_subjects", "oauth_device_authorizations",
	} {
		if !found[must] {
			t.Errorf("the probe did not find table %q; the parser is not reading the migrations", must)
		}
		if !erasureGuardMatches(accColsOf(t, must)) {
			t.Errorf("the guard does not detect %q's subject column, so nothing would fail if the erasure "+
				"step for it were dropped", must)
		}
	}
}

// --- 2. what the guard cannot see -------------------------------------------

// TestErasureGuardMissesAlterTableAddColumn is the first coverage gap, stated
// where it can be re-run: the guard only parses `CREATE TABLE`, so a column
// added later by `ALTER TABLE ... ADD COLUMN` is invisible to it.
//
// Concretely: migration 0015 and 0016 both add columns to existing tables, so
// the mechanism is already the repository's habit. An
// `ALTER TABLE oidc_copies ADD COLUMN subject text` would carry an account
// reference that the guard cannot see and that the static erasure map cannot
// list, because the table it is on was already classified when it had no such
// column. The integration test would still catch it in CI, which is why this is
// a guard-coverage gap and not an unguarded hole — the gap is that a pull
// request gets no signal.
func TestErasureGuardMissesAlterTableAddColumn(t *testing.T) {
	const synthetic = `ALTER TABLE some_table ADD COLUMN subject text NOT NULL DEFAULT '';`

	if strings.Contains(synthetic, "CREATE TABLE") {
		t.Fatal("the synthetic statement is not an ALTER TABLE; the probe no longer tests what it claims")
	}
	if erasureGuardMatches(synthetic) {
		t.Fatal("the guard now detects an ALTER TABLE ADD COLUMN, so this gap is closed — delete this probe")
	}
	t.Log("CONFIRMED GAP: `ALTER TABLE ... ADD COLUMN subject ...` is invisible to the erasure guard " +
		"(it scans CREATE TABLE only); the column would be covered by CI's information_schema sweep but by " +
		"no pull-request check")
}

// TestErasureGuardOnlyRecognisesTwoExactColumnNames is the second gap: the guard
// matches the column names `subject` and `user_id` and nothing else, while the
// integration test's information_schema query asks the same two names. A table
// keyed by any other name for the same thing — which is how the
// membership/owner columns of a future table would most naturally be spelled —
// is uncovered by both.
func TestErasureGuardOnlyRecognisesTwoExactColumnNames(t *testing.T) {
	for _, cols := range []string{
		"account_id text NOT NULL",
		"owner text NOT NULL",
		"user text NOT NULL",
		"identity_subject text NOT NULL",
		"sub text NOT NULL",
	} {
		if erasureGuardMatches(cols) {
			t.Errorf("the guard now detects %q — this gap is closed for that spelling; update the probe", cols)
		}
	}
	// And the control: the two spellings it does know.
	for _, cols := range []string{"subject text NOT NULL", "user_id text NOT NULL"} {
		if !erasureGuardMatches(cols) {
			t.Errorf("the guard no longer detects %q; the control fails, so the gap rows above prove nothing", cols)
		}
	}
	t.Log("CONFIRMED GAP: only the exact column names `subject` and `user_id` are recognised; " +
		"`account_id`, `owner`, `user`, `identity_subject` are not")
}

// TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs is the third gap: the
// guard reasons over column NAMES, so an account id inside a `jsonb`/`bytea`
// value is outside its reach even in principle.
//
// The shipped schema already has exactly the shape that hides one: (a)
// `audit_events.detail jsonb` carries free-form context (that is how
// security-audit-2's A5-1 happened — a raw `usr_…` was written into
// `detail["actor"]` and the pseudonymising sink could not reach it); (b)
// `sessions.data bytea` is the scs payload, whose encoded bytes can name an
// account; (c) `vault_credentials.meta jsonb`.
//
// The probe asserts the structural fact (the columns exist, and the guard's
// detector sees no `subject` column on those tables) so the claim is checkable
// rather than asserted.
func TestErasureGuardIsBlindToAccountIdsInsideJsonAndBlobs(t *testing.T) {
	// (a) audit_events: the guard DOES see this table — because of its `subject`
	// column — and the erasure deliberately exempts it (accountTablesIgnored),
	// because the erasure is the pseudonym-key destruction. The row-shaped hole is
	// `detail`: a raw account id written into a jsonb value is outside the
	// pseudonymising sink's reach, which is exactly what security-audit-2's A5-1
	// was (a `usr_…` in detail["actor"]). That one was fixed in lifecycle.record;
	// what this probe records is that the *guard* cannot see a recurrence, because
	// it reasons over column names and a jsonb value has no name.
	auditCols := accColsOf(t, "audit_events")
	if !guardAccountColumn(auditCols) {
		t.Fatal("audit_events is no longer detected by the guard; the premise of this probe changed")
	}
	if !strings.Contains(auditCols, "detail") || !strings.Contains(auditCols, "jsonb") {
		t.Fatalf("audit_events no longer has a jsonb detail column; got:\n%s", auditCols)
	}

	// (b) sessions.data: the scs payload. It carries no account id today (the
	// store hashes the cookie and the subject lives in session_subjects), but
	// nothing in the schema or the guard would notice if a handler put one there.
	sessionCols := accColsOf(t, "sessions")
	if guardAccountColumn(sessionCols) {
		t.Fatal("sessions now reads as subject-linked to the guard; the premise of this probe changed")
	}
	if !strings.Contains(sessionCols, "data") || !strings.Contains(sessionCols, "bytea") {
		t.Fatalf("sessions no longer has a bytea data column; got:\n%s", sessionCols)
	}

	// (c) vault_credentials.meta: non-secret metadata, documented as PII at rest,
	// with no name-based guard over its contents.
	vaultCols := accColsOf(t, "vault_credentials")
	if !strings.Contains(vaultCols, "meta") || !strings.Contains(vaultCols, "jsonb") {
		t.Fatalf("vault_credentials no longer has a jsonb meta column; got:\n%s", vaultCols)
	}

	t.Log("CONFIRMED STRUCTURAL GAP: audit_events.detail (jsonb), sessions.data (bytea) and " +
		"vault_credentials.meta (jsonb) can each hold an account id, and the guard's name-based detector " +
		"cannot see into any of them; only the Postgres-backed information_schema sweep in CI decides " +
		"whether a value leaks, and it too only counts rows WHERE a subject-named column matches")
}

// --- 3. the defensive claim, checked -----------------------------------------

// TestNoAlterTableAddsASubjectColumnToday is the other half of the ALTER TABLE
// probe: the mechanism is invisible to the guard, so this asserts the shipped
// migrations do not currently use it to add an account reference. It is a real
// check on the schema today, and it is the guard the gap needs until the guard
// learns to read ALTER TABLE.
func TestNoAlterTableAddsASubjectColumnToday(t *testing.T) {
	addColumnRE := mustCompile(`(?is)ALTER\s+TABLE\s+("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)`)

	alters := 0
	for _, name := range migrationFiles(t) {
		body := stripLineComments(readMigration(t, name))
		for _, m := range addColumnRE.FindAllStringSubmatch(body, -1) {
			alters++
			table, col := unquote(m[1]), unquote(m[2])
			if col == "subject" || col == "user_id" {
				t.Errorf("%s adds account-reference column %s.%s by ALTER TABLE, which the erasure guard "+
					"(CREATE TABLE only) cannot see: add it to erasureHandledTables and teach the guard "+
					"about ALTER TABLE", name, table, col)
			}
		}
	}
	// Anti-vacuous: the repository really does use ALTER TABLE ADD COLUMN, so a
	// regex that matched nothing would make this test silently useless.
	if alters < 4 {
		t.Fatalf("found only %d ALTER TABLE ADD COLUMN statements; the schema has more (0009, 0010, 0013, "+
			"0015, 0016), so the parser is broken and this test proves nothing", alters)
	}
	t.Logf("scanned %d ALTER TABLE ADD COLUMN statements across the migrations", alters)
}
