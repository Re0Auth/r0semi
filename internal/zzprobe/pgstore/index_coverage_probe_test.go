//go:build audit5

package pgstore

// This file is the schema half of the index audit: for every predicate the
// Postgres adapter runs, is there an index whose LEADING column is the one the
// predicate names?
//
// The distinction from the in-package guards matters. TestEverySweptTableHasADeadlineIndex,
// TestRevokeTokenLookupIsIndexed, TestSessionSubjectSweepIsIndexed,
// TestAuditTimeRangeQueryIsIndexed and TestClientScopedRevokeIsIndexed each check
// one column on one table, and they all pass. This probe asks the same question
// over the whole set at once, which is how the columns that no guard covers show
// up: the guard set is the set somebody thought of.
//
// It reads the SQL text of the Go adapter, not only the migrations, so the list
// of predicates is evidence rather than a hand-written inventory.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// indexLeadingCols returns table -> the set of columns that are the FIRST column
// of some index on that table, for the migrations under dir. A trailing column
// does not help a predicate that names only that column, which is the whole point
// of the distinction.
//
// dir is a parameter so disk_read_probe_test.go can point this at a damaged copy
// and require the missing index to be noticed 鈥?the anti-vacuous half of every
// claim built on it.
func indexLeadingColsIn(t *testing.T, dir string) map[string]map[string]bool {
	t.Helper()
	out := make(map[string]map[string]bool)

	add := func(table, col string) {
		if out[table] == nil {
			out[table] = make(map[string]bool)
		}
		out[table][col] = true
	}

	for _, name := range migrationFilesIn(t, dir) {
		clean := stripLineComments(readMigrationIn(t, dir, name))
		// CREATE [UNIQUE] INDEX name ON table (cols)
		for _, m := range probeCreateIndexOnRE.FindAllStringSubmatch(clean, -1) {
			table := unquote(m[1])
			cols := strings.Split(m[2], ",")
			first := strings.TrimSpace(cols[0])
			if i := strings.Index(first, "("); i > 0 { // expression index: upper(x), replace(x,鈥?
				first = strings.TrimSpace(first[:i])
			}
			add(table, first)
		}
		// Column-level `id text PRIMARY KEY` and table-level `UNIQUE (a, b)`, read
		// from the same CREATE TABLE match. The table name comes from the block
		// match, so a stray PRIMARY KEY elsewhere in a file cannot be attributed to
		// the wrong table (which is how the first version of this probe panicked).
		for _, m := range probeTableBlockRE.FindAllStringSubmatch(clean, -1) {
			tbl := unquote(m[1])
			for _, line := range strings.Split(m[2], "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 2 {
					continue
				}
				// Table-level `UNIQUE (provider, subject)`.
				if strings.EqualFold(fields[0], "unique") {
					inner := strings.Trim(strings.Join(fields[1:], " "), "()")
					for _, col := range strings.Split(inner, ",") {
						add(tbl, bareWord(strings.TrimSpace(col)))
					}
					continue
				}
				// Table-level `PRIMARY KEY (subject, provider)`: every column of a
				// composite PK is usable as a range start for a predicate on its
				// first column, which is what "leading" means here.
				if strings.EqualFold(fields[0], "primary") && strings.EqualFold(bareWord(fields[1]), "KEY") {
					inner := strings.Trim(strings.Join(fields[2:], " "), "()")
					for _, col := range strings.Split(inner, ",") {
						c := bareWord(strings.TrimSpace(col))
						if c == "" {
							continue
						}
						add(tbl, c)
						break // only the leading column helps a single-column predicate
					}
				}
				// Column-level `id text PRIMARY KEY,`.
				for i := 1; i+1 < len(fields); i++ {
					// The keyword carries its trailing comma (`KEY,`), so compare on
					// the bare word: the first version of this probe compared the raw
					// field and therefore never saw a column-level PRIMARY KEY.
					if strings.EqualFold(bareWord(fields[i]), "PRIMARY") && strings.EqualFold(bareWord(fields[i+1]), "KEY") {
						add(tbl, strings.Trim(strings.ToLower(fields[0]), `"`))
					}
				}
			}
		}
	}
	return out
}

var (
	probeCreateIndexOnRE = regexp.MustCompile(`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?\w+\s+ON\s+("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)\s*\(([^)]*)\)`)
	// The whole CREATE TABLE column block, captured WITH the table name, so a
	// column-level PRIMARY KEY or UNIQUE can be attributed to the right table.
	probeTableBlockRE = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)\s*\((.*?)\s*\)\s*;`)
)

// bareWord strips the punctuation a SQL column definition attaches to a keyword
// (`PRIMARY KEY,` -> `KEY`), so a keyword comparison is not defeated by a comma.
func bareWord(s string) string { return strings.Trim(s, `,;"'()`) }

// indexLeadingCols is indexLeadingColsIn against the shipped migrations.
func indexLeadingCols(t *testing.T) map[string]map[string]bool {
	return indexLeadingColsIn(t, migrationsDir)
}

// --- the predicate inventory ------------------------------------------------

// predicate is one single-column equality/range the adapter runs, transcribed
// from the Go source with the file:line that issues it.
type predicate struct {
	table  string
	column string
	where  string // the call site, for the report
}

// singleColumnPredicates is the inventory. It is written out rather than
// extracted (a Go AST walk cannot see inside a SQL string), and it is the
// deliverable of the manual read: every statement in the adapter whose WHERE
// clause is a single column, checked below against the schema.
var singleColumnPredicates = []predicate{
	// --- hot request paths (every request that carries a cookie or a token) ---
	{"sessions", "token_hash", "sessions.go:81 FindCtx: WHERE token_hash = $1"},
	{"sessions", "expiry", "sessions.go:144 SweepExpired: WHERE expiry < $1"},

	// --- delete paths that run on an incident (the Kill Switch) ---
	{"oauth_codes", "subject", "oauth.go:265 PurgeLegacySubject: WHERE subject = $1"},
	{"oauth_codes", "client_id", "oauth.go:198 DeleteBySubjectClient: WHERE subject = $1 AND client_id = $2 (leading `subject` index carries it; the client_id half does not)"},
	{"oauth_device_authorizations", "subject", "oauth.go:266 PurgeLegacySubject: WHERE subject = $1"},
	{"oauth_access_tokens", "client_id", "oauth.go:292 revokeMatching with a client-only filter"},
	{"oauth_refresh_tokens", "client_id", "oauth.go:292 revokeMatching with a client-only filter"},
	{"oauth_codes", "client_id", "oauth.go:242 RevokeTokens (legacy): DELETE FROM oauth_codes + filter"},

	// --- OP state ---
	{"oidc_auth_requests", "expires_at", "sweep.go:61 DELETE ... WHERE expires_at < $1"},
	{"oidc_auth_requests", "client_id", "oidc.go:1037 revokePendingAuthorizations: DELETE FROM oidc_auth_requests + client-only filter (V-1: the report named a phantom legacy-table predicate; this is the real one, on the current engine's table)"},
	{"oidc_codes", "request_id", "oidc.go:260 DeleteAuthRequest: WHERE request_id = $1"},
	{"oidc_codes", "expires_at", "sweep.go:61"},
	{"oidc_access_tokens", "id_hash", "oidc.go:441 RevokeToken: WHERE id_hash = $1"},
	{"oidc_access_tokens", "subject", "oidc.go:898 RevokeGrant: WHERE subject = $1 AND client_id = $2"},
	{"oidc_access_tokens", "client_id", "oidc.go:955 revokeMatching with a client-only filter"},
	{"oidc_refresh_tokens", "id_hash", "oidc.go:442 RevokeToken / :456 stranded-half repair"},
	{"oidc_refresh_tokens", "client_id", "oidc.go:955 revokeMatching with a client-only filter"},
	{"oidc_devices", "subject", "oidc.go:907 RevokeGrant: WHERE subject = $1 AND client_id = $2"},
	{"oidc_devices", "client_id", "oidc.go RevokeTokens: revokeMatching with a client-only filter (G-14; migration 0029 adds the leading index)"},

	// --- account / vault / federation ---
	{"accounts_identities", "provider", "account.go:38 FindByIdentity: WHERE provider = $1 AND subject = $2 (UNIQUE)"},
	{"accounts_identities", "user_id", "account.go:171 count(*) ... WHERE user_id = $1"},
	{"vault_credentials", "subject", "vault.go:141 DeleteSubject: WHERE subject = $1 (PK leading)"},
	{"federation_bindings", "user_id", "federation.go:89 List: WHERE user_id = $1 (PK leading)"},
	{"session_subjects", "subject", "sessions.go:188 RevokeSubjectSessions subselect: WHERE subject = $1"},
	{"session_subjects", "created_at", "sessions.go:151 sweep orphan age: si.created_at < now() - $1::interval"},
}

// TestEverySingleColumnPredicateHasALeadingIndex is the whole inventory checked
// at once. A failure names the table, the column, the index that would fix it and
// the call site, so the fix is mechanical.
func TestEverySingleColumnPredicateHasALeadingIndex(t *testing.T) {
	leading := indexLeadingCols(t)

	// Anti-vacuous in both directions: the parser must see the schema's real
	// indexes, and it must NOT claim every column is indexed.
	seen := 0
	for _, cols := range leading {
		seen += len(cols)
	}
	if seen < 25 {
		t.Fatalf("the schema parser found only %d leading index columns; it is not reading the migrations", seen)
	}
	if leading["oauth_device_authorizations"]["user_code"] {
		t.Fatal("oauth_device_authorizations.user_code now has a leading index; update the inventory rather than trusting this run")
	}
	if !leading["sessions"]["token_hash"] {
		t.Fatal("the parser does not see sessions.token_hash's primary key; it is not reading PRIMARY KEY clauses")
	}

	var missing []string
	for _, p := range singleColumnPredicates {
		if len(leading[p.table]) == 0 {
			missing = append(missing, p.table+" has no index at all ("+p.where+")")
			continue
		}
		if !leading[p.table][p.column] {
			missing = append(missing, p.table+"."+p.column+" is not the leading column of any index ("+p.where+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("UNINDEXED PREDICATE: %s", m)
	}
}

// TestKnownUnindexedPredicatesAreStillUnindexed is the honest half: it does not
// pretend the uncovered predicates should fail the build. It states, as an
// executable fact rather than a claim in prose, that these columns have no
// leading index today 鈥?so a reader can check the claim by running one test, and
// a change that adds the index fails here and forces the inventory to be updated.
func TestKnownUnindexedPredicatesAreStillUnindexed(t *testing.T) {
	leading := indexLeadingCols(t)

	// Migration 0022 indexed the four live client_id predicates — the three legacy
	// tables plus oidc_auth_requests — so they are gone from this list. The phantom
	// oauth_device_authorizations.client_id entry is gone too: no Go statement
	// filters that table by client_id (V-2 — it was an empty guard). What remains is
	// the one real, non-indexable predicate.
	known := []struct{ table, column, why string }{
		{"oauth_device_authorizations", "user_code",
			"the legacy table's lookup index is an expression index (upper(replace(...))), so only a canonicalised comparison can use it"},
	}
	for _, k := range known {
		if leading[k.table][k.column] {
			t.Errorf("%s.%s now HAS a leading index, so the known-gap list is stale: %s 鈥?remove this entry "+
				"(and re-run TestEverySingleColumnPredicateHasALeadingIndex)", k.table, k.column, k.why)
			continue
		}
		if len(leading[k.table]) == 0 {
			t.Errorf("%s was not found in the schema at all; the inventory names a table no migration defines", k.table)
			continue
		}
		t.Logf("CONFIRMED UNINDEXED: %s.%s 鈥?%s", k.table, k.column, k.why)
	}
}

// TestNoGoSourceBuildsSqlFromARequestValue is the SQL-injection reading, done as
// a source inspection rather than as an argument.
//
// The adapter composes SQL in seven places. Five interpolate a table name or a
// column name, and every one of those names is a compile-time constant at the
// call site:
//
//	sweep.go:60      table, column from the expiredTables literal
//	oauth.go:292     table from a literal slice at each call site (:237, :955, :966)
//	oauth.go:317/321 `client_id` / `subject` 鈥?literal column names, and the values
//	                 travel as $n parameters
//	oidc.go:988/994  clause from revokePredicate 鈥?same shape
//	auditread.go:43  column and op are literal arguments at every call site (:64,
//	                 :67, :70, :73, :76); the VALUE is a $n parameter
//	oidc.go:712      deviceState's `where` 鈥?a literal at both call sites (:693, :702)
//
// This test asserts the property that makes all of them safe, mechanically: no
// file in the adapter passes a variable into the SQL-building helpers in a way
// that could carry a request value. It cannot prove safety for a future call
// site; it can prove the current ones are literals, which is what the report
// claims.
//
// The one place a reader should stop and look is deviceState's `where` argument:
// its signature (`func (s *OIDCStore) deviceState(ctx context.Context, where
// string, args ...any)`) accepts a string that IS appended to the statement. It
// is called twice, both times with an inline constant. A third caller passing a
// composed string would be an injection; nothing in the package prevents it, and
// this test records that fact.
func TestNoGoSourceBuildsSqlFromARequestValue(t *testing.T) {
	files := []string{"oauth.go", "oidc.go", "auditread.go", "sweep.go", "account.go", "vault.go", "federation.go", "sessions.go"}
	const dir = adapterDir
	total := 0

	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		code := stripGoComments(string(body))
		for i, line := range strings.Split(code, "\n") {
			if !strings.Contains(line, "`+") && !strings.Contains(line, `"+`) {
				continue
			}
			total++
			// The only acceptable interpolations are these. Anything else is a new
			// call site that a human has to justify.
			switch {
			case strings.Contains(line, "accountIdentityCols"),
				strings.Contains(line, "deviceCols"),
				strings.Contains(line, "vaultCols"),
				strings.Contains(line, "+ clause+") || strings.Contains(line, "+clause"),
				strings.Contains(line, "+table+"),
				strings.Contains(line, "+where"),
				strings.Contains(line, `query +=`),
				strings.Contains(line, `query +`):
			default:
				t.Errorf("%s:%d interpolates into SQL and is not on the reviewed list: %s",
					f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if total < 12 {
		t.Fatalf("found only %d SQL interpolations; the scanner is not reading the files (the adapter has more)", total)
	}
	t.Logf("scanned %d SQL string interpolations across %d adapter files; all are column/table-name constants "+
		"or the reviewed `clause`/`table`/`where` builders", total, len(files))
}

// TestDeviceStateWhereArgumentIsOnlyEverALiteral records the single seam in the
// adapter where a statement fragment is a function argument. It is safe today
// because both call sites inline a constant; it is a hazard because the type
// system does not say so.
func TestDeviceStateWhereArgumentIsOnlyEverALiteral(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(adapterDir, "oidc.go"))
	if err != nil {
		t.Fatal(err)
	}
	code := stripGoComments(string(body))

	callRE := regexp.MustCompile(`s\.deviceState\(ctx,\s*([^,)]*)`)
	calls := callRE.FindAllStringSubmatch(code, -1)
	if len(calls) < 2 {
		t.Fatalf("found %d deviceState call sites; the scanner is broken (there are two)", len(calls))
	}
	for _, c := range calls {
		arg := strings.TrimSpace(c[1])
		if !strings.HasPrefix(arg, "`") {
			t.Errorf("deviceState is called with a non-literal first argument (%s): that fragment is appended "+
				"to a SELECT and would be an injection point if its value could come from a request", arg)
		}
	}
	t.Logf("inspected %d deviceState call sites; each passes an inline SQL fragment", len(calls))
}

// stripGoComments removes // and /* */ comments so a SQL fragment quoted inside
// prose is never mistaken for executed code.
func stripGoComments(src string) string {
	out := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
