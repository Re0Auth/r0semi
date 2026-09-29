//go:build audit7

package z21migrationsschemaintegrity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// TestAuditLogHasNoSchemaLevelAppendOnlyGuard asks whether "append-only" is a
// property of the schema or of the convention of the code that happens to hold
// the table grant.
//
// Migration 0013's own comment says the chain "make[s] a rewrite detectable"
// and that "nothing in the schema stopped a role with the table grant from
// rewriting or deleting rows". Detectable is not prevented: a role holding
// DELETE can destroy the rows and the chain head together, and Verify's head
// witness only catches the case where the head survives. There is no trigger,
// no REVOKE and no RLS policy in the shipped migrations.
//
// This test is a guard, not a claim that the project should have triggers; it
// makes the absence explicit and fails if a PARTIAL guard is ever mistaken for
// the whole one.
func TestAuditLogHasNoSchemaLevelAppendOnlyGuard(t *testing.T) {
	raw := readAll(t, migrationFiles(t))
	var all strings.Builder
	for _, body := range raw {
		// Comments are stripped: the word "grant" appears in 0013's prose and a
		// prose hit is exactly the vacuous evidence this probe must not produce.
		all.WriteString(strings.ToUpper(stripSQLComments(body)))
		all.WriteByte('\n')
	}
	sql := all.String()

	for _, shape := range []string{"CREATE TRIGGER", "CREATE POLICY", "ROW LEVEL SECURITY", "REVOKE "} {
		if strings.Contains(sql, shape) {
			t.Errorf("the probe's premise changed: the migrations now contain %q", shape)
		}
	}
	// The DML the shipped store issues against audit_events. If this ever grows a
	// DELETE or UPDATE, the append-only claim in audit.go's doc comment is false.
	dml := auditEventsDML(t)
	for _, verb := range []string{"DELETE", "UPDATE", "TRUNCATE"} {
		if dml[verb] {
			t.Errorf("APPEND-ONLY VIOLATED IN CODE: the shipped store issues %s against audit_events", verb)
		}
	}
	if !dml["INSERT"] {
		t.Fatal("control failed: no INSERT against audit_events was found, so the scan saw nothing")
	}

	// Retention: nothing in the migrations removes old audit rows, and nothing
	// caps the table. That is the documented trade-off for a hash chain, but it
	// means the log and the Verify walk grow without bound; state it here so a
	// future partition/retention migration is a visible change.
	if strings.Contains(sql, "PARTITION") {
		t.Logf("audit_events is partitioned")
	}
	if strings.Contains(strings.ToUpper(strings.Join(expiredTableNames(t), " ")), "AUDIT_EVENTS") {
		t.Errorf("audit_events is now part of the expiry sweep; the chain's integrity claim needs re-reading")
	}
}

// expiredTableNames reads internal/store/postgres/sweep.go's expiredTables list.
func expiredTableNames(t *testing.T) []string {
	t.Helper()
	src, err := readFileString(repoRoot(t), "internal", "store", "postgres", "sweep.go")
	if err != nil {
		t.Fatalf("read sweep.go: %v", err)
	}
	re := regexp.MustCompile(`\{"([a-z_]+)",\s*"([a-z_]+)"\}`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out = append(out, strings.ToUpper(m[1])+"."+strings.ToUpper(m[2]))
	}
	if len(out) < 8 {
		t.Fatalf("recovered only %d swept tables from sweep.go; the extractor is broken", len(out))
	}
	return out
}

// auditEventsDML returns the DML verbs the shipped store uses against
// audit_events, read from the Go AST rather than a text search.
func auditEventsDML(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range storeFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text := strings.ToUpper(strings.Trim(lit.Value, "`\""))
			if !strings.Contains(text, "AUDIT_EVENTS") {
				return true
			}
			for _, verb := range []string{"INSERT INTO AUDIT_EVENTS", "DELETE FROM AUDIT_EVENTS", "UPDATE AUDIT_EVENTS", "TRUNCATE"} {
				if strings.Contains(text, verb) {
					out[strings.Fields(verb)[0]] = true
				}
			}
			return true
		})
	}
	if !out["INSERT"] && !out["DELETE"] && !out["UPDATE"] {
		t.Fatalf("found no DML against audit_events; the scan is broken")
	}
	return out
}
