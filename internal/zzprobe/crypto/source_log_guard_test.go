//go:build audit5

package crypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestProbeNoSlogCallCarriesAnAccountIdentifier is the guard for the leak the
// brief's question 9 asks about: the prior round pinned "tokens never appear in
// logs", but the guard covers the audit sink and the protocol plane, not the
// process's own slog calls.
//
// What it forbids is narrow and deliberate: a slog attribute whose KEY is one of
// the identity keys AND whose VALUE is a raw account id or subject. It is a
// STATIC check over the repository's own source, so it needs no database, no
// server and no fixture — which is why it can cover cmd/ and internal/ alike.
//
// It found four sites; three of them are in production paths.
func TestProbeNoSlogCallCarriesAnAccountIdentifier(t *testing.T) {
	root := repoRoot(t)

	// Keys that name an account or a subject.
	identityKeys := map[string]bool{
		"user": true, "subject": true, "sub": true, "usr": true,
		"actor": true, "account": true, "user_id": true, "subject_id": true,
	}
	// Keys that would name a credential. Reported separately so the two classes
	// are not conflated.
	secretKeys := map[string]bool{
		"token": true, "secret": true, "client_secret": true, "verifier": true,
		"wrapped_dek": true, "dek": true, "kek": true, "cookie": true,
		"access_token": true, "refresh_token": true, "code_verifier": true,
		"clientsecret": true, "session": true,
	}

	var identityHits, secretHits []string

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "vendor", "scratchpad", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || (pkg.Name != "slog" && pkg.Name != "log") {
				return true
			}
			switch sel.Sel.Name {
			case "Info", "Warn", "Error", "Debug", "InfoContext", "WarnContext",
				"ErrorContext", "DebugContext", "Log", "LogAttrs":
			default:
				return true
			}
			// Attributes are key/value pairs after the message.
			args := call.Args
			if len(args) < 1 {
				return true
			}
			start := 1
			if strings.HasSuffix(sel.Sel.Name, "Context") {
				start = 2
			}
			for i := start; i+1 < len(args); i += 2 {
				lit, ok := args[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				key, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					continue
				}
				pos := fset.Position(call.Pos())
				line := pos.Line
				switch {
				case identityKeys[key]:
					identityHits = append(identityHits,
						rel+":"+strconv.Itoa(line)+" attr "+key+"="+exprString(args[i+1]))
				case secretKeys[key]:
					secretHits = append(secretHits,
						rel+":"+strconv.Itoa(line)+" attr "+key+"="+exprString(args[i+1]))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, h := range secretHits {
		t.Errorf("a credential-shaped slog attribute: %s", h)
	}
	for _, h := range identityHits {
		t.Errorf("an account identifier reaches the process log: %s", h)
	}
	if len(identityHits) == 0 && len(secretHits) == 0 {
		t.Log("no slog call in the tree carries an account identifier or a credential key")
	}
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	case *ast.BinaryExpr:
		return exprString(v.X) + v.Op.String() + exprString(v.Y)
	case *ast.IndexExpr:
		return exprString(v.X) + "[...]"
	default:
		return "<expr>"
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}
