//go:build audit5

package crypto

import (
	"go/ast"
	"go/build"
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
// 【原为发现演示，现为回归守卫】This probe started as the audit-5 demonstration of
// seven production sites that logged an account identifier
// (docs/audit-7/audit5-red.log:44-50). Those sites are G-23 and are fixed in
// 6665193; the probe is now the regression guard for that fix, and it must fail
// again the moment one of them (or any new production site) regrows the shape.
//
// What it forbids is narrow and deliberate: a slog attribute whose KEY is one of
// the identity keys AND whose VALUE is a raw account id or subject. It is a
// STATIC check over the repository's own source, so it needs no database, no
// server and no fixture — which is why it can cover cmd/ and internal/ alike.
//
// Scope refinement, so the guard is not silently red forever on a build that is
// not the product: the check now evaluates only non-test .go files that a
// release build can compile (see excludedFromReleaseBuild). The one site left in
// the tree when the guard is run — cmd/re0auth/conformance_autologin.go:65-66,
// which logs the fixed sentinel `usr_conformance` as `subject` — lives in a file
// gated by `//go:build conformance`, a tag no release target passes
// (docs/conformance.md:251-252: "the code exists only under the build tag, and
// no release target passes tags (Makefile:169 builds with go build -trimpath)").
// Its subject is the documented synthetic one (docs/conformance.md:248-249).
// Scanning it as if it were product code is what made the guard report a leak
// that cannot reach a deployed process log. The detection itself is unchanged
// and is proven non-vacuous by the planted-source control at the end.
//
// Anti-vacuity, explicitly: the guard (a) counts the files it actually scanned,
// (b) unit-checks the build-constraint filter against a planted tagged file, and
// (c) runs the matcher over a planted source that DOES carry both shapes, so a
// matcher that regressed to "find nothing" cannot pass.
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
	scanned, excluded := 0, 0

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
		// A file no release build can compile cannot reach a deployed process
		// log; see the doc comment. Failure to decide keeps the file in scope.
		if excludedFromReleaseBuild(filepath.Dir(path), d.Name()) {
			excluded++
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		scanned++
		for _, h := range scanSlogAttrs(fset, f, identityKeys, secretKeys) {
			line := rel + ":" + strconv.Itoa(h.line) + " attr " + h.attr
			if h.identity {
				identityHits = append(identityHits, line)
			} else {
				secretHits = append(secretHits, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// (a) The walk must have scanned the tree, not skipped it into a green.
	if scanned < 100 {
		t.Fatalf("only %d non-test .go files were scanned (%d skipped by build constraints); "+
			"the guard has gone blind", scanned, excluded)
	}
	// (b) The build-constraint filter itself: a tagged file must be excluded, an
	// untagged one kept. This is the mechanism that keeps the conformance-only
	// site out, so it is checked directly rather than inferred.
	filterDir := t.TempDir()
	plantedTagged := filepath.Join(filterDir, "conformance_only.go")
	plantedPlain := filepath.Join(filterDir, "release.go")
	if err := os.WriteFile(plantedTagged, []byte("//go:build conformance\n\npackage p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plantedPlain, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !excludedFromReleaseBuild(filterDir, "conformance_only.go") {
		t.Errorf("a //go:build conformance file was treated as release code: the filter is inert")
	}
	if excludedFromReleaseBuild(filterDir, "release.go") {
		t.Errorf("an untagged .go file was excluded: the filter is too broad")
	}
	// (c) The matcher still fires on a planted source carrying both shapes.
	plantedSrc := `package p

import "log/slog"

func f(subject, secret string) {
	slog.Info("auth", "subject", subject)
	slog.Warn("token", "client_secret", secret)
}
`
	plantedSet := token.NewFileSet()
	plantedFile, perr := parser.ParseFile(plantedSet, "planted.go", plantedSrc, 0)
	if perr != nil {
		t.Fatal(perr)
	}
	var plantedIdentity, plantedSecret int
	for _, h := range scanSlogAttrs(plantedSet, plantedFile, identityKeys, secretKeys) {
		if h.identity {
			plantedIdentity++
		} else {
			plantedSecret++
		}
	}
	if plantedIdentity == 0 || plantedSecret == 0 {
		t.Fatalf("the matcher found nothing in a planted source with both shapes "+
			"(identity=%d secret=%d): the detection is vacuous", plantedIdentity, plantedSecret)
	}

	for _, h := range secretHits {
		t.Errorf("a credential-shaped slog attribute: %s", h)
	}
	for _, h := range identityHits {
		t.Errorf("an account identifier reaches the process log: %s", h)
	}
	if len(identityHits) == 0 && len(secretHits) == 0 {
		t.Logf("no release-compilable slog call in the tree carries an account identifier or a "+
			"credential key (%d files scanned, %d excluded by build constraints)", scanned, excluded)
	}
}

// slogAttrHit is one offending slog attribute found by scanSlogAttrs.
type slogAttrHit struct {
	identity bool
	line     int
	attr     string
}

// scanSlogAttrs is the detection, factored out of the walk so the planted-source
// control in the test can run the exact same logic. A walk that finds nothing is
// only meaningful if this still finds something.
func scanSlogAttrs(fset *token.FileSet, f *ast.File, identityKeys, secretKeys map[string]bool) []slogAttrHit {
	var hits []slogAttrHit
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
			line := fset.Position(call.Pos()).Line
			switch {
			case identityKeys[key]:
				hits = append(hits, slogAttrHit{identity: true, line: line, attr: key + "=" + exprString(args[i+1])})
			case secretKeys[key]:
				hits = append(hits, slogAttrHit{identity: false, line: line, attr: key + "=" + exprString(args[i+1])})
			}
		}
		return true
	})
	return hits
}

// releaseBuildContexts are the build contexts a release could be produced for.
// A file is kept when ANY of them matches it: the shipped releases are
// linux/windows/darwin on amd64/arm64, and evaluating only the host context
// would hide a leak in, say, a //go:build linux file whenever the guard ran on
// Windows.
var releaseBuildContexts = func() []build.Context {
	var out []build.Context
	for _, goos := range []string{"linux", "windows", "darwin"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			c := build.Default
			c.GOOS, c.GOARCH = goos, goarch
			c.BuildTags = nil
			out = append(out, c)
		}
	}
	return out
}()

// excludedFromReleaseBuild reports whether a file's build constraints keep it out
// of every release build. A constraint the evaluator cannot parse is treated as
// "not excluded": a file the guard cannot classify stays in scope rather than
// escaping through an error.
func excludedFromReleaseBuild(dir, name string) bool {
	matched := false
	for _, c := range releaseBuildContexts {
		ok, err := c.MatchFile(dir, name)
		if err != nil {
			return false
		}
		if ok {
			matched = true
		}
	}
	return !matched
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
