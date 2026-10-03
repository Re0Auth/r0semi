//go:build audit7

package z16guardtestquality

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file is a meta-guard: it reads the repository's own tests and reports the
// ones that assert nothing about the thing they are named after. A test that
// computes a verdict and only prints it —the shape round 5 shipped in
// internal/zzprobe/federation/raw_test.go and round 6 shipped in
// internal/zzprobe/pubaddr/addr_test.go —is worse than no test: it is cited as
// evidence in an audit document while a green run says nothing at all.
//
// "Asserts nothing" is decided syntactically, on purpose: the question is whether
// any statement in the function can call a *failing* method on the *testing.T it
// was handed, directly or through a helper that takes that T. A test that reads a
// fixture and logs it fails this, and should hold its assertion behind a helper.
//
// The first version of this scanner missed tests whose only call that mentions t
// was a *fixture* helper (`srv := zzProbeServer(t, nil)`), because it treated any
// call that received t as able to assert. This version resolves the call graph
// inside each test package: a call counts as an assertion only when the callee
// can actually fail, and fatal-only capability (a fixture that t.Fatal's on a
// setup error) is reported separately, because it cannot fail on the property the
// test is named after.

// reportOnlyMethods are the *testing.T methods that do not make a test fail and
// therefore do not count as an assertion.
var reportOnlyMethods = map[string]bool{
	"Log": true, "Logf": true, "Skip": true, "Skipf": true, "SkipNow": true,
	"Helper": true, "Name": true, "Cleanup": true, "TempDir": true,
	"Setenv": true, "Parallel": true, "Deadline": true, "Context": true,
	"Run": true, "Chdir": true, "Output": true, "Attr": true,
}

// fatalMethods end the test but are what a *fixture* uses for a setup error: they
// are a failure only when the fixture itself is broken, never a statement about
// the property the test names.
var fatalMethods = map[string]bool{
	"Fatal": true, "Fatalf": true, "FailNow": true,
}

// failingMethods is every *testing.T method that fails the test.
func failingMethod(name string) bool { return !reportOnlyMethods[name] }

// errorMethod is a non-fatal failing method: t.Error, t.Errorf, t.Fail, t.Failf.
func errorMethod(name string) bool { return failingMethod(name) && !fatalMethods[name] }

// funcInfo is one top-level function or method in a test package.
type funcInfo struct {
	name       string
	file       string
	line       int
	tNames     []string // parameter names whose type is *testing.T / testing.TB
	body       *ast.BlockStmt
	recv       bool
	returns    bool // the function returns a value: a fixture constructor shape
	defaultRun bool
}

// isTestFunc reports whether fi is a top-level Test function the default suite
// would run (naming only; the build constraint is defaultRun).
func (fi funcInfo) isTestFunc() bool {
	return !fi.recv && strings.HasPrefix(fi.name, "Test") && !strings.HasPrefix(fi.name, "TestMain")
}

// tType reports whether an expression denotes a testing.T/TB-like type.
func tType(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return tType(e.X)
	case *ast.SelectorExpr:
		// testing.T / testing.B / testing.TB.
		return e.Sel.Name == "T" || e.Sel.Name == "B" || e.Sel.Name == "TB"
	case *ast.Ident:
		// testing.TB is an interface, so the parameter type is the identifier.
		return e.Name == "TB" || e.Name == "T" || e.Name == "B"
	case *ast.InterfaceType:
		return true
	}
	return false
}

// tParamNames returns the parameter names of fn whose type is a testing handle.
func tParamNames(fn *ast.FuncDecl) []string {
	if fn.Type == nil || fn.Type.Params == nil {
		return nil
	}
	var out []string
	for _, f := range fn.Type.Params.List {
		if !tType(f.Type) {
			continue
		}
		for _, n := range f.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

// isTIdent reports whether an expression is one of the named testing handles.
func isTIdent(expr ast.Expr, names []string) bool {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	for _, n := range names {
		if id.Name == n {
			return true
		}
	}
	return false
}

// scanFuncs collects every function in a parsed file.
func scanFuncs(fset *token.FileSet, file string, f *ast.File, defaultRun bool) []funcInfo {
	var out []funcInfo
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		returns := fn.Type != nil && fn.Type.Results != nil && len(fn.Type.Results.List) > 0
		out = append(out, funcInfo{
			name:       fn.Name.Name,
			file:       file,
			line:       fset.Position(fn.Pos()).Line,
			tNames:     tParamNames(fn),
			body:       fn.Body,
			recv:       fn.Recv != nil,
			returns:    returns,
			defaultRun: defaultRun,
		})
	}
	return out
}

// isFixture reports whether a helper that fails on a testing handle is shaped like
// a fixture constructor rather than an assertion: it returns a value (so its
// t.Fatal is "the fixture could not be built"), or it is named like one. An
// assertion helper takes t and returns nothing —and a helper named assert*/check*/
// verify* is an assertion whatever it returns, so the name wins.
func isFixture(fi funcInfo) bool {
	if isAssertionName(fi.name) {
		return false
	}
	return fi.returns || strings.HasPrefix(fi.name, "new") || strings.HasPrefix(fi.name, "must")
}

// isAssertionName is the naming convention an assertion helper carries. The prefix
// is matched anywhere in the name so the audit corpus's `zzAssertPlane` counts too.
func isAssertionName(name string) bool {
	lower := strings.ToLower(name)
	for _, needle := range []string{"assert", "check", "verify", "expect"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// isProbeName is the naming convention the audit rounds gave their probes. The
// check below is scoped to it because that corpus is where the recorded
// "computes a verdict and only prints it" anti-pattern lives.
func isProbeName(name string) bool {
	return strings.HasPrefix(name, "TestZZProbe") || strings.HasPrefix(name, "TestProbe") ||
		strings.HasPrefix(name, "TestVerify")
}

// directCalls walks body and reports, per call, whether it is a failing call on a
// testing handle and the name of the callee (for the call-graph fixpoint).
type callInfo struct {
	failsOnT  bool // a failing method called directly on the testing handle
	errorsOnT bool // a non-fatal failing method called directly on the handle
	logs      bool // the body prints something: t.Log / fmt.Print
	panic     bool
	callees   []string // names of functions called anywhere in the body
}

func inspectBody(body *ast.BlockStmt, tNames []string) callInfo {
	var out callInfo
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == "panic" {
				out.panic = true
			}
			out.callees = append(out.callees, fun.Name)
		case *ast.SelectorExpr:
			if id, ok := fun.X.(*ast.Ident); ok {
				if isTIdent(id, tNames) {
					if failingMethod(fun.Sel.Name) {
						out.failsOnT = true
						if errorMethod(fun.Sel.Name) {
							out.errorsOnT = true
						}
					}
					if fun.Sel.Name == "Log" || fun.Sel.Name == "Logf" {
						out.logs = true
					}
				} else {
					if (id.Name == "fmt" || id.Name == "os") &&
						(strings.HasPrefix(fun.Sel.Name, "Print") || fun.Sel.Name == "Stdout") {
						out.logs = true
					}
					out.callees = append(out.callees, fun.Sel.Name)
				}
			}
		}
		return true
	})
	return out
}

// closure computes a transitive property over the package's call graph: start is
// the set of functions with the property directly, and a function whose body
// calls one of them gains it too.
func closure(funcs []funcInfo, direct map[string]bool, info map[string]callInfo) map[string]bool {
	// name -> callee names, only for names defined in this package.
	defined := make(map[string]bool, len(funcs))
	for _, fi := range funcs {
		defined[fi.name] = true
	}
	have := map[string]bool{}
	for k, v := range direct {
		if v {
			have[k] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, fi := range funcs {
			if have[fi.name] {
				continue
			}
			for _, callee := range info[fi.name].callees {
				if defined[callee] && have[callee] {
					have[fi.name] = true
					changed = true
					break
				}
			}
		}
	}
	return have
}

type finding struct {
	file       string
	fn         string
	line       int
	defaultRun bool
	tier       int
	cited      bool
	helpers    string
}

// scanAssertionless walks every *_test.go in the module, builds the per-directory
// call graph, and returns the tests that cannot fail plus the ones that can only
// fail on a fixture's setup error.
func scanAssertionless(t *testing.T) (tier1, tier2 []finding, scanned int) {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()

	// byDir holds the parsed functions of every package: helpers declared in a
	// non-test file of the same directory are callable too.
	byDir := map[string][]funcInfo{}
	dirDefault := map[string]bool{} // whether the directory has a default-suite test file
	fileDefault := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		isTest := strings.HasSuffix(d.Name(), "_test.go")
		def := !hasNonDefaultTag(string(raw))
		fileDefault[path] = def
		if isTest && def {
			dirDefault[filepath.Dir(path)] = true
		}
		f, err := parser.ParseFile(fset, path, raw, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)],
			scanFuncs(fset, filepath.ToSlash(rel), f, def)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for _, funcs := range byDir {
		info := make(map[string]callInfo, len(funcs))
		directFail := map[string]bool{}
		for _, fi := range funcs {
			ci := inspectBody(fi.body, fi.tNames)
			info[fi.name] = ci
			directFail[fi.name] = ci.failsOnT || ci.panic
		}
		canFail := closure(funcs, directFail, info)

		for _, fi := range funcs {
			if !fi.isTestFunc() {
				continue
			}
			scanned++
			if canFail[fi.name] {
				// A probe test that prints a verdict and whose every failing
				// callee is a fixture constructor: it asserts nothing about the
				// property it is named after. This is the recorded anti-pattern
				// (round 5's raw_test.go, round 6's pubaddr/addr_test.go) stated
				// as a rule.
				if !isProbeName(fi.name) || info[fi.name].failsOnT || !info[fi.name].logs {
					continue
				}
				var helpers []string
				onlyFixtures := true
				for _, callee := range info[fi.name].callees {
					if !canFail[callee] {
						continue
					}
					defined := false
					for _, other := range funcs {
						if other.name == callee && other.recv == fi.recv {
							defined = true
							if !isFixture(other) {
								onlyFixtures = false
							}
							break
						}
					}
					if !defined {
						// A failing method resolved by name only: treat it as an
						// assertion, so the rule under-reports rather than
						// mislabels a helper this scanner cannot see.
						onlyFixtures = false
					}
					helpers = append(helpers, callee)
				}
				if !onlyFixtures {
					continue
				}
				sort.Strings(helpers)
				tier2 = append(tier2, finding{file: fi.file, fn: fi.name, line: fi.line,
					defaultRun: fi.defaultRun, tier: 2, helpers: strings.Join(dedupe(helpers), ",")})
				continue
			}
			tier1 = append(tier1, finding{file: fi.file, fn: fi.name, line: fi.line,
				defaultRun: fi.defaultRun, tier: 1})
		}
	}
	_ = dirDefault
	_ = fileDefault

	cited := citedTestNames(t, root)
	for i := range tier1 {
		tier1[i].cited = cited[tier1[i].fn]
	}
	for i := range tier2 {
		tier2[i].cited = cited[tier2[i].fn]
	}
	sortFindings(tier1)
	sortFindings(tier2)
	return tier1, tier2, scanned
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortFindings(f []finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].file != f[j].file {
			return f[i].file < f[j].file
		}
		return f[i].fn < f[j].fn
	})
}

// citedTestNames reads every Markdown document in docs/ and returns the test
// function names they mention. A test cited as evidence in an audit document is
// the case that matters: a green run of it is read as a verified property.
func citedTestNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, word := range strings.FieldsFunc(string(raw), func(r rune) bool {
			return !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
		}) {
			if strings.HasPrefix(word, "Test") && len(word) > 4 {
				out[word] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Logf("docs scan: %v", err)
	}
	return out
}

// hasNonDefaultTag reports whether the file's //go:build constraint mentions any
// tag at all. The default `go test ./...` sets none, so any constraint excludes
// the file from the ordinary gate —which is what the tag census in
// TestEveryTaggedTestFileIsReachableFromCI is about.
func hasNonDefaultTag(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") {
			return true
		}
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		return false // the comment header ended without a constraint
	}
	return false
}

// repoRoot locates the module root from this package's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// skipDirs are trees that are not part of the module's test surface.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "scratchpad": true, "dist": true,
	".svelte-kit": true, "test-results": true, "playwright-report": true,
	"_audit": true,
}

// TestNoAssertionlessTestsInTheDefaultSuite is the guard the repository does not
// have: a test in the default suite must be able to fail on what it is named
// after. Tier 1 is a test with no failing statement anywhere in its call graph;
// tier 2 is one whose only failure capability is a fixture's t.Fatal, so it
// cannot fail on the property under test either. Both are reported, and a test
// cited by name in docs/ is called out because its green run is read as evidence.
func TestNoAssertionlessTestsInTheDefaultSuite(t *testing.T) {
	tier1, tier2, scanned := scanAssertionless(t)
	var bad1, bad2 []string
	for _, f := range tier1 {
		t.Logf("tier1 (cannot fail): %s::%s:%d default=%v cited=%v", f.file, f.fn, f.line, f.defaultRun, f.cited)
		if f.defaultRun {
			bad1 = append(bad1, f.file+"::"+f.fn)
		}
	}
	for _, f := range tier2 {
		t.Logf("tier2 (fatal-only fixture): %s::%s:%d default=%v cited=%v helpers=%s",
			f.file, f.fn, f.line, f.defaultRun, f.cited, f.helpers)
		if f.defaultRun {
			bad2 = append(bad2, f.file+"::"+f.fn+" (via "+f.helpers+")")
		}
	}
	t.Logf("scanned %d top-level Test functions: %d tier1, %d tier2", scanned, len(tier1), len(tier2))
	if scanned < 500 {
		t.Fatalf("only %d test functions were parsed; the walk is not reading the repository", scanned)
	}
	if len(bad1) > 0 {
		t.Errorf("these default-suite tests cannot fail:\n  %s", strings.Join(bad1, "\n  "))
	}
	if len(bad2) > 0 {
		t.Errorf("these default-suite tests assert nothing; only a fixture's t.Fatal can fail them:\n  %s",
			strings.Join(bad2, "\n  "))
	}
}
