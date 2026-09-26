package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestOnlyMainExitsTheProcess pins the reason this package has a run() at all.
//
// run() opens the storage handle and starts the background loops; both are released
// by deferred calls, and a defer only runs on a return. So an os.Exit anywhere below
// main silently skips the cleanup — which is exactly what happened: a listener that
// failed to bind called os.Exit from inside the composition root while the comment
// above the defers promised every exit path had the same ordering, and nothing in
// the suite could tell. The ordering was real on the signal path and fiction on the
// failure paths, which are the ones that need it.
//
// A test rather than a comment because the mistake is invisible: re-adding an
// os.Exit in a helper compiles, reads as deliberate, and quietly restores the bug.
//
// The one thing this cannot see is an exit reached indirectly (a future
// log.Fatal-style helper in another package). That is why main is also the only
// caller of run, and why main does nothing but interpret what run returned.
func TestOnlyMainExitsTheProcess(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse the package: %v", err)
	}

	var foundMain bool
	exitsInMain, exitsElsewhere := 0, 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				inMain := fn.Name.Name == "main"
				if inMain {
					foundMain = true
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Exit" {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || id.Name != "os" {
						return true
					}
					if inMain {
						exitsInMain++
						return true
					}
					exitsElsewhere++
					t.Errorf("%s: os.Exit outside main; every deferred cleanup above it is skipped, "+
						"which is the bug run() exists to prevent. Return the error instead.",
						fset.Position(call.Pos()))
					return true
				})
			}
		}
	}

	if !foundMain {
		t.Fatal("no func main in the parsed package, so this check examined something else entirely")
	}
	// Anti-vacuous: main is expected to exit, so seeing none means the scan stopped
	// recognising the call rather than that the code became cleaner.
	if exitsInMain == 0 {
		t.Fatal("found no os.Exit even in main; the scan is looking at the wrong thing")
	}
	if exitsElsewhere != 0 {
		t.Fatalf("%d os.Exit call(s) outside main", exitsElsewhere)
	}
}
