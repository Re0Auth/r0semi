package archtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// modulePath is the import path prefix of every package in this module.
const modulePath = "github.com/Re0Auth/r0semi"

// publicLibraries are the packages published for reuse by out-of-process
// services (the reference data source, and third-party data sources). They may
// be imported from outside this module, so an import of internal/ -- directly or
// transitively -- would make them unimportable there. docs/architecture.md §4
// calls this the "包分层（v1 公开化）" boundary.
var publicLibraries = []string{
	"audit",
	"httpclient",
	"idp",
	"oauth",
	"referencesource",
	"tapsign",
	"taptapoauth",
	"upstreamkit",
	"upstreamkit/conformance",
	"vault",
}

// dbAdapter is the package that turns the storage ports into Postgres. It is
// imported only by the composition roots: keeping it out of the domain is what
// keeps the domain storage-port shaped instead of Postgres shaped.
const dbAdapter = "internal/store/postgres"

// kernel is the bottom of the component graph. It must not import any other
// package in this module, or the dependency direction would invert.
const kernel = "internal/core"

type pkgInfo struct {
	path    string
	imports []string
}

var (
	loadOnce sync.Once
	loaded   map[string]pkgInfo
	loadErr  error
)

// packages loads the real import graph once for all checks. `go list -deps`
// without -test sees production imports only, which is exactly the surface these
// rules govern; test files may freely wire adapters together.
func packages(t *testing.T) map[string]pkgInfo {
	t.Helper()
	if testing.Short() {
		t.Skip("architecture checks shell out to `go list`; skipped under -short")
	}
	loadOnce.Do(func() { loaded, loadErr = loadPackages() })
	if loadErr != nil {
		t.Fatalf("cannot read the import graph: %v", loadErr)
	}
	return loaded
}

func loadPackages() (map[string]pkgInfo, error) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return nil, err
	}
	root := strings.TrimSpace(string(gomod))
	if root == "" || root == os.DevNull {
		return nil, &os.PathError{Op: "go env GOMOD", Path: ".", Err: os.ErrNotExist}
	}

	cmd := exec.Command("go", "list", "-deps", "-f", `{{.ImportPath}}|{{join .Imports " "}}`, "./...")
	cmd.Dir = filepath.Dir(root)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, &listError{err: err, stderr: string(ee.Stderr)}
		}
		return nil, err
	}

	pkgs := make(map[string]pkgInfo)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		path, rest, _ := strings.Cut(line, "|")
		var imports []string
		if rest != "" {
			imports = strings.Fields(rest)
		}
		pkgs[path] = pkgInfo{path: path, imports: imports}
	}
	return pkgs, nil
}

type listError struct {
	err    error
	stderr string
}

func (e *listError) Error() string { return e.err.Error() + ": " + strings.TrimSpace(e.stderr) }

// moduleRel returns the module-relative path of pkg, and whether pkg belongs to
// this module at all.
func moduleRel(pkg string) (string, bool) {
	return strings.CutPrefix(pkg, modulePath+"/")
}

// TestPublicLibrariesDoNotDependOnInternal is the firewall that makes the public
// libraries actually public. `internal/` cannot be imported from outside the
// module, so a published library that reaches into it is not publishable -- and
// nothing in `go build` would say so.
func TestPublicLibrariesDoNotDependOnInternal(t *testing.T) {
	pkgs := packages(t)
	for _, lib := range publicLibraries {
		full := modulePath + "/" + lib
		if _, ok := pkgs[full]; !ok {
			t.Errorf("publicLibraries lists %q, which is not a package in this module (stale entry?)", lib)
			continue
		}
		for _, v := range internalDependencies(pkgs, full) {
			t.Errorf("public library %s must not depend on %s: %s -> %s (internal/ is not importable outside this module)",
				lib, v.to, v.from, v.to)
		}
	}
}

// TestDatabaseAdapterIsConfinedToCompositionRoots keeps Postgres out of the
// domain. Only cmd/* (the composition roots) may import it; everywhere else
// depends on the storage ports instead.
func TestDatabaseAdapterIsConfinedToCompositionRoots(t *testing.T) {
	pkgs := packages(t)
	want := modulePath + "/" + dbAdapter
	for _, p := range pkgs {
		rel, ok := moduleRel(p.path)
		if !ok {
			continue
		}
		if rel == dbAdapter || strings.HasPrefix(rel, "cmd/") {
			continue
		}
		for _, imp := range p.imports {
			if imp == want {
				t.Errorf("%s imports %s; only the composition roots (cmd/*) may import the database adapter", rel, dbAdapter)
			}
		}
	}
}

// TestKernelHasNoInternalDependencies holds the bottom of the graph in place.
// internal/core is the component runtime; if it grows a dependency on a domain
// or adapter package, the direction has inverted.
func TestKernelHasNoInternalDependencies(t *testing.T) {
	pkgs := packages(t)
	info, ok := pkgs[modulePath+"/"+kernel]
	if !ok {
		t.Fatalf("%s is not a package in this module", kernel)
	}
	for _, imp := range info.imports {
		if _, ok := strings.CutPrefix(imp, modulePath+"/internal/"); ok && imp != modulePath+"/"+kernel {
			t.Errorf("%s must not import %s: it is the bottom of the dependency graph", kernel, imp)
		}
	}
}

// TestEveryModulePackageIsRegistered is the "register before you merge" rule from
// r0semi-mp's check-deps.py. A new top-level package is either a public library
// (add it to publicLibraries) or belongs under internal/ -- the check refuses to
// silently treat an unclassified package as public.
func TestEveryModulePackageIsRegistered(t *testing.T) {
	pkgs := packages(t)
	known := make(map[string]bool, len(publicLibraries))
	for _, lib := range publicLibraries {
		known[lib] = true
	}
	for path := range pkgs {
		rel, ok := moduleRel(path)
		if !ok {
			continue
		}
		switch {
		case known[rel], strings.HasPrefix(rel, "internal/"), strings.HasPrefix(rel, "cmd/"):
			// classified
		default:
			t.Errorf("unregistered module package %q: add it to publicLibraries if it is a published library, or place it under internal/",
				rel)
		}
	}
}

type violation struct{ from, to string }

// internalDependencies returns the internal/ packages reachable from root. Each
// violation names the edge that introduced the internal import, so the fix is
// obvious without re-deriving the graph.
func internalDependencies(pkgs map[string]pkgInfo, root string) []violation {
	seen := map[string]bool{root: true}
	queue := []string{root}
	var out []violation
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, imp := range pkgs[cur].imports {
			if seen[imp] {
				continue
			}
			seen[imp] = true
			if _, ok := strings.CutPrefix(imp, modulePath+"/internal/"); ok {
				out = append(out, violation{from: cur, to: imp})
				continue // the internal package's own deps are not this rule's concern
			}
			queue = append(queue, imp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].from != out[j].from {
			return out[i].from < out[j].from
		}
		return out[i].to < out[j].to
	})
	return out
}
