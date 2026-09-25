package main

import (
	"strings"
	"testing"
)

// The profile format is parsed by hand, so the parser is pinned here: a table that
// silently reads zero statements would report 0% (or 100%) for everything and be
// believed, which is worse than no table.
func TestParseAggregatesPerPackage(t *testing.T) {
	profile := strings.Join([]string{
		"mode: atomic",
		"github.com/Re0Auth/r0semi/aa/a.go:10.2,12.3 4 1",
		"github.com/Re0Auth/r0semi/aa/a.go:20.2,22.3 6 0",
		"github.com/Re0Auth/r0semi/bb/b.go:5.1,7.1 10 3",
		"github.com/Re0Auth/r0semi/root.go:1.1,2.1 5 0",
	}, "\n")

	rows, total, err := parse(profile)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]packageCoverage, len(rows))
	for _, row := range rows {
		byName[row.pkg] = row
	}

	aa, ok := byName["github.com/Re0Auth/r0semi/aa"]
	if !ok {
		t.Fatalf("package aa missing from %v", byName)
	}
	if aa.stmts != 10 || aa.covered != 4 {
		t.Fatalf("aa = %d/%d statements, want 4/10", aa.covered, aa.stmts)
	}
	bb, ok := byName["github.com/Re0Auth/r0semi/bb"]
	if !ok || bb.stmts != 10 || bb.covered != 10 {
		t.Fatalf("bb = %+v, want 10/10", bb)
	}
	// A file at the module root belongs to its own directory, not to the module
	// path's last element.
	root, ok := byName["github.com/Re0Auth/r0semi"]
	if !ok || root.stmts != 5 || root.covered != 0 {
		t.Fatalf("root package = %+v, want 0/5", root)
	}
	if total.stmts != 25 || total.covered != 14 {
		t.Fatalf("total = %d/%d, want 14/25", total.covered, total.stmts)
	}
}

func TestParseRejectsWhatItCannotTrust(t *testing.T) {
	for name, profile := range map[string]string{
		"no mode line":    "github.com/x/y/z.go:1.1,2.2 3 1",
		"short line":      "mode: atomic\ngithub.com/x/y/z.go:1.1,2.2 3",
		"bad statement":   "mode: atomic\ngithub.com/x/y/z.go:1.1,2.2 many 1",
		"bad count":       "mode: atomic\ngithub.com/x/y/z.go:1.1,2.2 3 lots",
		"no colon in loc": "mode: atomic\ngithub.com/x/y/z.go 3 1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parse(profile); err == nil {
				t.Fatal("a profile that cannot be trusted was accepted")
			}
		})
	}
}

// An empty (but well formed) profile yields no rows, which the caller turns into a
// failure: a table with no packages is not a coverage report.
func TestParseAcceptsAnEmptyProfile(t *testing.T) {
	rows, total, err := parse("mode: atomic\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || total.stmts != 0 {
		t.Fatalf("rows = %v, total = %+v; want nothing", rows, total)
	}
}
