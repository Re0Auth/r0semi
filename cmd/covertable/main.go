// Command covertable renders a Go coverage profile as a per-package table, lowest
// coverage first.
//
// It exists so `make cover` and the CI job print the same table from the same
// code: a table that only lives inside a workflow step cannot be produced while
// deciding where a test belongs, and two implementations would drift. CI uses it
// to put per-package coverage in the job summary, where a reviewer sees that a
// package is barely clearing the floor rather than only the total.
//
// It is statement-weighted (the profile's numStmts and count columns), not an
// average of `go tool cover -func`'s per-function percentages: averaging functions
// lets one large tested function hide a package full of untested ones.
//
// It is a developer tool, not a shipped binary: `make dist` packages only
// cmd/re0auth.
//
// Usage: go run ./cmd/covertable coverage.out
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type packageCoverage struct {
	pkg     string
	stmts   int
	covered int
}

func (p packageCoverage) percent() float64 {
	if p.stmts == 0 {
		return 0
	}
	return 100 * float64(p.covered) / float64(p.stmts)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: covertable <coverage.out>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "covertable: %v\n", err)
		os.Exit(1)
	}
	rows, total, err := parse(string(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "covertable: %v\n", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "covertable: no coverage data in %s\n", os.Args[1])
		os.Exit(1)
	}
	// Lowest first: the packages worth a decision are at the top, and a package at
	// 90% looks the same as one at 60% when the list is sorted the other way.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].percent() != rows[j].percent() {
			return rows[i].percent() < rows[j].percent()
		}
		return rows[i].pkg < rows[j].pkg
	})
	for _, row := range rows {
		fmt.Printf("%6.1f%%  %6d/%-6d statements  %s\n", row.percent(), row.covered, row.stmts, row.pkg)
	}
	fmt.Printf("%6.1f%%  %6d/%-6d statements  TOTAL\n", total.percent(), total.covered, total.stmts)
}

// parse aggregates a coverage profile per package. The profile's format is
//
//	mode: atomic
//	<file>:<startLine>.<startCol>,<endLine>.<endCol> <numStmts> <count>
//
// repeated; count > 0 means the statements were executed.
func parse(profile string) ([]packageCoverage, packageCoverage, error) {
	byPackage := make(map[string]*packageCoverage)
	var total packageCoverage

	scanner := bufio.NewScanner(strings.NewReader(profile))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if !strings.HasPrefix(line, "mode:") {
				return nil, total, fmt.Errorf("not a coverage profile: first line is %q", line)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, total, fmt.Errorf("malformed profile line %q", line)
		}
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, total, fmt.Errorf("malformed statement count in %q", line)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, total, fmt.Errorf("malformed execution count in %q", line)
		}
		file, _, ok := strings.Cut(fields[0], ":")
		if !ok {
			return nil, total, fmt.Errorf("malformed location in %q", line)
		}
		pkg := file
		if idx := strings.LastIndex(file, "/"); idx >= 0 {
			pkg = file[:idx]
		}
		row, ok := byPackage[pkg]
		if !ok {
			row = &packageCoverage{pkg: pkg}
			byPackage[pkg] = row
		}
		row.stmts += stmts
		if count > 0 {
			row.covered += stmts
		}
		total.stmts += stmts
		if count > 0 {
			total.covered += stmts
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, total, err
	}

	rows := make([]packageCoverage, 0, len(byPackage))
	for _, row := range byPackage {
		rows = append(rows, *row)
	}
	return rows, total, nil
}
