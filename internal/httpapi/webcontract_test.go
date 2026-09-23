package httpapi

import (
	"os"
	"regexp"
	"testing"
)

// apiTSPath is relative to this package's directory, which is the working
// directory of a test binary. Like openapi_test.go's read of docs/openapi.yaml,
// it reaches outside the package because that is where the contract lives.
const apiTSPath = "../../web/src/lib/api.ts"

var (
	// The ProblemCode union is the only part of api.ts this test parses.
	problemCodeUnion = regexp.MustCompile(`(?s)export type ProblemCode =([^;]*);`)
	problemCodeItem  = regexp.MustCompile(`'([a-z_]+)'`)
)

// Every code the server can emit must be one the frontend knows how to branch
// on, and vice versa.
//
// problemTitles is already asserted equal to docs/openapi.yaml's enum
// (TestOpenAPIProblemCodesMatchCatalogue), so tying the frontend union to it
// keeps all three in step. Without this, a new server code is a silently
// unhandled case in the UI — which is exactly what happened when compression
// introduced `not_acceptable`: the union still claimed to be exhaustive.
func TestFrontendProblemCodesMatchCatalogue(t *testing.T) {
	raw, err := os.ReadFile(apiTSPath)
	if err != nil {
		t.Fatalf("read %s: %v", apiTSPath, err)
	}
	match := problemCodeUnion.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s: could not find the ProblemCode union", apiTSPath)
	}
	frontend := make(map[string]bool)
	for _, item := range problemCodeItem.FindAllStringSubmatch(string(match[1]), -1) {
		frontend[item[1]] = true
	}
	if len(frontend) == 0 {
		t.Fatalf("%s: the ProblemCode union parsed as empty (did the declaration shape change?)", apiTSPath)
	}

	for code := range problemTitles {
		if !frontend[code] {
			t.Errorf("%q is emitted by the server but missing from %s", code, apiTSPath)
		}
		delete(frontend, code)
	}
	for code := range frontend {
		t.Errorf("%q is in %s but no handler can emit it", code, apiTSPath)
	}
}
