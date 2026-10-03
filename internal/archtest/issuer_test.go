package archtest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// S02-11. DenyAuthorization (internal/oidchttp/oidchttp.go) answers a denied
// authorization request with a redirect, and RFC 9207 requires an `iss` on it.
// That method is handed an interaction id and not an *http.Request, so it cannot
// call issuerFor and can only carry the static Handler.issuer field. An empty
// issuer therefore produces an authorization response with no `iss` — but an empty
// issuer is not reachable in a shipped deployment, because both composition roots
// refuse one before a Handler is ever built.
//
// That is the whole reason this is recorded as NOT-A-DEFECT rather than fixed, so
// the claim needs a machine behind it: if a later change relaxes either root, the
// denial path silently loses `iss` and nothing else notices. The rule below reads
// the two source files and fails on exactly that relaxation.
//
// The check is source-level on purpose. cmd/re0auth's loadConfig is unexported in
// package main, so no test outside that package can call it, and this package's
// files are limited to internal/archtest — a behavioural half-cover of
// internal/httpapi.New would leave the cmd/re0auth root unguarded. Reading both
// files keeps the two roots in one rule.
func TestS02_11CompositionRootsRequireAStaticIssuer(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	roots := []struct {
		file      string
		signature string
		// relaxHint says what refusing the empty value buys, for the failure text.
		relaxHint string
	}{
		{
			file:      filepath.Join("cmd", "re0auth", "config.go"),
			signature: "func loadConfig(path string) (settings, error) {",
			relaxHint: "an empty server.issuer / RE0AUTH_ISSUER must be refused at startup",
		},
		{
			file:      filepath.Join("internal", "httpapi", "server.go"),
			signature: "func New(cfg Config) (*Server, error) {",
			relaxHint: "an empty Config.Issuer must be refused by New",
		},
	}

	for _, rt := range roots {
		raw, err := os.ReadFile(filepath.Join(root, rt.file))
		if err != nil {
			t.Fatalf("read %s: %v", rt.file, err)
		}

		check, err := checkIssuerGuard(string(raw), rt.signature)
		if err != nil {
			t.Fatalf("%s: %v. The issuer guard cannot be read, so this check would pass without "+
				"proving anything (S02-11)", rt.file, err)
		}
		if check.guards == 0 {
			t.Fatalf("%s: %s has no `...Issuer == \"\"` guard; %s, or the shipped denial path loses "+
				"RFC 9207 `iss` (S02-11)", rt.file, rt.signature, rt.relaxHint)
		}
		if check.relaxed > 0 {
			t.Fatalf("%s: %d of %d issuer guard(s) in %s no longer return an error; %s. If that "+
				"relaxation is deliberate, thread the request/issuer through DenyAuthorization's "+
				"interface instead of reopening an empty-issuer deployment (S02-11)",
				rt.file, check.relaxed, check.guards, rt.signature, rt.relaxHint)
		}
	}

	// The anti-vacuous half, the shape internal/archtest/zz_p3_misc2_test.go uses
	// for the Makefile guard: the same parser the checks above run is driven on
	// mutated copies of that shape, so "a relaxed root turns this red" is shown
	// rather than asserted. The mutations are the two ways a root gets relaxed —
	// the guard is deleted, or it stops failing — plus a multi-line nil return,
	// which is the case a naive line scan would miss.
	const signature = "func New(cfg Config) (*Server, error) {"
	for _, tc := range []struct {
		name string
		src  string
		want issuerRootCheck
	}{
		{
			name: "failing guard",
			src: signature + `
	if cfg.Issuer == "" {
		return nil, errors.New("httpapi: Config.Issuer is required")
	}
}
`,
			want: issuerRootCheck{guards: 1, relaxed: 0},
		},
		{
			name: "guard returns nil",
			src: signature + `
	if cfg.Issuer == "" {
		return nil, nil
	}
}
`,
			want: issuerRootCheck{guards: 1, relaxed: 1},
		},
		{
			name: "guard returns nil across lines",
			src: signature + `
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil,
			nil
	}
}
`,
			want: issuerRootCheck{guards: 1, relaxed: 1},
		},
		{
			name: "guard deleted",
			src: signature + `
	_ = cfg.Issuer
}
`,
			want: issuerRootCheck{guards: 0, relaxed: 0},
		},
	} {
		got, err := checkIssuerGuard(tc.src, signature)
		if err != nil {
			t.Errorf("%s: checkIssuerGuard: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: checkIssuerGuard = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// issuerGuard matches the `if` clause that refuses an empty issuer. Both
// spellings in the tree are covered: `cfg.Issuer == ""` and
// `strings.TrimSpace(cfg.Issuer) == ""`.
var issuerGuard = regexp.MustCompile(`(?m)^[ \t]*if[^\n]*\bIssuer\b[^\n]*==[ \t]*""[ \t]*\{`)

// issuerRootCheck is what one composition root's issuer guard looks like: how many
// empty-issuer guards the named function has, and how many of them do not return an
// error.
type issuerRootCheck struct {
	guards  int
	relaxed int
}

// checkIssuerGuard reads signature's body in src and counts its empty-issuer
// guards. It reports a structural error when the function or its body cannot be
// found, so a rename fails the guard instead of silently finding no guards.
func checkIssuerGuard(src, signature string) (issuerRootCheck, error) {
	var out issuerRootCheck

	at := strings.Index(src, signature)
	if at < 0 {
		return out, fmt.Errorf("no %q", signature)
	}

	masked := maskGoLiterals(src)
	open := strings.Index(masked[at:], "{")
	if open < 0 {
		return out, fmt.Errorf("%q has no body", signature)
	}
	open += at

	end, ok := blockEnd(masked, open)
	if !ok {
		return out, fmt.Errorf("%q has no closing brace", signature)
	}

	// The guard is located on the raw body: the pattern includes the literal
	// `""`, which masking blanks out. Structure below uses the masked body, whose
	// byte offsets match the raw one.
	body := src[open+1 : end]
	maskedBody := masked[open+1 : end]
	for _, m := range issuerGuard.FindAllStringIndex(body, -1) {
		guardOpen := strings.Index(maskedBody[m[0]:], "{")
		if guardOpen < 0 {
			continue
		}
		guardOpen += m[0]
		guardEnd, ok := blockEnd(maskedBody, guardOpen)
		if !ok {
			return out, fmt.Errorf("an issuer guard in %q has no closing brace", signature)
		}
		out.guards++
		if !returnsAnError(maskedBody[guardOpen+1 : guardEnd]) {
			out.relaxed++
		}
	}
	return out, nil
}

// returnsAnError reports whether a literal-masked block contains a return
// statement whose result is not the bare literal nil, folding continuation lines
// so a `return nil,\n nil` is still read as nil.
func returnsAnError(maskedBlock string) bool {
	lines := strings.Split(maskedBlock, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "return") {
			continue
		}
		stmt := strings.TrimSpace(strings.TrimPrefix(line, "return"))
		for statementContinues(stmt) && i+1 < len(lines) {
			i++
			stmt = strings.TrimSpace(stmt + " " + strings.TrimSpace(lines[i]))
		}
		if stmt == "" || stmt == "nil" || strings.HasSuffix(stmt, ", nil") {
			continue
		}
		return true
	}
	return false
}

// statementContinues reports whether a return statement read so far is incomplete:
// it ends on a trailing comma or operator, or leaves a bracket open.
func statementContinues(stmt string) bool {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return true
	}
	switch stmt[len(stmt)-1] {
	case ',', '(', '{', '[', '+', '-', '*', '/', '&', '|':
		return true
	}
	depth := 0
	for _, r := range stmt {
		switch r {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
		}
	}
	return depth > 0
}

// blockEnd returns the index of the `}` that closes the `{` at open, counting
// brackets in masked source. Callers must pass a masked string: a `{` inside a
// string literal or a comment must not move the depth.
func blockEnd(masked string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// maskGoLiterals blanks the contents of string, rune and comment literals without
// changing the byte offsets, so brace counting cannot be fooled by a `{` inside an
// error message and returnsAnError cannot match the word "nil" inside one.
func maskGoLiterals(src string) string {
	b := []byte(src)
	const (
		code = iota
		lineComment
		blockComment
		str
		raw
		char
	)
	state := code

	for i := 0; i < len(b); i++ {
		c := b[i]
		switch state {
		case code:
			switch {
			case c == '/' && i+1 < len(b) && b[i+1] == '/':
				state = lineComment
				b[i], b[i+1] = ' ', ' '
				i++
			case c == '/' && i+1 < len(b) && b[i+1] == '*':
				state = blockComment
				b[i], b[i+1] = ' ', ' '
				i++
			case c == '"':
				state = str
				b[i] = ' '
			case c == '`':
				state = raw
				b[i] = ' '
			case c == '\'':
				state = char
				b[i] = ' '
			}
		case lineComment:
			if c == '\n' {
				state = code
			} else {
				b[i] = ' '
			}
		case blockComment:
			switch {
			case c == '*' && i+1 < len(b) && b[i+1] == '/':
				b[i], b[i+1] = ' ', ' '
				i++
				state = code
			case c != '\n':
				b[i] = ' '
			}
		case str:
			switch {
			case c == '\\' && i+1 < len(b):
				b[i], b[i+1] = ' ', ' '
				i++
			case c == '"':
				b[i] = ' '
				state = code
			case c != '\n':
				b[i] = ' '
			}
		case raw:
			switch {
			case c == '`':
				b[i] = ' '
				state = code
			case c != '\n':
				b[i] = ' '
			}
		case char:
			switch {
			case c == '\\' && i+1 < len(b):
				b[i], b[i+1] = ' ', ' '
				i++
			case c == '\'':
				b[i] = ' '
				state = code
			}
		}
	}
	return string(b)
}
