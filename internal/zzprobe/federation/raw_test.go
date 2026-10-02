//go:build audit5

package zzprobe_federation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
)

// ---------------------------------------------------------------------------
// D. Raw-path handling: can the path leave the source's base URL?
//
// cleanRawPath / rejectEscapingPath are unexported, so this drives them through
// the exported Raw() on a service pointed at a real httptest source and asserts
// what URL the source actually received. That is the property that matters: not
// "the guard returned an error", but "the request did or did not go to the place
// the caller asked for".
// ---------------------------------------------------------------------------

// rawRig is a source that records every request line it is asked for.
type rawRig struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	bodies   []string
	// token echoes the Authorization header it saw, to prove the credential went
	// to the same host the operator configured.
	tokens []string
}

func newRawRig(t *testing.T) *rawRig {
	t.Helper()
	rig := &rawRig{}
	rig.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.requests = append(rig.requests, r.Method+" "+r.URL.RequestURI())
		rig.tokens = append(rig.tokens, r.Header.Get("Authorization"))
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(rig.Close)
	return rig
}

func (r *rawRig) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

// rawService builds a federation service whose source has the given raw base and
// a bound token, using the httptest client so loopback is reachable.
func rawService(t *testing.T, rawBase, token string) (federation.Service, *rawRig) {
	t.Helper()
	rig := newRawRig(t)
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", DisplayName: "Src", Issuer: rig.URL,
		TokenClass: "revocable",
		RawBase:    strings.Replace(rawBase, "RIG", rig.URL, 1),
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	b := federation.Binding{User: "usr_1", Game: "phigros", Source: "src", Version: 1}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(b), mustPair(t, token, ""), nil); err != nil {
		t.Fatal(err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: rig.Client(), HTTPClient: rig.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, rig
}

func TestProbeRawPathCannotChangeTheHost(t *testing.T) {
	// Every one of these is a path an attacker would try. What matters is the
	// RequestURI the source ends up seeing and whether the request went to the
	// configured host at all.
	paths := []string{
		"..",
		"../secret",
		"a/../../secret",
		"..%2fsecret",
		"%2e%2e/secret",
		"%2e%2e%2fsecret",
		"%252e%252e%252fsecret",
		".../secret",
		"..;/secret",
		".%2e/secret",
		"..%5csecret",
		"..\\secret",
		"//evil.example/x",
		"///evil.example/x",
		"/\\evil.example/x",
		"http://evil.example/x",
		"https://evil.example/x",
		"@evil.example/x",
		"#frag",
		"?a=b",
		"a?b=c",
		"a#b",
		"a%00b",
		"%00",
		"a%0d%0aX-Injected:%201",
		"%2F%2Fevil.example",
		"a/b/%2e%2e/%2e%2e/../../x",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			svc, rig := rawService(t, "RIG/v1", "upstream-token")
			res, err := svc.Raw(context.Background(), federation.RawRequest{
				User: "usr_1", Game: "phigros", Source: "src", Path: p,
				Query: url.Values{"keep": {"1"}},
			})
			if err != nil {
				// A refusal is acceptable; assert it is the path guard and that
				// nothing was sent upstream.
				if seen := rig.seen(); len(seen) != 0 {
					t.Errorf("path %q was refused but the source was still asked: %v", p, seen)
				}
				if !errors.Is(err, federation.ErrRawPathEscapes) {
					t.Logf("path %q refused with %v", p, err)
				}
				return
			}
			seen := rig.seen()
			if len(seen) != 1 {
				t.Fatalf("expected one upstream request, saw %v", seen)
			}
			got := seen[0]
			// The whole question is whether the host changed. The rig only ever
			// answers on its own host, so "the rig saw it" already means the host
			// did not move; what is asserted here is that the base's own prefix was
			// not escaped and that no absolute-form request line appeared.
			if !strings.HasPrefix(got, "GET /v1") {
				t.Errorf("path %q produced %q, which is not under the configured /v1 base", p, got)
			}
			if strings.HasPrefix(got, "GET http://") || strings.HasPrefix(got, "GET https://") {
				t.Errorf("path %q produced an absolute-form request line: %q", p, got)
			}
			if strings.Contains(got, "//evil.example") {
				t.Errorf("path %q produced a scheme-relative target: %q", p, got)
			}
			t.Logf("path %-32q => %q status=%d", p, got, res.Status)
		})
	}
}

// The guard's own documented blind spot, driven explicitly: a segment that
// becomes ".." only after a decoding the guard does not perform.
//
// It used to only print what each form did, so the decode-depth property its name
// claims had no guard at all: a regression that stopped decoding once, twice or
// three times would still PASS. The two halves are asserted now — the forms the
// guard's round cap decodes to ".." must be refused with nothing sent upstream,
// and the forms it does not decode may pass through but must never leave the
// configured base or host.
func TestProbeRawPathEncodedTraversalDepth(t *testing.T) {
	// Decoded to ".." within maxRawPathDecodeRounds (4): each must be refused.
	for _, p := range []string{
		"%2e%2e/x",            // one decode: guard sees ".." -> refuse
		"%252e%252e/x",        // two decodes
		"%25252e%25252e/x",    // three
		"%2525252e%2525252ex", // four+ (hits the round cap)
	} {
		svc, rig := rawService(t, "RIG/v1", "upstream-token")
		_, err := svc.Raw(context.Background(), federation.RawRequest{
			User: "usr_1", Game: "phigros", Source: "src", Path: p,
		})
		if !errors.Is(err, federation.ErrRawPathEscapes) {
			t.Errorf("path %q decodes to %q within the round cap but erred with %v, want ErrRawPathEscapes: "+
				"the decode depth the guard relies on regressed", p, "..", err)
		}
		if seen := rig.seen(); len(seen) != 0 {
			t.Errorf("path %q was refused but the source was still asked: %v", p, seen)
		}
	}

	// Not decoded to ".." by the guard: overlong UTF-8, fullwidth full stop,
	// IIS-style %u. The guard may let these through, but the invariant holds
	// regardless — the request never leaves the configured base, and it is never
	// an absolute-form or scheme-relative target.
	for _, p := range []string{
		"%c0%ae%c0%ae/x",       // overlong UTF-8 for ".."
		"%ef%bc%8e%ef%bc%8e/x", // fullwidth full stop
		"%u002e%u002e/x",       // IIS-style %u
	} {
		svc, rig := rawService(t, "RIG/v1", "upstream-token")
		_, err := svc.Raw(context.Background(), federation.RawRequest{
			User: "usr_1", Game: "phigros", Source: "src", Path: p,
		})
		for _, got := range rig.seen() {
			if !strings.HasPrefix(got, "GET /v1") {
				t.Errorf("path %q produced %q, which is not under the configured /v1 base", p, got)
			}
			if strings.HasPrefix(got, "GET http://") || strings.HasPrefix(got, "GET https://") {
				t.Errorf("path %q produced an absolute-form request line: %q", p, got)
			}
			if strings.Contains(got, "//evil.example") {
				t.Errorf("path %q produced a scheme-relative target: %q", p, got)
			}
		}
		t.Logf("path %-24q err=%v upstream=%v", p, err, rig.seen())
	}
}

// Is the response cap real, and does a source that never stops streaming get cut?
func TestProbeRawResponseSizeAndStreaming(t *testing.T) {
	const gib = int64(1) << 30

	// 1. Declared Content-Length far past the cap, with only a few bytes actually
	// sent. The read must not report the truncated stream as a complete 200: it
	// used to only log the error, so a read path that swallowed the EOF and
	// returned its five bytes as success would still PASS.
	t.Run("huge Content-Length", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "1000000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("small"))
		}))
		defer srv.Close()
		svc := rawServiceAt(t, srv.URL)
		start := time.Now()
		res, err := svc.Raw(context.Background(), federation.RawRequest{User: "usr_1", Game: "phigros", Source: "src", Path: "x"})
		elapsed := time.Since(start)
		t.Logf("Content-Length: 1e18 => err=%v res=%q after %v", err, res.Body, elapsed)
		if err == nil {
			t.Errorf("a body that declared 1e18 bytes and sent %d was reported as a complete read (res=%q): "+
				"a truncated body must not be served as a 200", len(res.Body), res.Body)
		}
		if elapsed > 30*time.Second {
			t.Errorf("a huge declared Content-Length held the call for %v", elapsed)
		}
	})

	// 2. A body that never ends. The attempt is bounded only by the client's own
	// Timeout, because the handler ignores resp.Body.Read errors on purpose.
	t.Run("endless body", func(t *testing.T) {
		stop := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			chunk := make([]byte, 64<<10)
			for {
				select {
				case <-stop:
					return
				case <-r.Context().Done():
					return
				default:
				}
				if _, err := w.Write(chunk); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
		}))
		defer func() { close(stop); srv.Close() }()
		svc := rawServiceAt(t, srv.URL)
		start := time.Now()
		_, err := svc.Raw(context.Background(), federation.RawRequest{User: "usr_1", Game: "phigros", Source: "src", Path: "x"})
		elapsed := time.Since(start)
		t.Logf("endless body => err=%v after %v (client Timeout is %v)", err, elapsed, 20*time.Second)
		if elapsed > 30*time.Second {
			t.Errorf("an endless body held the call for %v", elapsed)
		}
		_ = gib
	})
}

func rawServiceAt(t *testing.T, issuer string) federation.Service {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: issuer, TokenClass: "revocable",
		RawBase: issuer + "/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	b := federation.Binding{User: "usr_1", Game: "phigros", Source: "src", Version: 1}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(b), mustPair(t, "upstream-token", ""), nil); err != nil {
		t.Fatal(err)
	}
	client := httptestClient()
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v, Doer: client, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// ---------------------------------------------------------------------------
// E. Registry validation: can a source name or game escape the path it is
// concatenated into?
// ---------------------------------------------------------------------------

// TestProbeRegistryAcceptsPathEscapingNames started as the FO-04/G-18 finding:
// NewRegistry accepted game/source names containing "/", ".", "?", "#",
// whitespace or control bytes, and every one of those is concatenated into a
// bind redirect URL, an OAuth scope or the raw proxy route — so an
// operator-supplied name could move the path it was placed in. The "." case is
// worse: BindingIdentity joins the two halves with ".", so ("a.b","c") and
// ("a","b.c") are two registry entries sharing one vault credential row. The
// registry now validates both halves against a path-safe alphabet; this is the
// regression guard for that fix.
func TestProbeRegistryAcceptsPathEscapingNames(t *testing.T) {
	dangerous := []struct{ game, name string }{
		{"phigros", "../evil"},
		{"../..", "src"},
		{"phigros", "src/../other"},
		{"phigros", "src?x=1"},
		{"phigros", "src#f"},
		{"phigros", "src%2F..%2Fother"},
		{"phigros", "src\x00null"},
		{"phigros", "src\nnewline"},
		{"phigros", "src with space"},
		{"phigros", ".."},
		{"phigros", "src.other"},
		{"phigros", `src\other`},
		{"phigros", "UPPER"},
		{"phigros", "-leading"},
		{"phigros", "_leading"},
	}
	for _, c := range dangerous {
		_, err := federation.NewRegistry(federation.Source{
			Game: c.game, Name: c.name, Issuer: "https://api.example",
			Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
		})
		if err == nil {
			t.Errorf("NewRegistry accepted game=%q name=%q: both halves are concatenated into bind redirect "+
				"paths, OAuth scopes and the raw route, so a name that escapes its path changes where the "+
				"request goes — and '.' makes two entries share one vault credential row (FO-04/G-18)",
				c.game, c.name)
		}
	}

	// Positive control: a well-formed source is still accepted and retrievable,
	// so the refusals above are about the characters and not a registry that
	// refuses everything.
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src-1", Issuer: "https://api.example",
		Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatalf("NewRegistry refused a well-formed source: %v", err)
	}
	if _, ok := reg.Get("phigros", "src-1"); !ok {
		t.Errorf("the accepted source is not retrievable under its own key")
	}

	// The length half of 22-2: path-safe is not bounded. The charset rule alone
	// accepted a name of any length, and a 4096-byte one landed verbatim in the
	// redirect URL and the registry key. It is asserted now, and the cap is
	// checked from both sides — a name exactly at internal/federation's
	// maxSourceNameBytes (128) is accepted, one byte past it is not — so a
	// registry that refused everything could not satisfy this.
	const cap = 128
	if _, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: strings.Repeat("a", cap), Issuer: "https://api.example",
		Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	}); err != nil {
		t.Errorf("NewRegistry refused a path-safe name exactly at the %d-byte cap: %v", cap, err)
	}
	for _, n := range []int{cap + 1, 4096} {
		if _, err := federation.NewRegistry(federation.Source{
			Game: "phigros", Name: strings.Repeat("a", n), Issuer: "https://api.example",
			Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
		}); err == nil {
			t.Errorf("NewRegistry accepted a %d-byte source name: a path-safe name is still a URL path "+
				"segment, a vault identity and a registry key, so an unbounded one must be refused at startup (22-2)", n)
		}
	}
}

// The scope a source declares is used verbatim as an OAuth scope: if it carries
// whitespace or a space, one resource's "scope" becomes several. This was the
// finding; the registry now refuses such a scope at construction, so the probe is
// the regression guard for that fix.
func TestProbeScopeInjectionFromRegistry(t *testing.T) {
	_, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: "https://api.example",
		Resources: []federation.Resource{
			{Name: "profile", Scope: "phigros.profile.read account.id"},
		},
	})
	if err == nil {
		t.Errorf("NewRegistry accepted a resource scope carrying whitespace: the declared value is used " +
			"verbatim as an OAuth scope, so one resource's scope silently becomes several on the wire")
	}

	// Positive control: a well-formed scope is accepted, and the registry does not
	// rewrite it — so the refusal above is about the whitespace and not "the
	// registry refuses every scope".
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: "https://api.example",
		Resources: []federation.Resource{
			{Name: "profile", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry refused a well-formed scope: %v", err)
	}
	src, _ := reg.Get("phigros", "src")
	if len(src.Resources) != 1 || src.Resources[0].Scope != "phigros.profile.read" {
		t.Fatalf("the registry rewrote the valid scope: %+v", src.Resources)
	}
	if strings.ContainsAny(src.Resources[0].Scope, " \t\n") {
		t.Errorf("a valid resource scope carries whitespace: %q", src.Resources[0].Scope)
	}
}

// ---------------------------------------------------------------------------
// F. Unbind / list-view consistency: the working-tree change.
// ---------------------------------------------------------------------------

// The claim in binding_routes.go's bindingView.Configured doc and in the
// working-tree unbind.go is "the connection still exists and can still be
// removed". This drives the HTTP list view and the service Unbind for a binding
// whose source is gone, to check the two agree.
func TestProbeOrphanedBindingIsListedAndRemovable(t *testing.T) {
	issuer := "https://api.example"
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "other", Issuer: issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	orphan := federation.Binding{User: "usr_1", Game: "phigros", Source: "gone", Version: 1}
	if err := bindings.Put(context.Background(), orphan); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(orphan), mustPair(t, "tok", ""), nil); err != nil {
		t.Fatal(err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.example",
	})
	if err != nil {
		t.Fatal(err)
	}

	list, err := svc.Bindings(context.Background(), "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("orphaned binding not listed: %v", list)
	}

	res, err := svc.Unbind(context.Background(), "usr_1", "phigros", "gone")
	if err != nil {
		t.Fatalf("orphaned binding not removable: %v", err)
	}
	if res.Upstream != federation.RevocationNothingToDo {
		t.Errorf("upstream = %q, want %q", res.Upstream, federation.RevocationNothingToDo)
	}
	if _, err := bindings.Get(context.Background(), "usr_1", "phigros", "gone"); err == nil {
		t.Error("the row survived")
	}
	if ok, _ := v.Exists(context.Background(), federation.BindingIdentity(orphan)); ok {
		t.Error("the secret survived")
	}
}

// Can a user enumerate which sources exist in the deployment by watching the
// Unbind status code? The working-tree change made "unknown source, nothing
// bound" => 404 and "known source, nothing bound" => 200.
func TestProbeUnbindIsASourceExistenceOracle(t *testing.T) {
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "known", Issuer: "https://api.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: federation.NewMemoryBindingStore(), Vault: newTestVault(t),
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, knownErr := svc.Unbind(context.Background(), "usr_1", "phigros", "known")
	_, unknownErr := svc.Unbind(context.Background(), "usr_1", "phigros", "not-configured")
	t.Logf("known source, nothing bound   => %v", knownErr)
	t.Logf("unknown source, nothing bound => %v", unknownErr)
	if errors.Is(knownErr, federation.ErrUnknownSource) {
		t.Error("known source reported as unknown")
	}
	if !errors.Is(unknownErr, federation.ErrUnknownSource) {
		t.Error("unknown source was not reported as unknown")
	}
	// /v1/sources is public and already lists every configured source, so this is
	// not a new disclosure — recorded so the next reader does not have to check.
	t.Logf("note: GET /v1/sources is public and lists every configured source, so the " +
		"oracle above reveals nothing a caller could not already read")
	_ = fmt.Sprint()
}
