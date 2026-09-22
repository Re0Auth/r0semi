package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
	"gopkg.in/yaml.v3"
)

// openAPIPath is relative to this package's directory, which is the working
// directory of a test binary. go:embed cannot reach outside the package, so a
// relative read is the only way to keep the document at the repository root next
// to the other docs.
const openAPIPath = "../../docs/openapi.yaml"

// httpVerbs are the OpenAPI path-item keys that denote an operation. Everything
// else in a path item — parameters, summary, description, $ref — is not one.
var httpVerbs = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// newFullConfig assembles every mountable piece — sessions, the IdP login plane, the
// authorization-interaction API and federation — so the route assertions see the
// complete surface rather than a subset that happens to satisfy them. The
// upstream and IdP servers are never called; they exist so the constructors have
// something to point at.
func newFullConfig(t *testing.T) Config {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(upstream.Close)
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(idpSrv.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   idpSrv.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL:     idpSrv.URL + "/github/authorize",
			TokenURL:    idpSrv.URL + "/github/token",
			UserInfoURL: idpSrv.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://re0auth.test", Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	azSvc, err := authz.NewService(as, authz.NewMemoryStore(), authz.Config{})
	if err != nil {
		t.Fatal(err)
	}

	sources, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: upstream.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: sources,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    newTestVault(t),
		Doer:     upstream.Client(),
		BaseURL:  "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	return Config{
		Issuer: "https://re0auth.test", AS: as,
		Sessions: manager, Accounts: accounts, Auth: authHandler,
		Authz: azSvc, Federation: fed,
	}
}

func newFullEnv(t *testing.T) *Server {
	t.Helper()
	srv, err := New(newFullConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read %s: %v", openAPIPath, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s does not parse: %v", openAPIPath, err)
	}
	return doc
}

// dig walks a decoded document, failing the test rather than panicking when a
// key is missing: a malformed document should produce a readable failure, not a
// stack trace.
func dig(t *testing.T, node any, keys ...string) any {
	t.Helper()
	path := openAPIPath
	for _, key := range keys {
		path += " > " + key
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s: parent is not a mapping", path)
		}
		v, ok := m[key]
		if !ok {
			t.Fatalf("%s is missing", path)
		}
		node = v
	}
	return node
}

func digMap(t *testing.T, node any, keys ...string) map[string]any {
	t.Helper()
	m, ok := dig(t, node, keys...).(map[string]any)
	if !ok {
		t.Fatalf("%s: not a mapping", strings.Join(keys, " > "))
	}
	return m
}

// specOperations returns "METHOD /path" for every operation the document defines.
func specOperations(t *testing.T, doc map[string]any) map[string]bool {
	t.Helper()
	paths := digMap(t, doc, "paths")
	if len(paths) == 0 {
		t.Fatal("the document has no paths")
	}
	ops := make(map[string]bool)
	for path, item := range paths {
		item, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("path %s is not a mapping", path)
		}
		for key := range item {
			if httpVerbs[strings.ToLower(key)] {
				ops[strings.ToUpper(key)+" "+path] = true
			}
		}
	}
	return ops
}

// normalizePattern turns a router pattern into the path template the document
// uses. The only difference is the router's rest wildcard: Go writes `{path...}`
// and OpenAPI has no such form, so it writes `{path}`.
func normalizePattern(pattern string) string {
	return strings.ReplaceAll(pattern, "...", "")
}

func TestOpenAPIVersion(t *testing.T) {
	doc := loadSpec(t)
	if v, _ := dig(t, doc, "openapi").(string); !strings.HasPrefix(v, "3.1") {
		t.Errorf("openapi = %q, want 3.1.x", v)
	}
	if title, _ := dig(t, doc, "info", "title").(string); title == "" {
		t.Error("info.title is empty")
	}
}

// The document and the declared surface must agree, in both directions. Adding a
// route without describing it fails here; so does describing one that is not
// mounted. A spec that promises an endpoint which does not exist is worse than
// having no spec, because it is a lie a client will build against.
func TestOpenAPIMatchesDeclaredRoutes(t *testing.T) {
	srv := newFullEnv(t)

	want := make(map[string]bool)
	for _, rt := range srv.specRoutes() {
		want[rt.Method+" "+normalizePattern(rt.Pattern)] = true
	}
	got := specOperations(t, loadSpec(t))

	for op := range want {
		if !got[op] {
			t.Errorf("%s is served but not described in %s", op, openAPIPath)
		}
	}
	for op := range got {
		if !want[op] {
			t.Errorf("%s is described in %s but not served", op, openAPIPath)
		}
	}
}

// The previous test compares the document with the declared surface. This proves
// the declared surface is what the mux actually serves: a pattern that is listed
// but never registered would still pass that comparison, and would be a 404 for
// every client. Reachability is checked by dispatch, not by reading the table.
func TestOpenAPIOperationsAreReachable(t *testing.T) {
	srv := newFullEnv(t)
	handler := srv.Handler()

	for op := range specOperations(t, loadSpec(t)) {
		method, path, _ := strings.Cut(op, " ")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, fillPathParams(path), nil))
		// The requests carry no credential on purpose. Reaching a real handler
		// therefore yields 401/403/200, and only a miss yields the catch-all.
		if detail := catchAllDetail(rec); detail != "" {
			t.Errorf("%s %s reached the catch-all (%q): described but not served", method, path, detail)
		}
	}
}

// fillPathParams replaces each {param} with a dummy value, turning a template into
// a request target.
func fillPathParams(path string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			b.WriteString(path)
			return b.String()
		}
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			b.WriteString(path)
			return b.String()
		}
		b.WriteString(path[:start])
		b.WriteString("x")
		path = path[start+end+1:]
	}
}

// catchAllDetail reports which catch-all handler answered, or "" if a real route
// did. The three strings are the catch-alls' own detail messages.
func catchAllDetail(rec *httptest.ResponseRecorder) string {
	if rec.Code != http.StatusNotFound {
		return ""
	}
	var p struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		return ""
	}
	switch p.Detail {
	case "unknown resource", "unknown endpoint", "unknown OAuth endpoint":
		return p.Detail
	}
	return ""
}

// The Problem schema enumerates a closed set of codes, and problemTitles is the
// set the server can actually emit. They must be equal: a code that is documented
// but unreachable tells a client to handle something that cannot happen, and one
// that is emittable but undocumented is a case nobody planned for.
func TestOpenAPIProblemCodesMatchCatalogue(t *testing.T) {
	doc := loadSpec(t)
	enum, ok := dig(t, doc, "components", "schemas", "Problem", "properties", "code", "enum").([]any)
	if !ok {
		t.Fatal("Problem.code has no enum")
	}
	spec := make(map[string]bool, len(enum))
	for _, v := range enum {
		code, ok := v.(string)
		if !ok {
			t.Fatalf("Problem.code enum contains a non-string: %v", v)
		}
		if spec[code] {
			t.Errorf("Problem.code lists %q twice", code)
		}
		spec[code] = true
	}

	for code := range problemTitles {
		if !spec[code] {
			t.Errorf("%q is emitted by the server but missing from the document's enum", code)
		}
		delete(spec, code)
	}
	for code := range spec {
		t.Errorf("%q is documented but no handler can emit it", code)
	}
}

// A $ref that does not resolve is a broken link, and every consumer — a code
// generator, a docs renderer — discovers it at its own time and in its own way.
func TestOpenAPIReferencesResolve(t *testing.T) {
	doc := loadSpec(t)
	var refs []string
	collectRefs(doc, &refs)
	if len(refs) == 0 {
		t.Fatal("no $ref was found; the walker is probably wrong")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if !strings.HasPrefix(ref, "#/") {
			t.Errorf("%s: only local references are allowed, got %q", openAPIPath, ref)
			continue
		}
		var node any = doc
		resolved := true
		for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, isMap := node.(map[string]any)
			if !isMap {
				resolved = false
				break
			}
			child, exists := m[seg]
			if !exists {
				resolved = false
				break
			}
			node = child
		}
		if !resolved {
			t.Errorf("%s: %s does not resolve", openAPIPath, ref)
		}
	}
}

// collectRefs gathers every local $ref in the document.
func collectRefs(node any, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok {
			*out = append(*out, ref)
		}
		for _, child := range v {
			collectRefs(child, out)
		}
	case []any:
		for _, child := range v {
			collectRefs(child, out)
		}
	}
}
