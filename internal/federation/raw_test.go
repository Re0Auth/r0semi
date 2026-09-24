package federation

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func rawSource(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/native/scores" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("limit") != "5" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.native+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"native":true,"field":1}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func rawService(t *testing.T, up *httptest.Server, rawBase string, status SourceStatus) (Service, backend) {
	t.Helper()
	src := testSource(sourceName, "https://up.example", status)
	src.RawBase = rawBase
	reg, err := NewRegistry(src)
	if err != nil {
		t.Fatal(err)
	}
	b := bindAll(t, "upstream-token", sourceName)
	return mustService(t, Config{Registry: reg, Doer: up.Client(), BaseURL: "https://re0auth.test"}, b), b
}

func TestRawPassthroughIsVerbatim(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, up.URL, StatusActive)

	res, err := svc.Raw(context.Background(), RawRequest{
		User: "usr_1", Game: game, Source: sourceName,
		Path: "v1/native/scores", Query: map[string][]string{"limit": {"5"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d", res.Status)
	}
	if res.ContentType != "application/vnd.native+json" {
		t.Fatalf("content type = %q", res.ContentType)
	}
	if string(res.Body) != `{"native":true,"field":1}` {
		t.Fatalf("body = %s", res.Body)
	}
	if res.Source != sourceName {
		t.Fatalf("source = %q", res.Source)
	}
}

// A raw request with no binding is reported like any other fetch.
func TestRawWithoutBinding(t *testing.T) {
	up := rawSource(t)
	reg, err := NewRegistry(func() Source {
		s := testSource(sourceName, "https://up.example", StatusActive)
		s.RawBase = up.URL
		return s
	}())
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: up.Client(), BaseURL: "https://re0auth.test"},
		backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	_, err = svc.Raw(context.Background(), RawRequest{User: "usr_1", Game: game, Source: sourceName, Path: "v1/native/scores"})
	if !errors.Is(err, ErrNotBound) {
		t.Fatalf("err = %v, want ErrNotBound", err)
	}
}

func TestRawUnsupported(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, "", StatusActive) // no RawBase

	_, err := svc.Raw(context.Background(), RawRequest{User: "usr_1", Game: game, Source: sourceName, Path: "x"})
	if !errors.Is(err, ErrRawUnsupported) {
		t.Fatalf("err = %v, want ErrRawUnsupported", err)
	}
}

func TestRawRetired(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, up.URL, StatusRetired)

	_, err := svc.Raw(context.Background(), RawRequest{User: "usr_1", Game: game, Source: sourceName, Path: "x"})
	if !errors.Is(err, ErrSourceRetired) {
		t.Fatalf("err = %v, want ErrSourceRetired", err)
	}
}

func TestRawUnknownSource(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, up.URL, StatusActive)

	_, err := svc.Raw(context.Background(), RawRequest{User: "usr_1", Game: game, Source: "nope", Path: "x"})
	if !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
}

// A raw path may not climb out of the source's base URL.
//
// In the assembled server this cannot be reached: ServeMux cleans `..` out of
// r.URL.Path before it matches a route. That is the point of testing it here
// instead — the guard protects a property of THIS package, and it has to hold
// wherever Raw is called from, not only where the standard library happens to be
// in front of it.
func TestRawPathEscapingTheBaseIsRefused(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, up.URL, StatusActive)

	for _, p := range []string{"..", "../admin", "v1/../../admin", "a/b/../../../etc/passwd"} {
		_, err := svc.Raw(context.Background(), RawRequest{
			User: "usr_1", Game: game, Source: sourceName, Path: p,
		})
		if !errors.Is(err, ErrRawPathEscapes) {
			t.Errorf("path %q: err = %v, want ErrRawPathEscapes", p, err)
		}
	}
}

// The normalization is applied on the way out, not merely validated: the source
// sees the path the caller denoted, so a redundant segment cannot become a
// different upstream resource.
func TestRawPathIsNormalizedBeforeItIsSent(t *testing.T) {
	up := rawSource(t)
	svc, _ := rawService(t, up, up.URL, StatusActive)

	// rawSource answers only "/v1/native/scores"; an uncleaned "/v1/./native/scores"
	// is a 404 from it, so a 200 is evidence the cleaning happened.
	res, err := svc.Raw(context.Background(), RawRequest{
		User: "usr_1", Game: game, Source: sourceName,
		Path: "v1/./native/scores", Query: map[string][]string{"limit": {"5"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200: the path was not normalized", res.Status)
	}
}

func TestCleanRawPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"v1/native/scores", "v1/native/scores"},
		{"/v1/native/scores", "v1/native/scores"},
		{"v1//native///scores", "v1/native/scores"},
		{"v1/./native/scores", "v1/native/scores"},
		{"", ""},
		{"/", ""},
		// A literal percent sign is not an escape, so it is left for the source to
		// read as the text it is. Refusing it would break a legitimate path.
		{"100%25/x", "100%25/x"},
	} {
		got, err := cleanRawPath(tc.in)
		if err != nil {
			t.Fatalf("cleanRawPath(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("cleanRawPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Refused, not resolved. `a/../b` would clean to `b`, which is a meaning the
	// passthrough contract does not grant.
	//
	// The encoded forms are the ones round 4 added: net/http unescapes a wildcard
	// value exactly once, so the caller still controls a second encoding, and a
	// check that only looks for a literal `..` misses them all.
	for _, bad := range []string{
		"..", "../x", "a/../..", "a/../../b", "x/..",
		"%2e%2e/x", "%2E%2E/x", "%2e%2e%2fadmin", "%252e%252e/x",
		"..;/admin", `..\..\x`,
	} {
		if _, err := cleanRawPath(bad); !errors.Is(err, ErrRawPathEscapes) {
			t.Errorf("cleanRawPath(%q) = %v, want ErrRawPathEscapes", bad, err)
		}
	}
}

// Round 4: a body past the cap is an error, not a truncated 200.
//
// io.LimitReader cannot tell "exactly the limit" from "more than the limit", so
// the proxy used to hand back a short body wearing the upstream's status and
// content type — a response asserting a completeness it does not have, on the one
// endpoint whose contract is "verbatim". For the byte-oriented payloads raw exists
// for (NDJSON, CSV, plain text) the truncation stays syntactically valid, so
// nothing downstream can notice it.
func TestRawRefusesABodyPastTheCap(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxBody+1))
	}))
	t.Cleanup(up.Close)

	svc, _ := rawService(t, up, up.URL, StatusActive)

	_, err := svc.Raw(context.Background(), RawRequest{
		User: "usr_1", Game: game, Source: sourceName, Path: "big",
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

// Round 4: a raw_base that is not an absolute http(s) URL, or that carries its own
// query or fragment, silently changes what every raw request means. With `?x=1`
// the caller's path and query are appended to the query string, the path guard is
// never consulted on the join it was written for, and the subject's upstream token
// is sent to whatever that string resolves to.
func TestRegistryRejectsAMalformedRawBase(t *testing.T) {
	for _, bad := range []string{
		"//evil.example/v1",
		"api/v1",
		"ftp://api.example/v1",
		"https://api.example/v1?x=1",
		"https://api.example/v1#frag",
	} {
		src := testSource(sourceName, "https://up.example", StatusActive)
		src.RawBase = bad
		if _, err := NewRegistry(src); err == nil {
			t.Errorf("NewRegistry accepted raw_base %q", bad)
		}
	}

	// The ordinary values keep working, so the rule is a malformed-URL check and
	// not a blanket refusal.
	for _, good := range []string{"https://api.example/v1", "http://127.0.0.1:8080"} {
		src := testSource(sourceName, "https://up.example", StatusActive)
		src.RawBase = good
		if _, err := NewRegistry(src); err != nil {
			t.Errorf("NewRegistry refused raw_base %q: %v", good, err)
		}
	}
}
