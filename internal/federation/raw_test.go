package federation

import (
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
