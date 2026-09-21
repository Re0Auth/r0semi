package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testSource(name, issuer string, status SourceStatus) Source {
	return Source{
		Game: game, Name: name, DisplayName: name, Issuer: issuer, Status: status,
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	}
}

func faultySource(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// An unbound pinned source must fail, never be swapped for another.
func TestPinnedSourceIsNotSubstituted(t *testing.T) {
	bad := faultySource(t)
	good := fakeSource(t, http.StatusOK, `{"ok":true}`)

	reg, err := NewRegistry(testSource("a-src", bad.URL, StatusActive), testSource("b-src", good.URL, StatusActive))
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: good.Client(), BaseURL: "https://re0auth.test"},
		bindAll(t, "upstream-token", "a-src", "b-src"))

	_, err = svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile", Source: "a-src"})
	var se *SourceError
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want the pinned source's failure", err)
	}
}

// Without a pin, a failing source falls back to another and reports degraded.
func TestFetchFallsBackAndMarksDegraded(t *testing.T) {
	bad := faultySource(t)
	good := fakeSource(t, http.StatusOK, `{"ok":true}`)

	reg, err := NewRegistry(testSource("a-src", bad.URL, StatusActive), testSource("b-src", good.URL, StatusActive))
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: good.Client(), BaseURL: "https://re0auth.test"},
		bindAll(t, "upstream-token", "a-src", "b-src"))

	res, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "b-src" || !res.Degraded {
		t.Fatalf("result = %+v, want b-src degraded", res)
	}
}

// A retired source is never selected unpinned.
func TestRetiredSourceIsExcluded(t *testing.T) {
	retired := fakeSource(t, http.StatusOK, `{"from":"a-src"}`)
	active := fakeSource(t, http.StatusOK, `{"from":"b-src"}`)

	reg, err := NewRegistry(testSource("a-src", retired.URL, StatusRetired), testSource("b-src", active.URL, StatusActive))
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: active.Client(), BaseURL: "https://re0auth.test"},
		bindAll(t, "upstream-token", "a-src", "b-src"))

	res, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "b-src" || res.Degraded {
		t.Fatalf("result = %+v, want b-src not degraded", res)
	}
}

func TestPinnedRetiredSourceIsGone(t *testing.T) {
	retired := fakeSource(t, http.StatusOK, `{}`)
	reg, err := NewRegistry(testSource("a-src", retired.URL, StatusRetired))
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: retired.Client(), BaseURL: "https://re0auth.test"},
		bindAll(t, "upstream-token", "a-src"))

	_, err = svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile", Source: "a-src"})
	if !errors.Is(err, ErrSourceRetired) {
		t.Fatalf("err = %v, want ErrSourceRetired", err)
	}
}

// Active sources are preferred over degraded ones.
func TestActiveBeatsDegraded(t *testing.T) {
	degraded := fakeSource(t, http.StatusOK, `{"from":"a-src"}`)
	active := fakeSource(t, http.StatusOK, `{"from":"b-src"}`)

	reg, err := NewRegistry(testSource("a-src", degraded.URL, StatusDegraded), testSource("b-src", active.URL, StatusActive))
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: active.Client(), BaseURL: "https://re0auth.test"},
		bindAll(t, "upstream-token", "a-src", "b-src"))

	res, err := svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "b-src" || res.Degraded {
		t.Fatalf("result = %+v, want the active source", res)
	}
}

// When every candidate is merely unbound, the first one drives the bind prompt.
func TestAllUnboundReportsFirstSource(t *testing.T) {
	reg, err := NewRegistry(
		testSource("a-src", "https://a.example", StatusActive),
		testSource("b-src", "https://b.example", StatusActive),
	)
	if err != nil {
		t.Fatal(err)
	}
	svc := mustService(t, Config{Registry: reg, Doer: http.DefaultClient, BaseURL: "https://re0auth.test"},
		backend{store: NewMemoryBindingStore(), vault: newVault(t)})

	_, err = svc.Fetch(context.Background(), FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	var nb *NotBoundError
	if !errors.As(err, &nb) || nb.Source != "a-src" {
		t.Fatalf("err = %v, want NotBoundError for a-src", err)
	}
}
