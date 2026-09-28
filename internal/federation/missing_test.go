package federation

import (
	"context"
	"net/http"
	"testing"
)

const scoreScope = "phigros.score.read"

func sourceWith(name string, status SourceStatus, resources ...Resource) Source {
	return Source{
		Game: game, Name: name, DisplayName: name,
		Issuer: "https://" + name + ".example", Status: status,
		Resources: resources,
	}
}

func profileResource() Resource {
	return Resource{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}
}

func scoreResource() Resource {
	return Resource{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: scoreScope}
}

func missingService(t *testing.T, sources ...Source) (Service, backend) {
	t.Helper()
	reg, err := NewRegistry(sources...)
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	return mustService(t, Config{Registry: reg, Doer: nopDoer{}, BaseURL: "https://re0auth.test"}, b), b
}

// nopDoer is never called by MissingBindings; it only satisfies NewService.
type nopDoer struct{}

func (nopDoer) Do(*http.Request) (*http.Response, error) { panic("unused") }

// A scope no source declares needs no data source.
func TestMissingBindingsIgnoresUnknownScope(t *testing.T) {
	svc, _ := missingService(t, sourceWith("a-src", StatusActive, profileResource()))

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{"account.id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Fatalf("requirements = %+v, want none", reqs)
	}
}

// An already connected source satisfies the scope.
func TestMissingBindingsSatisfiedByConnectedSource(t *testing.T) {
	reg, err := NewRegistry(sourceWith("a-src", StatusActive, profileResource()))
	if err != nil {
		t.Fatal(err)
	}
	b := bindAll(t, "upstream-token", "a-src")
	svc := mustService(t, Config{Registry: reg, Doer: nopDoer{}, BaseURL: "https://re0auth.test"}, b)

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Fatalf("requirements = %+v, want none for a bound source", reqs)
	}
}

// With nothing connected, the requirement names the preferred source.
func TestMissingBindingsNamesPreferredSource(t *testing.T) {
	svc, _ := missingService(t,
		sourceWith("a-src", StatusActive, profileResource()),
		sourceWith("b-src", StatusActive, profileResource()),
	)

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("requirements = %+v, want one", reqs)
	}
	got := reqs[0]
	if got.Game != game || got.Source != "a-src" || got.DisplayName != "a-src" {
		t.Fatalf("requirement = %+v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != profileScope {
		t.Fatalf("scopes = %v", got.Scopes)
	}
}

// Active sources are preferred to degraded ones, matching the data plane.
func TestMissingBindingsPrefersActiveOverDegraded(t *testing.T) {
	svc, _ := missingService(t,
		sourceWith("a-src", StatusDegraded, profileResource()),
		sourceWith("b-src", StatusActive, profileResource()),
	)

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Source != "b-src" {
		t.Fatalf("requirements = %+v, want b-src", reqs)
	}
}

// A retired source is never offered.
func TestMissingBindingsSkipsRetiredSource(t *testing.T) {
	svc, _ := missingService(t, sourceWith("a-src", StatusRetired, profileResource()))

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Fatalf("requirements = %+v, want none for a retired source", reqs)
	}
}

// One source covering two requested scopes produces one requirement.
func TestMissingBindingsGroupsScopesBySource(t *testing.T) {
	svc, _ := missingService(t, sourceWith("a-src", StatusActive, profileResource(), scoreResource()))

	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope, scoreScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("requirements = %+v, want one", reqs)
	}
	if len(reqs[0].Scopes) != 2 {
		t.Fatalf("scopes = %v, want both", reqs[0].Scopes)
	}
}

// "Satisfied" uses the data plane's resource-name criterion, not the scope
// string. Two sources declare the same resource name under different scopes; the
// account is bound to the one whose scope is NOT requested. The read is served by
// the bound source, so nothing is missing — keying on the scope alone would
// instead prompt for a binding the read does not need.
func TestMissingBindingsSatisfiedByResourceNameNotScope(t *testing.T) {
	reg, err := NewRegistry(
		sourceWith("a-src", StatusActive, Resource{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}),
		sourceWith("b-src", StatusActive, Resource{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: scoreScope}),
	)
	if err != nil {
		t.Fatal(err)
	}
	b := bindAll(t, "upstream-token", "b-src")
	svc := mustService(t, Config{Registry: reg, Doer: nopDoer{}, BaseURL: "https://re0auth.test"}, b)

	// The requested scope belongs to a-src, which is NOT bound; but the read for
	// resource `profile` is served by b-src, which is.
	reqs, err := svc.MissingBindings(context.Background(), "usr_1", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Fatalf("requirements = %+v, want none: the read is servable through the bound source", reqs)
	}

	// Anti-vacuity: an unbound account is prompted.
	reqs, err = svc.MissingBindings(context.Background(), "usr_2", []string{profileScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) == 0 {
		t.Fatal("an unbound account was not prompted, so the agreement above is vacuous")
	}
}
