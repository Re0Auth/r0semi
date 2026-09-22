package oauth

import "testing"

func TestScopeValid(t *testing.T) {
	for _, ok := range []Scope{"account.id", "phigros.b30.read", "a_b.c0"} {
		if !ok.valid() {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []Scope{"account", "account.", ".id", "Account.id", "a.b-c"} {
		if bad.valid() {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestDefaultRegistryHasMVPScopes(t *testing.T) {
	r := DefaultRegistry()
	for _, s := range []Scope{ScopeAccountID, ScopeTapTapAccount, ScopePhigrosProfile, ScopePhigrosScore, ScopePhigrosB30} {
		if _, ok := r.Get(s); !ok {
			t.Errorf("missing scope %s", s)
		}
	}
	// Guard against a scope creeping back that re0auth cannot serve. The catalog
	// must not advertise a capability the broker has no credential to back.
	if _, ok := r.Get("taptap.stoken.read"); ok {
		t.Fatal("the catalog advertises an upstream-credential export scope again")
	}
	for _, d := range r.Descriptors() {
		if d.ExplicitConsent {
			t.Fatalf("the built-in catalog has an ExplicitConsent scope: %s", d.Scope)
		}
	}
}

func TestRegistryRejectsDuplicateAndMalformed(t *testing.T) {
	r := DefaultRegistry()
	if err := r.Register(DefaultDescriptors()[0]); err == nil {
		t.Fatal("accepted a duplicate scope")
	}
	if err := r.Register(Descriptor{Scope: "bad", Title: "x"}); err == nil {
		t.Fatal("accepted a malformed scope")
	}
	if err := r.Register(Descriptor{Scope: "good.one"}); err == nil {
		t.Fatal("accepted a scope without a title")
	}
}

func TestRegistryResolve(t *testing.T) {
	r := DefaultRegistry()
	if _, err := r.Resolve([]Scope{ScopeAccountID}, "c"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := r.Resolve([]Scope{"unknown.scope"}, "c"); err == nil {
		t.Fatal("accepted an unknown scope")
	}
}

func TestRegistryResolveHonorsClientAllowlist(t *testing.T) {
	r, err := NewRegistry(Descriptor{
		Scope:          "special.thing",
		Title:          "Special",
		Risk:           RiskHigh,
		AllowedClients: []string{"first-party"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve([]Scope{"special.thing"}, "first-party"); err != nil {
		t.Fatalf("allowlisted client rejected: %v", err)
	}
	if _, err := r.Resolve([]Scope{"special.thing"}, "third-party"); err == nil {
		t.Fatal("non-allowlisted client was accepted")
	}
}
