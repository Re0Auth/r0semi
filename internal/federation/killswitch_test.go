package federation

import (
	"context"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// connectTo drives the real binding flow against a named source, so a binding
// under test came from the code that produces bindings.
func connectTo(t *testing.T, svc Service, user string, source string) Binding {
	t.Helper()
	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, account.UserID(user), game, source, "/app/sources")
	if err != nil {
		t.Fatal(err)
	}
	binding, _, err := svc.CompleteBind(ctx, account.UserID(user), ch.ID, "upstream-code")
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// multiSourceService builds a service over the given sources, which is what a
// deployment-wide sweep needs in order to exercise more than one source at once.
func multiSourceService(t *testing.T, srcs ...Source) (Service, *MemoryBindingStore, vault.Service) {
	t.Helper()
	reg, err := NewRegistry(srcs...)
	if err != nil {
		t.Fatal(err)
	}
	bindings := NewMemoryBindingStore()
	v := newVault(t)
	svc, err := NewService(Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, bindings, v
}

// A deployment-wide sweep must cut every binding, through the strongest upstream
// action each source allows, and leave nothing behind.
func TestRevokeAllBindingsCutsEverySource(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)

	cascade := unbindSource(up.URL, "revocable")
	cascade.Name = "cascade"
	cascade.DisplayName = "Cascade"
	cascade.CascadeRevocationEndpoint = up.URL + "/oauth/cascade_revocation"
	plain := unbindSource(up.URL, "revocable")

	svc, bindings, v := multiSourceService(t, cascade, plain)
	ctx := context.Background()
	connectTo(t, svc, "usr_1", "cascade")
	connectTo(t, svc, "usr_1", sourceName)
	connectTo(t, svc, "usr_2", sourceName)

	summary, err := svc.RevokeAllBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 3 || summary.Revoked != 3 {
		t.Fatalf("summary = %+v, want 3 total and 3 revoked", summary)
	}
	if summary.Cascade != 1 {
		t.Fatalf("cascade = %d, want the one cascade-capable binding", summary.Cascade)
	}
	if summary.Unsupported != 0 || summary.Unavailable != 0 || summary.Orphaned != 0 || summary.Failed != 0 {
		t.Fatalf("unexpected outcomes: %+v", summary)
	}
	if calls := rec.calls(); len(calls) != 2 {
		t.Fatalf("token revocations = %v, want the two plain bindings", calls)
	}
	if cascadeCalls := rec.cascadeCalls(); len(cascadeCalls) != 1 {
		t.Fatalf("cascade calls = %v, want one", cascadeCalls)
	}
	if all, _ := bindings.ListAll(ctx); len(all) != 0 {
		t.Fatalf("bindings survived: %+v", all)
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(Binding{User: "usr_1", Game: game, Source: sourceName})); exists {
		t.Fatal("a binding secret survived")
	}
}

// A source that declared it cannot revoke must be counted, not claimed as done.
func TestRevokeAllBindingsCountsUnsupported(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := multiSourceService(t, unbindSource(up.URL, "long_lived"))
	connectTo(t, svc, "usr_1", sourceName)

	summary, err := svc.RevokeAllBindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Revoked != 1 || summary.Unsupported != 1 {
		t.Fatalf("summary = %+v, want revoked=1 unsupported=1", summary)
	}
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("a long-lived source was asked to revoke anyway: %v", calls)
	}
}

// A binding whose source is gone still exists and must be shredded locally; there
// is simply no one left to ask.
func TestRevokeAllBindingsShredsOrphanedBindings(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, bindings, v := unbindService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()
	binding := connect(t, svc, "usr_1")

	// A deployment whose registry no longer names the binding's source.
	other := unbindSource(up.URL, "revocable")
	other.Name = "other"
	reg, err := NewRegistry(other)
	if err != nil {
		t.Fatal(err)
	}
	svc2, err := NewService(Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	summary, err := svc2.RevokeAllBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 || summary.Revoked != 1 || summary.Orphaned != 1 {
		t.Fatalf("summary = %+v, want 1 total, 1 revoked, 1 orphaned", summary)
	}
	if exists, _ := v.Exists(ctx, BindingIdentity(binding)); exists {
		t.Fatal("the orphaned binding's secret survived")
	}
	if _, err := bindings.Get(ctx, "usr_1", game, sourceName); err == nil {
		t.Fatal("the orphaned binding row survived")
	}
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("asked a source that is not configured: %v", calls)
	}
}

func TestRevokeUserBindingsLeavesOthersAlone(t *testing.T) {
	rec := &releasingSource{}
	up := newReleasingSource(t, rec)
	svc, _, _ := multiSourceService(t, unbindSource(up.URL, "revocable"))
	ctx := context.Background()
	connectTo(t, svc, "usr_1", sourceName)
	connectTo(t, svc, "usr_2", sourceName)

	summary, err := svc.RevokeUserBindings(ctx, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 || summary.Revoked != 1 {
		t.Fatalf("summary = %+v, want only usr_1's binding", summary)
	}
	if mine, _ := svc.Bindings(ctx, "usr_1"); len(mine) != 0 {
		t.Fatalf("usr_1 still has %+v", mine)
	}
	if other, _ := svc.Bindings(ctx, "usr_2"); len(other) != 1 {
		t.Fatalf("usr_2 binding was touched: %+v", other)
	}
	if _, err := svc.RevokeUserBindings(ctx, ""); err == nil {
		t.Error("RevokeUserBindings accepted an empty user")
	}
}
