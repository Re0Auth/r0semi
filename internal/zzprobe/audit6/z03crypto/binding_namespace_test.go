//go:build audit6

// Probes against the federation bind path — the vault's only production
// caller — for the identity namespace it feeds and for what happens to the
// stored credential when the vault's audit write fails.
package z03crypto

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/vault"
)

// bindService wires a federation Service over the given vault service, with one
// source per game/name pair handed in. The binding store is returned so a probe
// can assert what rows exist.
func bindService(t *testing.T, v vault.Service, issuer string, pairs ...[2]string) (federation.Service, *federation.MemoryBindingStore) {
	t.Helper()
	sources := make([]federation.Source, 0, len(pairs))
	for i, p := range pairs {
		sources = append(sources, federation.Source{
			Game: p[0], Name: p[1], DisplayName: "Fake",
			Issuer:     issuer,
			ClientID:   "cid-" + string(rune('A'+i)),
			TokenClass: "revocable",
			Resources: []federation.Resource{{
				Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read",
			}},
		})
	}
	reg, err := federation.NewRegistry(sources...)
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, bindings
}

// completeBind drives one full bind through the real BeginBind/CompleteBind
// flow and returns the outcome.
func completeBind(t *testing.T, svc federation.Service, user, game, source string) error {
	t.Helper()
	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, userID(user), game, source, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("client_id") == "" {
		t.Fatal("control: the authorize URL carries no client id")
	}
	_, _, err = svc.CompleteBind(ctx, userID(user), ch.ID, "code-1")
	return err
}

// TestProbeBindingProviderNamespaceCollides is the red probe for the finding:
// BindingIdentity joins game and source with a bare dot and nothing validates
// the characters of either, so two distinct (game, source) pairs map to ONE
// vault identity. Binding the second overwrites the first's credential, reads
// through the first present the second's upstream token, and unbinding either
// shreds the other's credential.
func TestProbeBindingProviderNamespaceCollides(t *testing.T) {
	ctx := context.Background()
	up := newFakeUpstream(t)
	repo := vault.NewMemoryRepo()
	v := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())

	// Control 1: the registry rejects the same join collision when the
	// separator is "/" (sourceKey is deduplicated), which is what makes the
	// vault's dotted join the unguarded one.
	if _, err := federation.NewRegistry(
		federation.Source{Game: "a/b", Name: "c", Issuer: up.URL},
		federation.Source{Game: "a", Name: "b/c", Issuer: up.URL},
	); err == nil {
		t.Fatal("control: the registry accepted a '/'-join collision; the dedup premise of this probe is wrong")
	}

	// Control 2: with names that do not collide, two bindings hold distinct
	// credentials — the isolation this probe asserts.
	distinct, _ := bindService(t, v, up.URL, [2]string{"gamea", "src-x"}, [2]string{"gamea", "src-y"})
	if err := completeBind(t, distinct, "usr_ctrl", "gamea", "src-x"); err != nil {
		t.Fatal(err)
	}
	if err := completeBind(t, distinct, "usr_ctrl", "gamea", "src-y"); err != nil {
		t.Fatal(err)
	}
	idX := federation.BindingIdentity(federation.Binding{User: userID("usr_ctrl"), Game: "gamea", Source: "src-x"})
	got, err := useSecret(t, v, idX)
	if err != nil || accessTokenOf(t, []byte(got)) != "token-for-cid-A" {
		t.Fatalf("control: src-x reads %q, %v; the fixture is not isolating credentials", accessTokenOf(t, []byte(got)), err)
	}

	// The probe: two sources whose (game, source) joins are the same string,
	// which the registry accepts because sourceKey's separator is "/".
	svc, bindings := bindService(t, v, up.URL, [2]string{"phigros", "official.beta"}, [2]string{"phigros.official", "beta"})
	if err := completeBind(t, svc, "usr_1", "phigros", "official.beta"); err != nil {
		t.Fatal(err)
	}
	if err := completeBind(t, svc, "usr_1", "phigros.official", "beta"); err != nil {
		t.Fatal(err)
	}
	bindingA := federation.BindingIdentity(federation.Binding{User: userID("usr_1"), Game: "phigros", Source: "official.beta"})
	bindingB := federation.BindingIdentity(federation.Binding{User: userID("usr_1"), Game: "phigros.official", Source: "beta"})
	if bindingA != bindingB {
		t.Fatalf("control: the two bindings do not share a vault identity (%v vs %v)", bindingA, bindingB)
	}
	// Both binding rows exist, each believing it holds its own credential.
	if rows, err := bindings.List(ctx, userID("usr_1")); err != nil || len(rows) != 2 {
		t.Fatalf("binding rows = %d, %v; want two", len(rows), err)
	}

	got, err = useSecret(t, v, bindingA)
	if err != nil {
		t.Fatal(err)
	}
	if tok := accessTokenOf(t, []byte(got)); tok != "token-for-cid-A" {
		t.Errorf("CONFIRMED: the credential of (phigros, official.beta) reads %q — the token bound to the "+
			"OTHER source is served under this binding: two distinct sources share one vault row", tok)
	}

	// Unbinding the other source shreds this one's credential: the same row.
	if _, err := svc.Unbind(ctx, userID("usr_1"), "phigros.official", "beta"); err != nil {
		t.Fatal(err)
	}
	if exists, err := v.Exists(ctx, bindingA); err != nil || !exists {
		t.Errorf("CONFIRMED: after unbinding (phigros.official, beta) the credential of (phigros, "+
			"official.beta) no longer opens (exists=%v, %v): one source's unbind crypto-shredded "+
			"another source's credential — they share one vault row", exists, err)
	}
	// ...while the first binding's row still points at the now-missing secret.
	if rows, err := bindings.List(ctx, userID("usr_1")); err != nil || len(rows) != 1 || rows[0].Game != "phigros" {
		t.Fatalf("binding rows after the cross-shred = %d, %v; want the phigros row to survive", len(rows), err)
	}
}

// TestProbeBindAuditFailureStrandsTheUpstreamToken is the red probe for the
// finding: Enroll persists the credential and only then writes its audit
// record, so a failing audit sink returns an error while the credential is
// already stored. On the bind path there is no rollback and no operator log —
// the residue class the sibling failure (bindings.Put) rolls back and joins
// into the error.
func TestProbeBindAuditFailureStrandsTheUpstreamToken(t *testing.T) {
	ctx := context.Background()
	up := newFakeUpstream(t)
	repo := vault.NewMemoryRepo()
	wrapper := mustWrapper(t, "kek-1", 0xA1)

	// Control: the same fixture with a working audit sink binds successfully.
	goodVault := mustService(t, repo, wrapper, audit.NewMemoryLogger())
	goodSvc, goodBindings := bindService(t, goodVault, up.URL, [2]string{"phigros", "fake"})
	if err := completeBind(t, goodSvc, "usr_ctrl", "phigros", "fake"); err != nil {
		t.Fatalf("control: a bind against a working audit sink failed: %v", err)
	}
	ctrlID := federation.BindingIdentity(federation.Binding{User: userID("usr_ctrl"), Game: "phigros", Source: "fake"})
	if rows, err := goodBindings.List(ctx, userID("usr_ctrl")); err != nil || len(rows) != 1 {
		t.Fatalf("control: the working bind left %d rows, %v", len(rows), err)
	}
	if exists, _ := goodVault.Exists(ctx, ctrlID); !exists {
		t.Fatal("control: the working bind stored no credential")
	}

	// The probe: a vault whose audit sink is down while its store is up.
	strandedID := federation.BindingIdentity(federation.Binding{User: userID("usr_1"), Game: "phigros", Source: "fake"})
	failing := mustService(t, repo, wrapper, failingLogger{err: errProbeSink})
	svc, bindings := bindService(t, failing, up.URL, [2]string{"phigros", "fake"})

	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	err := completeBind(t, svc, "usr_1", "phigros", "fake")
	if err == nil {
		t.Fatal("control: the bind succeeded although the audit sink is failing; the fixture is not failing")
	}

	// No binding row points at the credential the exchange produced.
	if rows, berr := bindings.List(ctx, userID("usr_1")); berr != nil || len(rows) != 0 {
		t.Fatalf("binding rows after the failed bind = %d, %v; want none", len(rows), berr)
	}

	// The residue: present and decryptable, reachable by no endpoint.
	blob, uerr := useSecret(t, goodVault, strandedID)
	switch {
	case uerr == nil:
		t.Fatalf("CONFIRMED: the bind reported failure (%v) yet stored a decryptable upstream token "+
			"(%q) that no binding row points at and only an account erasure clears; the sibling failure "+
			"path rolls the secret back and joins the residue into the error, this path does neither. "+
			"Operator log at the time: %q",
			err, accessTokenOf(t, []byte(blob)), logged.String())
	case errors.Is(uerr, vault.ErrNotFound):
		t.Log("the failed bind left no credential behind — the residue is gone")
	default:
		t.Fatalf("unexpected: the record exists but does not open: %v", uerr)
	}
}
