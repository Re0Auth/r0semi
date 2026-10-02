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
	"strings"
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

// TestProbeBindingProviderNamespaceCollides is G-18's regression guard (name
// kept; it was the finding's demonstration probe). BindingIdentity joins game
// and source with a bare dot, and the finding was that nothing validated either
// half: ("phigros", "official.beta") and ("phigros.official", "beta") mapped to
// ONE vault identity, so binding the second overwrote the first's credential and
// unbinding either crypto-shredded the other.
//
// The join separator cannot change (existing ciphertext is bound to it as AAD),
// so the fix is upstream of it: NewRegistry refuses a '.' inside either half.
// The probe now measures that the colliding pairs cannot both exist, and keeps
// the isolation control.
func TestProbeBindingProviderNamespaceCollides(t *testing.T) {
	up := newFakeUpstream(t)

	// Control: the join really is still a bare dot, so the pairs below are the
	// ones the registry has to refuse. If this ever stops holding, the guard is
	// measuring nothing and must be revisited rather than deleted.
	bindingA := federation.BindingIdentity(federation.Binding{User: userID("usr_1"), Game: "phigros", Source: "official.beta"})
	bindingB := federation.BindingIdentity(federation.Binding{User: userID("usr_1"), Game: "phigros.official", Source: "beta"})
	if bindingA != bindingB {
		t.Fatalf("control: the dotted join no longer collides (%v vs %v); the guard below has no target", bindingA, bindingB)
	}

	// The fix: the registry refuses the separator inside either half, so the
	// colliding configuration is rejected at startup rather than sharing a row.
	if _, err := federation.NewRegistry(
		federation.Source{Game: "phigros", Name: "official.beta", Issuer: up.URL},
		federation.Source{Game: "phigros.official", Name: "beta", Issuer: up.URL},
	); err == nil {
		t.Fatalf("the registry accepted game/source names carrying the '.' join separator: two distinct " +
			"sources can still map to one vault identity (G-18)")
	} else if !strings.Contains(err.Error(), "no '.'") {
		t.Fatalf("the refusal does not name the separator rule it enforces: %v", err)
	}
	for _, bad := range []federation.Source{
		{Game: "phigros", Name: "official.beta", Issuer: up.URL},
		{Game: "phigros.official", Name: "beta", Issuer: up.URL},
		{Game: "phigros.beta", Name: "official", Issuer: up.URL},
	} {
		if _, err := federation.NewRegistry(bad); err == nil {
			t.Errorf("the registry accepted game=%q source=%q, which the vault's dotted join cannot "+
				"keep injective (G-18)", bad.Game, bad.Name)
		}
	}

	// Control: separator-free counterparts are accepted and two bindings hold
	// distinct credentials — the isolation the guard protects.
	repo := vault.NewMemoryRepo()
	v := mustService(t, repo, mustWrapper(t, "kek-1", 0xA1), audit.NewMemoryLogger())
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
}

// TestProbeBindAuditFailureStrandsTheUpstreamToken is G-20's regression guard
// (name kept; it was the finding's demonstration probe). Enroll used to persist
// the credential and only then write its audit record, so a failing audit sink
// returned an error while the credential was already stored — and the bind path
// neither rolled back nor logged, leaving an orphan upstream token.
//
// The fix is fail-closed on both sides: Enroll audits BEFORE it persists
// (vault/service.go:244-257), and CompleteBind rolls the vault back when the
// write fails after its claim (bind.go:285-304). The probe now asserts that no
// decryptable token survives, which is the residue the finding named.
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

	// No decryptable upstream token survives the failed bind. This is the
	// residue the finding named: a secret no binding row points at and only an
	// account erasure clears.
	blob, uerr := useSecret(t, goodVault, strandedID)
	switch {
	case uerr == nil:
		t.Fatalf("CONFIRMED: the bind reported failure (%v) yet stored a decryptable upstream token "+
			"(%q) that no binding row points at and only an account erasure clears; Enroll must audit "+
			"before persisting and CompleteBind must roll the vault back when its write fails. "+
			"Operator log at the time: %q", err, accessTokenOf(t, []byte(blob)), logged.String())
	case errors.Is(uerr, vault.ErrNotFound):
		t.Log("the failed bind left no decryptable credential behind — the residue is gone")
	default:
		t.Fatalf("unexpected: the record exists but does not open: %v", uerr)
	}
	if exists, xerr := goodVault.Exists(ctx, strandedID); xerr != nil || exists {
		t.Errorf("the failed bind still has a vault record for %v (exists=%v, err=%v)", strandedID, exists, xerr)
	}

	// CompleteBind claims the binding row BEFORE the vault write, on purpose: a
	// writer that fails the claim must not have touched the vault, and a failed
	// write must not strand a secret with no row (bind.go:261-284). A metadata
	// row may therefore remain after the refusal — what must not remain is a
	// credential behind it, which the assertions above prove.
	rows, berr := bindings.List(ctx, userID("usr_1"))
	if berr != nil {
		t.Fatalf("listing binding rows after the failed bind: %v", berr)
	}
	t.Logf("binding metadata rows after the failed bind = %d (claim-first; the credential itself is gone)", len(rows))
	for _, row := range rows {
		id := federation.BindingIdentity(row)
		if _, err := useSecret(t, goodVault, id); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("the surviving binding row %v/%v resolves to a live credential: %v", row.Game, row.Source, err)
		}
	}
}
