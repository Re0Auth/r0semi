//go:build audit7

// Z09-3: a retired source can still be bound.
//
// `federation.candidates` never selects a retired source, `Raw` refuses one and
// the account page reports `bindable: false` for one — three places agree that a
// retired source is out of service. `BeginBind`/`CompleteBind` are not one of
// them: they look the source up and check only that a client is configured, so a
// hand-written `/bind?game=..&source=..` link (the same link shape the 409
// `source_not_bound` body hands out) starts a real flow, and completing it
// enrolls the user's upstream token in the vault for a source the data plane will
// never call.
//
// This is the FO-01 shape (two decisions, one object) with a much smaller blast
// radius: the presenter says "not offerable" and the actor says "yes".
package zzprobe_z09federationdataplane

import (
	"context"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
)

func zzBindService(t *testing.T, reg *federation.Registry) federation.Service {
	t.Helper()
	svc, err := federation.NewService(federation.Config{
		Registry: reg,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    newTestVault(t),
		Doer:     http.DefaultClient,
		BaseURL:  "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestZ09ARetiredSourceCanStillBeBound(t *testing.T) {
	ctx := context.Background()
	reg, err := federation.NewRegistry(
		federation.Source{
			Game: zzGame, Name: "gone", DisplayName: "Gone", Issuer: "https://gone.example",
			ClientID: "cid", ClientSecret: "sec", Status: federation.StatusRetired,
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
			},
		},
		federation.Source{
			Game: zzGame, Name: "live", DisplayName: "Live", Issuer: "https://live.example",
			ClientID: "cid", ClientSecret: "sec", Status: federation.StatusActive,
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	svc := zzBindService(t, reg)

	// Control 1 (the presenter): only the live source is offered.
	reqs, err := svc.MissingBindings(ctx, "usr_1", []string{zzProfileScope})
	if err != nil {
		t.Fatal(err)
	}
	var offered []string
	for _, r := range reqs {
		offered = append(offered, r.Source)
	}
	t.Logf("MissingBindings offers %v for %q", offered, zzProfileScope)
	if len(offered) != 1 || offered[0] != "live" {
		t.Fatalf("the presenter offered %v; the probe needs exactly [live] to be discriminating "+
			"(the retired source must not be offered)", offered)
	}

	// Control 2 (the actor, positive): the live source can be bound.
	if _, err := svc.BeginBind(ctx, "usr_1", zzGame, "live", "/app/sources"); err != nil {
		t.Fatalf("BeginBind(live) = %v; the probe needs the live source to work", err)
	}

	// The finding: the retired source can be bound too.
	ch, err := svc.BeginBind(ctx, "usr_1", zzGame, "gone", "/app/sources")
	if err == nil {
		t.Errorf("BeginBind started a binding flow for a RETIRED source: %s. The account page reports "+
			"bindable=false for this source and candidates() never selects it, so completing this flow stores "+
			"the user's upstream credential (vault.Enroll, bind.go:192-197) for a source the data plane will "+
			"never call. CompleteBind re-reads the same registry entry and has no status check either",
			ch.AuthorizeURL)
	} else {
		t.Logf("BeginBind(gone) was refused: %v", err)
	}
}
