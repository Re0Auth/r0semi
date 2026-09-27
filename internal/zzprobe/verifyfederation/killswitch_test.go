//go:build audit5

package zzprobe_verifyfederation

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

// failingPager is a store that can page and fails on the Nth page. The audit
// claims a "第 2 页起失败" store cannot be built without a database; it can, because
// federation.Config.Bindings is an interface.
type failingPager struct {
	*federation.MemoryBindingStore
	pages  int
	failAt int
}

func (f *failingPager) ListAllPage(ctx context.Context, afterUser, afterGame, afterSource string, limit int) ([]federation.Binding, error) {
	f.pages++
	if f.failAt > 0 && f.pages >= f.failAt {
		return nil, errors.New("verify: page fetch failed")
	}
	return f.MemoryBindingStore.ListAllPage(ctx, afterUser, afterGame, afterSource, limit)
}

func TestVerifyPartialKillSwitchSummaryIsDiscardedByTheOperatorPlane(t *testing.T) {
	ctx := context.Background()
	srv := recordingServer(t, nil, `{"ok":true}`)

	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: srv.URL, TokenClass: "revocable",
		RevocationEndpoint: srv.URL + "/oauth/revoke",
		Resources:          []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &failingPager{MemoryBindingStore: federation.NewMemoryBindingStore(), failAt: 3}
	v := newTestVault(t)
	for i := 0; i < 5; i++ {
		b := federation.Binding{
			User: account.UserID(fmt.Sprintf("usr_%d", i)), Game: "phigros", Source: "src",
			Version: uint64(i + 1),
		}
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := v.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "tok", ""), nil); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
		KillSwitchPageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	summary, serr := svc.RevokeAllBindings(ctx)
	t.Logf("federation.RevokeAllBindings after page %d failed: summary=%+v err=%v", store.failAt, summary, serr)
	if serr == nil {
		t.Fatal("fixture: the paged sweep should have failed")
	}
	if summary.Total == 0 {
		t.Fatalf("fixture: nothing was swept before the failure, so there is no partial summary to lose")
	}
	left, _ := store.ListAll(ctx)
	t.Logf("bindings already cut and no longer listed: %d of 5; still present: %d", summary.Total, len(left))

	// The operator plane gets (outcome, err) from its adapter and throws the
	// outcome away on the error branch.
	logger := newAuditLogger()
	adminSvc, err := admin.New(admin.Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: oauth.NewMemoryStore(),
		Bindings: partialBindingRevoker{fed: svc}, Audit: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, aerr := adminSvc.KillSwitch(ctx, "usr_admin", admin.Target{Bindings: true})
	t.Logf("admin.KillSwitch: err=%v report.Bindings=%v", aerr, rep.Bindings)
	if aerr == nil {
		t.Fatal("fixture: the operator action should have failed")
	}
	if rep.Bindings != nil {
		t.Errorf("the partial summary reached the operator: %+v", rep.Bindings)
	}
	for _, e := range logger.Events() {
		if e.Action != "admin.kill_switch" {
			continue
		}
		t.Logf("audit row: outcome=%s detail=%v", e.Outcome, e.Detail)
		if _, ok := e.Detail["bindings_revoked"]; ok {
			t.Logf("the audit chain does carry the partial counts")
		} else {
			t.Logf("the audit chain does NOT carry the partial counts: only %v", e.Detail)
		}
	}
}

// partialBindingRevoker is the composition root's adapter (main.go:1333) without
// its package boundary.
type partialBindingRevoker struct{ fed federation.Service }

func (p partialBindingRevoker) RevokeAllBindings(ctx context.Context) (admin.BindingOutcome, error) {
	s, err := p.fed.RevokeAllBindings(ctx)
	return admin.BindingOutcome{
		Total: s.Total, Revoked: s.Revoked, Cascade: s.Cascade, Unsupported: s.Unsupported,
		Unavailable: s.Unavailable, Orphaned: s.Orphaned, Failed: s.Failed,
	}, err
}

func (p partialBindingRevoker) RevokeSubjectBindings(ctx context.Context, subject string) (admin.BindingOutcome, error) {
	s, err := p.fed.RevokeUserBindings(ctx, account.UserID(subject))
	return admin.BindingOutcome{Total: s.Total, Revoked: s.Revoked, Failed: s.Failed}, err
}
