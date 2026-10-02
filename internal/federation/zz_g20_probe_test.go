package federation

// G-20 probe: CompleteBind must roll the vault back when storeBindingSecret
// fails, and must join (and log) a rollback that also fails.
//
// The probe is RED against the code before the fix: that code returned the
// vault-write failure without calling vault.Revoke, so a secret the vault may
// already have written could outlive the report. It is GREEN after, and every
// assertion carries an anti-vacuity control so it cannot pass for the wrong
// reason.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/vault"
)

// g20Vault is a vault.Service that fails Enroll (the storeBindingSecret call)
// and records every Revoke (the rollback call). Enroll never writes, so a
// recorded Revoke can only come from the rollback path.
type g20Vault struct {
	vault.Service
	enrollErr error
	revokeErr error

	mu      sync.Mutex
	revokes []vault.Identity
}

func (v *g20Vault) Enroll(context.Context, vault.Identity, []byte, map[string]string) error {
	return v.enrollErr
}

func (v *g20Vault) Revoke(_ context.Context, id vault.Identity) error {
	v.mu.Lock()
	v.revokes = append(v.revokes, id)
	v.mu.Unlock()
	return v.revokeErr
}

func (v *g20Vault) revoked() []vault.Identity {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]vault.Identity(nil), v.revokes...)
}

// g20CompleteBind drives one full bind flow against v. The upstream exchange is
// real (an httptest token endpoint), so the only failure in play is the vault's.
func g20CompleteBind(t *testing.T, v vault.Service) (Binding, BindFlow, error) {
	t.Helper()
	up, challenge := fakeTokenServer(t, "up-token")
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{
		Registry: reg, Bindings: NewMemoryBindingStore(), Vault: v,
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ch, err := svc.BeginBind(ctx, "usr_1", game, sourceName, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	*challenge = u.Query().Get("code_challenge")

	return svc.CompleteBind(ctx, "usr_1", ch.ID, "code-1")
}

// TestG20BindRollsBackTheVaultWhenTheSecretWriteFails: when the vault write
// fails after the row is claimed, CompleteBind must attempt vault.Revoke so a
// secret the vault may have written cannot be left decryptable behind a
// reported failure.
func TestG20BindRollsBackTheVaultWhenTheSecretWriteFails(t *testing.T) {
	enrollErr := errors.New("vault is sealed")
	v := &g20Vault{Service: newVault(t), enrollErr: enrollErr}

	_, _, err := g20CompleteBind(t, v)
	if !errors.Is(err, enrollErr) {
		t.Fatalf("CompleteBind error = %v, want the vault write failure %v", err, enrollErr)
	}

	revoked := v.revoked()
	if len(revoked) != 1 {
		t.Fatalf("storeBindingSecret failed and the vault was rolled back %d time(s), want 1: "+
			"the failure was reported without revoking the secret it may have written (G-20)", len(revoked))
	}
	want := BindingIdentity(Binding{User: "usr_1", Game: game, Source: sourceName})
	if revoked[0] != want {
		t.Fatalf("rollback revoked %v, want the failed binding's identity %v", revoked[0], want)
	}

	// Anti-vacuity: with a vault write that succeeds, the same flow must not
	// revoke anything, so the call above is the rollback and not a read path.
	ok := &g20Vault{Service: newVault(t)}
	binding, _, err := g20CompleteBind(t, ok)
	if err != nil {
		t.Fatalf("control bind with a healthy vault write = %v", err)
	}
	if binding.Source != sourceName || binding.Version == 0 {
		t.Fatalf("control bind produced %+v", binding)
	}
	if n := len(ok.revoked()); n != 0 {
		t.Fatalf("a successful bind revoked %d secret(s); the probe is not measuring the failure path", n)
	}
}

// TestG20BindJoinsAndLogsAFailedRollback: if the rollback itself fails, the
// reported error must carry BOTH the original vault-write failure and the
// rollback failure (so a caller can see both), and the process log must record
// that a secret may remain — without naming the subject (G-21).
func TestG20BindJoinsAndLogsAFailedRollback(t *testing.T) {
	enrollErr := errors.New("vault is sealed")
	revokeErr := errors.New("vault delete refused")
	v := &g20Vault{Service: newVault(t), enrollErr: enrollErr, revokeErr: revokeErr}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	_, _, err := g20CompleteBind(t, v)
	if !errors.Is(err, enrollErr) {
		t.Fatalf("the joined error lost the vault write failure: %v", err)
	}
	if !errors.Is(err, revokeErr) {
		t.Fatalf("the rollback failure was dropped instead of joined: %v (want %v)", err, revokeErr)
	}
	if !strings.Contains(err.Error(), enrollErr.Error()) || !strings.Contains(err.Error(), revokeErr.Error()) {
		t.Fatalf("the joined error text does not carry both failures: %v", err)
	}

	logged := buf.String()
	t.Logf("captured log: %s", logged)
	if !strings.Contains(logged, "roll back") {
		t.Fatalf("a failed rollback was not logged: %q", logged)
	}
	// Anti-vacuity: the line must locate the binding by game/source, and must
	// not carry the subject (G-21).
	if !strings.Contains(logged, game) || !strings.Contains(logged, sourceName) {
		t.Errorf("the rollback log line does not locate the binding: %q", logged)
	}
	if strings.Contains(logged, "usr_1") {
		t.Errorf("the rollback log line carries the subject: %q", logged)
	}
}
