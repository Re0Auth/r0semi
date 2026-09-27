//go:build audit5

package adminprobe

// Adversarial probes for the operator plane (internal/admin), account erasure
// (internal/lifecycle) and the audit log, run against the in-memory stores.
// Prefix zzAdm on every symbol so this package can grow alongside other probes.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
	oidc "github.com/zitadel/oidc/v3/pkg/oidc"
)

// zzAdmLogger is an audit logger that keeps everything, so a probe can read back
// what an operation recorded.
type zzAdmLogger struct{ events []audit.Event }

func (l *zzAdmLogger) Record(_ context.Context, e audit.Event) error {
	l.events = append(l.events, e)
	return nil
}

func (l *zzAdmLogger) actions() []string {
	var out []string
	for _, e := range l.events {
		out = append(out, e.Action)
	}
	return out
}

// zzAdmRevoker is a token admin that revokes nothing and counts the calls.
type zzAdmRevoker struct{ calls int }

func (r *zzAdmRevoker) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) {
	r.calls++
	return 0, nil
}

// zzAdmBindings stands in for the federation service.
type zzAdmBindings struct{ outcome admin.BindingOutcome }

func (b zzAdmBindings) RevokeAllBindings(context.Context) (admin.BindingOutcome, error) {
	return b.outcome, nil
}

func (b zzAdmBindings) RevokeSubjectBindings(context.Context, string) (admin.BindingOutcome, error) {
	return b.outcome, nil
}

// ---------------------------------------------------------------------------
// P8. The documented contract for audit detail: "Non-secret context; it never
// holds a credential" (docs/openapi.yaml, AuditEntry.detail). The operator
// plane is where a credential is born — POST /v1/admin/clients returns a
// plaintext secret exactly once — so it is the place to check.
// ---------------------------------------------------------------------------
func TestZZAdmRegistrationSecretNeverReachesTheAuditDetail(t *testing.T) {
	ctx := context.Background()
	clients := oauth.NewMemoryClientRegistry()
	logger := &zzAdmLogger{}
	svc, err := admin.New(admin.Config{
		Clients: clients, Tokens: &zzAdmRevoker{}, Audit: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	reg, err := svc.Register(ctx, "usr_operator", admin.RegisterRequest{
		Name: "Confidential App", Type: oauth.ClientConfidential,
		RedirectURIs:  []string{"https://app.example/cb"},
		AllowedScopes: []oauth.Scope{oauth.ScopeAccountID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Secret == "" {
		t.Fatal("no secret was issued; the probe would prove nothing")
	}

	// Non-vacuity: the operator id IS recorded, on purpose (the documented
	// exception), so a clean credential check is not the result of an empty log.
	foundActor := false
	for _, e := range logger.events {
		if e.Detail["actor"] == "usr_operator" {
			foundActor = true
		}
	}
	if !foundActor {
		t.Fatalf("no admin.* event carries detail[actor]; the probe is not reading the log it thinks: %v",
			logger.actions())
	}

	for _, e := range logger.events {
		if strings.Contains(e.Subject, reg.Secret) {
			t.Errorf("%s: event subject carries the client secret", e.Action)
		}
		for k, v := range e.Detail {
			if strings.Contains(v, reg.Secret) {
				t.Errorf("%s: detail[%s] carries the client secret", e.Action, k)
			}
		}
	}

	// Rotation is the second place a secret is minted.
	secret, err := svc.RotateClientSecret(ctx, "usr_operator", reg.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range logger.events {
		for k, v := range e.Detail {
			if strings.Contains(v, secret) {
				t.Errorf("%s: detail[%s] carries the rotated client secret", e.Action, k)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// P9. A deployment with no data sources answers the Kill Switch's `all` target
// with a report that says nothing about bindings: Report.Bindings stays nil, and
// `bindings` is omitted from the JSON. An incident responder cannot tell "no
// bindings existed" from "this deployment cannot sweep bindings" — while the
// dedicated `bindings` target is refused with ErrBindingsUnavailable, precisely
// so that a hollow zero is never returned. The two targets disagree about the
// same fact.
// ---------------------------------------------------------------------------
func TestZZAdmKillSwitchAllIsSilentAboutBindings(t *testing.T) {
	ctx := context.Background()
	svc, err := admin.New(admin.Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: &zzAdmRevoker{},
		Audit: &zzAdmLogger{}, // Bindings deliberately nil: a deployment with no sources
	})
	if err != nil {
		t.Fatal(err)
	}

	rep, err := svc.KillSwitch(ctx, "usr_operator", admin.Target{All: true})
	if err != nil {
		t.Fatalf("KillSwitch(all) = %v", err)
	}
	if rep.Bindings == nil {
		t.Errorf("KillSwitch(all) returned a report with no bindings outcome: the answer to "+
			"\"were the data-source bindings cut?\" is missing entirely, while the `bindings` "+
			"target refuses with ErrBindingsUnavailable so that it never answers a hollow zero "+
			"(report: %+v)", rep)
	}

	// The control that shows the asymmetry.
	if _, err := svc.KillSwitch(ctx, "usr_operator", admin.Target{Bindings: true}); !errors.Is(err, admin.ErrBindingsUnavailable) {
		t.Fatalf("KillSwitch(bindings) = %v, want ErrBindingsUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// P10. The erasure purges in-flight bind flows; the Kill Switch has no way to.
//
// lifecycle.Config has a Flows port and cmd/re0auth wires it
// (Flows: store.bindFlows), because a pending bind flow is a capability that
// outlives the binding: completing it creates a new binding and a new upstream
// token. admin.Config has no such port, so a `subject`-scoped Kill Switch leaves
// the flow in place. Whether that is exploitable depends on the deployment being
// unable to revoke the account's sessions (which is what kills the browser
// handle the flow is bound to) — the same memory-mode boundary the docs already
// record — so this is filed as a hypothesis with the port asymmetry as evidence.
// ---------------------------------------------------------------------------
func TestZZAdmKillSwitchHasNoFlowPurgerWhileErasureDoes(t *testing.T) {
	fields := func(v any) map[string]string {
		out := map[string]string{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			out[f.Name] = f.Type.String()
		}
		return out
	}

	lifecycleFields := fields(lifecycle.Config{})
	adminFields := fields(admin.Config{})

	if _, ok := lifecycleFields["Flows"]; !ok {
		t.Fatalf("lifecycle.Config has no Flows port; the premise of this probe changed: %v", lifecycleFields)
	}
	mentionsFlows := false
	for name, typ := range adminFields {
		if strings.Contains(strings.ToLower(name+typ), "flow") {
			mentionsFlows = true
		}
	}
	if !mentionsFlows {
		t.Errorf("admin.Config cannot purge in-flight bind flows (fields: %v), while "+
			"lifecycle.Config can: a `subject`-scoped Kill Switch cuts the account's tokens, "+
			"sessions and bindings and leaves a pending bind flow able to recreate a binding "+
			"afterwards. The erasure path treats the same flow as needing removal.",
			adminFields)
	}
}

// ---------------------------------------------------------------------------
// P11. Erasure without a pseudonym store reports success.
//
// lifecycle.New accepts a Config with Pseudonyms nil, and DeleteAccount then
// returns a nil error. In a durable deployment that is the difference between
// "the account's audit history is unlinkable" and "it is not", and nothing here
// can tell the two apart — the step that delivers the promise is optional and
// unasserted.
// ---------------------------------------------------------------------------
func TestZZAdmErasureWithoutAPseudonymStoreReportsSuccess(t *testing.T) {
	ctx := context.Background()
	accounts := account.NewMemoryStore()
	user, _, err := accounts.CreateWithIdentity(ctx, idp.Identity{Provider: idp.GitHub, Subject: "erase-me"})
	if err != nil {
		t.Fatal(err)
	}

	logger := &zzAdmLogger{}
	d, err := lifecycle.New(lifecycle.Config{
		Accounts: accounts,
		Tokens:   &zzAdmRevoker{},
		Vault:    vault.NewMemoryRepo(),
		Audit:    logger,
		// Pseudonyms deliberately absent, as a mis-wired durable deployment would be.
	})
	if err != nil {
		t.Fatalf("lifecycle.New rejected a config with no pseudonym store: %v", err)
	}
	res, err := d.DeleteAccount(ctx, user.ID, user.ID)
	if err != nil {
		t.Fatalf("DeleteAccount = %v", err)
	}
	if len(logger.events) == 0 || logger.events[len(logger.events)-1].Action != "account.delete" {
		t.Fatalf("no account.delete record: %v", logger.actions())
	}
	if logger.events[len(logger.events)-1].Outcome != audit.OutcomeOK {
		t.Fatalf("outcome = %q", logger.events[len(logger.events)-1].Outcome)
	}
	t.Logf("erasure reported OK with no pseudonym key destroyed (result %+v)", res)

	// The gap this leaves: nothing failed, so nothing tells the operator that the
	// erased account's audit history is still linkable.
	t.Errorf("a durable deployment whose audit sink holds pseudonym keys can erase an account "+
		"and report success without destroying the key; neither lifecycle.New nor the result "+
		"records that the unlinkability step was skipped (result %+v)", res)
}

// ---------------------------------------------------------------------------
// P12. The account id and the operator id in one place: the admin plane records
// the operator as an account id on purpose (documented), and everything else
// goes through the sink's pseudonymisation. What this probe pins is that no
// *other* account id leaks into detail — the property that makes the documented
// exception an exception rather than the rule.
// ---------------------------------------------------------------------------
func TestZZAdmOnlyTheOperatorIdAppearsInAdminDetail(t *testing.T) {
	ctx := context.Background()
	clients := oauth.NewMemoryClientRegistry()
	logger := &zzAdmLogger{}
	svc, err := admin.New(admin.Config{
		Clients: clients, Tokens: &zzAdmRevoker{},
		Bindings: zzAdmBindings{outcome: admin.BindingOutcome{Total: 1, Revoked: 1}},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	const victim = "usr_victim"
	if _, err := svc.KillSwitch(ctx, "usr_operator", admin.Target{Subject: victim}); err != nil {
		t.Fatal(err)
	}
	for _, e := range logger.events {
		for k, v := range e.Detail {
			if v == victim {
				t.Errorf("%s: detail[%s] carries the subject account id %q, which the sink cannot "+
					"pseudonymise and which survives the erasure of that account", e.Action, k, victim)
			}
		}
		if e.Subject != victim {
			t.Errorf("%s: subject = %q, want the account the event is about", e.Action, e.Subject)
		}
	}
}

// zzAdmTokenIssuanceIsAudited is deliberately not asserted here: the OP store's
// record() call sites are enumerated in the report instead, because the store
// needs a signer and a client registry the admin package has no business
// building. See findings AUD-3/AUD-4.

// ---------------------------------------------------------------------------
// P13. The consent decision leaves no audit record.
//
// Approving a client's authorization request calls consent.CompleteLogin
// (internal/oidchttp/oidchttp.go:1288), and denying one calls
// DeleteAuthRequest (:1309). Neither store's record() helper is on either path:
// the complete set of audited OP events is oidc.token, oidc.revoke,
// oidc.grant.revoke, oidc.device.approve and oidc.device.deny. The retired
// hand-rolled engine audits its equivalent action (oauth.authorize,
// oauth/as.go:156) but is not the engine the composition root wires, so on the
// production path the log answers "which client got a token for this account"
// and not "which request this account approved, when, with which scopes" - and
// a refused request leaves no trace at all.
// ---------------------------------------------------------------------------
func TestZZAdmConsentDecisionIsNotAudited(t *testing.T) {
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	logger := &zzAdmLogger{}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  oauth.NewMemoryClientRegistry(),
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe", key),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Control: this store does audit, so a missing consent event is not the
	// result of an unwired sink.
	if err := store.StoreDeviceAuthorization(ctx, "cli", "probe-device", "ABCD-1234",
		time.Now().Add(time.Hour), []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveDevice(ctx, "ABCD-1234", "usr_victim", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if !zzAdmHasAction(logger, "oidc.device.approve") {
		t.Fatalf("control failed: the store recorded no device approval; actions %v", logger.actions())
	}

	// The probe: a consent decision.
	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	before := len(logger.events)
	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_victim", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	if len(logger.events) != before {
		t.Fatalf("the consent decision now records %v; this probe can be deleted",
			logger.actions()[before:])
	}
	t.Errorf("an account approving client %q for scopes %v recorded no audit event: the "+
		"authorization decision - the moment access is granted - is absent from the log that "+
		"docs/openapi.yaml advertises as \"who did what\", and a denied request leaves nothing "+
		"at all (`DenyAuthorization` only deletes the request)", "cli", []string{"account.id"})
}

func zzAdmHasAction(l *zzAdmLogger, action string) bool {
	for _, e := range l.events {
		if e.Action == action {
			return true
		}
	}
	return false
}
