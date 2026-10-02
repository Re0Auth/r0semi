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

// zzAdmFlows stands in for the bind-flow store's purge capability, recording the
// subject it was called for.
type zzAdmFlows struct {
	purged  int
	subject string
}

func (f *zzAdmFlows) PurgeUserFlows(_ context.Context, subject string) (int, error) {
	f.subject = subject
	return f.purged, nil
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
// P9. (FIXED) A deployment with no data sources now says so on the `all` target
// too: Report.BindingsUnavailable is set, so an incident responder can tell "no
// bindings existed" from "this deployment cannot sweep bindings". The `bindings`
// target still refuses with ErrBindingsUnavailable, because it has nothing else
// to do.
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
	if rep.Bindings != nil {
		t.Errorf("KillSwitch(all) returned a bindings outcome from a deployment with no binding port: %+v", rep.Bindings)
	}
	if !rep.BindingsUnavailable {
		t.Errorf("KillSwitch(all) did not mark the binding dimension unavailable: a responder cannot tell "+
			"\"no bindings existed\" from \"this deployment cannot sweep bindings\" (report: %+v)", rep)
	}

	// The control: the dedicated target still fails loudly, since it has nothing
	// else to do.
	if _, err := svc.KillSwitch(ctx, "usr_operator", admin.Target{Bindings: true}); !errors.Is(err, admin.ErrBindingsUnavailable) {
		t.Fatalf("KillSwitch(bindings) = %v, want ErrBindingsUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// P10. (FIXED) The Kill Switch now purges in-flight bind flows: admin.Config has
// a flow port, and a `subject` sweep calls it, the same way an erasure does.
//
// A pending bind flow is a capability that outlives the binding: completing it
// creates a new binding and a new upstream token. The two paths used to disagree
// about that state — the erasure removed it, the Kill Switch left it — and they
// now agree.
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
	if _, ok := adminFields["Flows"]; !ok {
		t.Fatalf("admin.Config has no flow port, so a `subject` Kill Switch cannot purge in-flight bind flows: %v", adminFields)
	}

	// And the port is actually used: a `subject` sweep must call it with that
	// subject, and the count must reach the report.
	ctx := context.Background()
	flows := &zzAdmFlows{purged: 2}
	svc, err := admin.New(admin.Config{
		Clients:  oauth.NewMemoryClientRegistry(),
		Tokens:   &zzAdmRevoker{},
		Bindings: zzAdmBindings{outcome: admin.BindingOutcome{Total: 1, Revoked: 1}},
		Flows:    flows,
		Audit:    &zzAdmLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := svc.KillSwitch(ctx, "usr_operator", admin.Target{Subject: "usr_victim"})
	if err != nil {
		t.Fatal(err)
	}
	if flows.subject != "usr_victim" {
		t.Errorf("the flow purge ran for %q, want the swept subject", flows.subject)
	}
	if rep.FlowsPurged != 2 {
		t.Errorf("Report.FlowsPurged = %d, want 2: the count must reach the responder", rep.FlowsPurged)
	}
}

// ---------------------------------------------------------------------------
// P11. (FIXED) Erasure without a pseudonym store no longer reports the
// unlinkability step as if it had happened: the result and the audit record
// both carry `pseudonym_destroyed=false`, so a skipped step is readable instead
// of silent. Memory mode stays legal (its log keeps no keys); the composition
// root refuses a durable sink that does not expose the capability.
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
		// Pseudonyms deliberately absent, as a mis-wired deployment would be.
	})
	if err != nil {
		t.Fatalf("lifecycle.New rejected a config with no pseudonym store: %v", err)
	}
	res, err := d.DeleteAccount(ctx, user.ID, user.ID)
	if err != nil {
		t.Fatalf("DeleteAccount = %v", err)
	}
	last := logger.events[len(logger.events)-1]
	if last.Action != "account.delete" || last.Outcome != audit.OutcomeOK {
		t.Fatalf("record = %s/%s, want account.delete/ok", last.Action, last.Outcome)
	}
	if res.PseudonymDestroyed {
		t.Errorf("result says pseudonym_destroyed=true with no pseudonym store wired (result %+v)", res)
	}
	if got := last.Detail["pseudonym_destroyed"]; got != "false" {
		t.Errorf("the audit record does not say the unlinkability step was skipped: "+
			"detail[pseudonym_destroyed] = %q, want \"false\" — without this the erasure reports "+
			"success and nothing tells the operator the history is still linkable", got)
	}
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
// P13. (FIXED) The consent decision is audited, in both stores, on both exits.
//
// Approving a client's authorization request calls consent.CompleteLogin;
// denying one calls DeleteAuthRequest. Both now record `oidc.consent.approve`
// / `oidc.consent.deny` with the client id and the approved scopes, so the log
// answers "which request did this account approve, when, with which scopes" —
// and a refusal leaves a trace instead of nothing.
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
	if err := store.DecideDeviceAuthorization(ctx, "ABCD-1234", "usr_victim", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !zzAdmHasAction(logger, "oidc.device.approve") {
		t.Fatalf("control failed: the store recorded no device approval; actions %v", logger.actions())
	}

	newRequest := func() string {
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
		return ar.GetID()
	}

	// The approval: an account granting client "cli" the scopes it asked for.
	if err := store.CompleteLogin(ctx, newRequest(), "usr_victim", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	approve := zzAdmFind(logger, "oidc.consent.approve")
	if approve == nil {
		t.Fatalf("the approval recorded no audit event: the authorization decision - the moment access "+
			"is granted - is absent from the log that docs/openapi.yaml advertises as \"who did what\"; "+
			"actions %v", logger.actions())
	}
	if approve.Subject != "usr_victim" || approve.Detail["client_id"] != "cli" {
		t.Errorf("the approval event names the wrong parties: subject %q client %q",
			approve.Subject, approve.Detail["client_id"])
	}
	if approve.Detail["scopes"] != "account.id" {
		t.Errorf("the approval event does not say which scopes were granted: detail[scopes] = %q",
			approve.Detail["scopes"])
	}

	// The denial: a refusal must leave as much trace as an approval.
	if err := store.DeleteAuthRequest(ctx, newRequest()); err != nil {
		t.Fatal(err)
	}
	deny := zzAdmFind(logger, "oidc.consent.deny")
	if deny == nil {
		t.Fatalf("the denial recorded no audit event: a refused request leaves nothing at all; actions %v",
			logger.actions())
	}
	if deny.Detail["client_id"] != "cli" {
		t.Errorf("the denial event names the wrong client: %q", deny.Detail["client_id"])
	}
	if deny.Outcome != audit.OutcomeDenied {
		t.Errorf("the denial event outcome = %q, want denied", deny.Outcome)
	}
}

func zzAdmFind(l *zzAdmLogger, action string) *audit.Event {
	for i := range l.events {
		if l.events[i].Action == action {
			return &l.events[i]
		}
	}
	return nil
}

func zzAdmHasAction(l *zzAdmLogger, action string) bool {
	for _, e := range l.events {
		if e.Action == action {
			return true
		}
	}
	return false
}
