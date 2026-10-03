package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/oauth"
)

// recorder appends the name of each store it is asked to clear, so a test can
// assert the ORDER as well as the fact. Order is the part of this package that is
// easy to get wrong and impossible to see from the counts alone.
type recorder struct{ calls *[]string }

func (r recorder) note(name string) { *r.calls = append(*r.calls, name) }

type fakeVault struct {
	recorder
	n   int
	err error
}

func (f fakeVault) DeleteSubject(context.Context, string) (int, error) {
	f.note("vault")
	return f.n, f.err
}

type fakeTokens struct {
	recorder
	n   int
	err error
}

func (f fakeTokens) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) {
	f.note("tokens")
	return f.n, f.err
}

type fakeSessions struct {
	recorder
	n   int64
	err error
}

func (f fakeSessions) RevokeSubjectSessions(context.Context, string) (int64, error) {
	f.note("sessions")
	return f.n, f.err
}

type fakeFlows struct {
	recorder
	n   int
	err error
}

func (f fakeFlows) PurgeUserFlows(context.Context, account.UserID) (int, error) {
	f.note("flows")
	return f.n, f.err
}

type fakeOIDC struct {
	recorder
	n   int
	err error
}

func (f fakeOIDC) PurgeSubject(context.Context, string) (int, error) {
	f.note("oidc")
	return f.n, f.err
}

type fakeAccounts struct {
	recorder
	err error
}

func (f fakeAccounts) DeleteUser(context.Context, account.UserID) error {
	f.note("accounts")
	return f.err
}

type fakeBindings struct {
	recorder
	outcome BindingOutcome
	err     error
}

func (f fakeBindings) RevokeUserBindings(context.Context, account.UserID) (BindingOutcome, error) {
	f.note("bindings")
	return f.outcome, f.err
}

// harness wires every fake to one shared call log.
func harness(t *testing.T) (*Deleter, *[]string, *audit.MemoryLogger) {
	t.Helper()
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r(), n: 3},
		Vault:    fakeVault{recorder: r(), n: 2},
		Bindings: fakeBindings{recorder: r(), outcome: BindingOutcome{Total: 2, Revoked: 2}},
		Sessions: fakeSessions{recorder: r(), n: 1},
		OIDC:     fakeOIDC{recorder: r(), n: 4},
		Flows:    fakeFlows{recorder: r(), n: 5},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, &calls, logger
}

// TestDeleteAccountClearsEveryStoreInUpstreamFirstOrder pins the order. Bindings
// must go first because each one is also an upstream call that needs the local
// credential still present; the account row must go last, or the identity lookups
// a later step might need would already be gone.
func TestDeleteAccountClearsEveryStoreInUpstreamFirstOrder(t *testing.T) {
	d, calls, _ := harness(t)

	result, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	want := []string{"bindings", "vault", "tokens", "sessions", "flows", "oidc", "accounts"}
	if got := strings.Join(*calls, ","); got != strings.Join(want, ",") {
		t.Errorf("clear order = %v, want %v", got, want)
	}
	if *calls == nil || (*calls)[len(*calls)-1] != "accounts" {
		t.Error("the account row was not the last thing removed")
	}

	if result.Vault != 2 || result.Tokens != 3 || result.Sessions != 1 || result.Flows != 5 || result.OIDC != 4 {
		t.Errorf("counts not carried through: %+v", result)
	}
	if result.Bindings.Revoked != 2 {
		t.Errorf("binding outcome not carried through: %+v", result.Bindings)
	}
	if !result.SessionScoped {
		t.Error("SessionScoped should be true when a session revoker is wired")
	}
}

// TestDeleteAccountAuditsTheResult: the audit row is the only durable proof the
// erasure happened, and it must survive the account row it describes.
//
// It must also not name the account: Subject is pseudonymised by the durable sink,
// but a raw `usr_…` in a detail value would survive that AND the pseudonym-key
// destruction, leaving the erased person identifiable in the one row guaranteed to
// be about them.
func TestDeleteAccountAuditsTheResult(t *testing.T) {
	d, _, logger := harness(t)

	if _, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target"); err != nil {
		t.Fatal(err)
	}

	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Action != "account.delete" || e.Subject != "usr_target" || e.Outcome != audit.OutcomeOK {
		t.Errorf("unexpected event: %+v", e)
	}
	for k, v := range e.Detail {
		if v == "usr_actor" || v == "usr_target" {
			t.Errorf("detail[%q] = %q names the account being erased", k, v)
		}
	}
	// An operator-initiated erasure is distinguishable without naming an id.
	if e.Detail["self"] != "false" {
		t.Errorf("self = %q, want false when the actor is a different account", e.Detail["self"])
	}
}

// TestDeleteAccountSelfErasureIsMarkedAndStillAnonymous: the shape the HTTP
// endpoint produces — actor and subject are the same — must be marked as such
// without writing the id anywhere, since the id is exactly what the erasure is
// supposed to take away.
func TestDeleteAccountSelfErasureIsMarkedAndStillAnonymous(t *testing.T) {
	d, _, logger := harness(t)

	if _, err := d.DeleteAccount(context.Background(), "usr_target", "usr_target"); err != nil {
		t.Fatal(err)
	}

	e := logger.Events()[0]
	if e.Detail["self"] != "true" {
		t.Errorf("self = %q, want true", e.Detail["self"])
	}
	for k, v := range e.Detail {
		if v == "usr_target" {
			t.Errorf("detail[%q] = %q: a self-erasure leaked the account id", k, v)
		}
	}
}

// TestDeleteAccountStopsAtTheFailingStep: a mid-way failure must not continue to
// the next store. The stores are idempotent, so stopping and retrying is the
// correct recovery, and continuing would make the failure harder to reason about.
func TestDeleteAccountStopsAtTheFailingStep(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	sentinel := errors.New("vault unavailable")
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r()},
		Vault:    fakeVault{recorder: r(), err: sentinel},
		Bindings: fakeBindings{recorder: r()},
		Sessions: fakeSessions{recorder: r()},
		OIDC:     fakeOIDC{recorder: r()},
		Flows:    fakeFlows{recorder: r()},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target"); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the vault's error", err)
	}
	if got := strings.Join(calls, ","); got != "bindings,vault" {
		t.Errorf("calls = %v, want it to stop right after the failure", got)
	}

	events := logger.Events()
	if len(events) != 1 || events[0].Outcome != audit.OutcomeError {
		t.Fatalf("want one error event, got %+v", events)
	}
	if events[0].Detail["failed_at"] != "vault" {
		t.Errorf("failed_at = %q, want vault", events[0].Detail["failed_at"])
	}
}

// TestDeleteAccountStopsWhenABindingRemovalFailed: a binding sweep that returns
// no error can still have failed to remove a binding locally. The federation
// service folds that into the summary's Failed count rather than erroring, so
// DeleteAccount has to read the count itself. Treating it as success would erase
// the account and record outcome=ok while a binding — and the credential it
// holds — is still there.
func TestDeleteAccountStopsWhenABindingRemovalFailed(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r()},
		Vault:    fakeVault{recorder: r()},
		Bindings: fakeBindings{recorder: r(), outcome: BindingOutcome{Total: 2, Revoked: 1, Failed: 1}},
		Sessions: fakeSessions{recorder: r()},
		OIDC:     fakeOIDC{recorder: r()},
		Flows:    fakeFlows{recorder: r()},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err == nil {
		t.Fatalf("a binding that could not be removed locally must fail the erasure (result %+v)", res)
	}
	if got := strings.Join(calls, ","); got != "bindings" {
		t.Errorf("calls = %v, want it to stop at the bindings step", got)
	}

	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one", events)
	}
	if events[0].Outcome != audit.OutcomeError {
		t.Errorf("outcome = %q, want %q", events[0].Outcome, audit.OutcomeError)
	}
	if got := events[0].Detail["failed_at"]; got != "bindings" {
		t.Errorf("failed_at = %q, want bindings", got)
	}
	if got := events[0].Detail["bindings_failed"]; got != "1" {
		t.Errorf("bindings_failed = %q, want \"1\"", got)
	}
}

// an unprovable erasure is refused. The account row is already gone, but DeleteUser
// is idempotent, so a retry produces the record.
func TestDeleteAccountFailsWhenTheRecordCannotBeWritten(t *testing.T) {
	d, _, _ := harness(t)
	d.cfg.Audit = failingLogger{}

	if _, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target"); err == nil {
		t.Fatal("an erasure with no audit record should fail")
	}
}

// TestDeleteAccountWithoutASessionRevokerSaysSo: memory mode cannot enumerate one
// account's sessions. Zero cleared and "could not clear any" must not look alike.
func TestDeleteAccountWithoutASessionRevokerSaysSo(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r()},
		Vault:    fakeVault{recorder: r()},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionScoped {
		t.Error("SessionScoped must be false when there is no session revoker")
	}
	if events := logger.Events(); len(events) != 1 || events[0].Detail["session_scoped"] != "false" {
		t.Errorf("the false must reach the audit detail: %+v", logger.Events())
	}
}

func TestDeleteAccountRejectsAnEmptySubject(t *testing.T) {
	d, calls, _ := harness(t)
	if _, err := d.DeleteAccount(context.Background(), "usr_actor", ""); err == nil {
		t.Fatal("an empty subject should be rejected")
	}
	if len(*calls) != 0 {
		t.Errorf("nothing should have been cleared, got %v", *calls)
	}
}

func TestNewRequiresTheMandatoryPorts(t *testing.T) {
	base := func() Config {
		return Config{
			Accounts: fakeAccounts{},
			Tokens:   fakeTokens{},
			Vault:    fakeVault{},
			Audit:    audit.NewMemoryLogger(),
		}
	}
	for name, mutate := range map[string]func(*Config){
		"Accounts": func(c *Config) { c.Accounts = nil },
		"Tokens":   func(c *Config) { c.Tokens = nil },
		"Vault":    func(c *Config) { c.Vault = nil },
		"Audit":    func(c *Config) { c.Audit = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Errorf("New should reject a missing %s", name)
			}
		})
	}
}

// failingLogger makes Record fail, standing in for an audit sink that is down.
type failingLogger struct{}

func (failingLogger) Record(context.Context, audit.Event) error {
	return errors.New("audit sink unavailable")
}

// flakyLogger writes records until failAt, then fails every subsequent one. It
// stands in for a sink that is healthy while the pre-Destroy record is written and
// down by the time fail() tries to append the corrective one — the only window in
// which the second write's error used to be discarded (audit round 9, S08-3).
type flakyLogger struct {
	logged  *audit.MemoryLogger
	failErr error
	failAt  int
	calls   int
}

func (l *flakyLogger) Record(ctx context.Context, e audit.Event) error {
	l.calls++
	if l.calls >= l.failAt {
		return l.failErr
	}
	return l.logged.Record(ctx, e)
}

// TestDeleteAccountSurfacesARecordFailureOnTheFailurePath: fail()'s record is the
// only thing that can contradict the outcome=ok record written before Destroy, so
// losing THAT write must not be silent. The caller already has the destroy failure
// to act on; when the corrective record also fails, both must be visible, and the
// original cause must stay reachable through errors.Is.
func TestDeleteAccountSurfacesARecordFailureOnTheFailurePath(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	destroyErr := errors.New("pseudonym store unavailable")
	recordErr := errors.New("audit sink unavailable")
	logged := audit.NewMemoryLogger()
	logger := &flakyLogger{logged: logged, failErr: recordErr, failAt: 2}
	d, err := New(Config{
		Accounts:   fakeAccounts{recorder: r()},
		Tokens:     fakeTokens{recorder: r()},
		Vault:      fakeVault{recorder: r()},
		Pseudonyms: &fakePseudonyms{err: destroyErr},
		Audit:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err == nil {
		t.Fatal("a failed destroy must fail the erasure")
	}
	if !errors.Is(err, destroyErr) {
		t.Errorf("err = %v, want the destroy failure still reachable", err)
	}
	if !errors.Is(err, recordErr) {
		t.Errorf("err = %v, want the failure to record the failure surfaced too", err)
	}
	if !strings.Contains(err.Error(), "could not record the failure") {
		t.Errorf("the record failure is not named: %v", err)
	}
	// The pre-Destroy record was written; the corrective write is the one that
	// failed. That is the state the caller must be able to see.
	if got := len(logged.Events()); got != 1 {
		t.Errorf("durable records = %d, want the pre-Destroy one only", got)
	}
}

// fakePseudonyms records that it was asked to destroy a key, and — importantly —
// what had been written to the audit log by then.
type fakePseudonyms struct {
	destroyed []string
	err       error
	// eventsAtDestroy is the audit log's length when Destroy was called. The
	// ordering assertion needs it: the record of the deletion must already exist,
	// because a sink that pseudonymises would otherwise mint a fresh key in order
	// to write it, re-creating the link the step exists to remove.
	eventsAtDestroy int
	logger          *audit.MemoryLogger
}

func (f *fakePseudonyms) Destroy(_ context.Context, subject string) error {
	f.destroyed = append(f.destroyed, subject)
	if f.logger != nil {
		f.eventsAtDestroy = len(f.logger.Events())
	}
	return f.err
}

// TestDeleteAccountDestroysThePseudonymKeyLast pins the ordering that makes the
// erasure's own audit record possible: the record is written while the key still
// exists, and the key is destroyed only afterwards.
func TestDeleteAccountDestroysThePseudonymKeyLast(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	pseudo := &fakePseudonyms{logger: logger}
	d, err := New(Config{
		Accounts:   fakeAccounts{recorder: r()},
		Tokens:     fakeTokens{recorder: r()},
		Vault:      fakeVault{recorder: r()},
		Pseudonyms: pseudo,
		Audit:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target"); err != nil {
		t.Fatal(err)
	}

	if len(pseudo.destroyed) != 1 || pseudo.destroyed[0] != "usr_target" {
		t.Fatalf("destroyed = %v, want the erased subject", pseudo.destroyed)
	}
	if pseudo.eventsAtDestroy != 1 {
		t.Fatalf("at destroy time the audit log had %d events, want the deletion record already written",
			pseudo.eventsAtDestroy)
	}
	// And the record survives the key's destruction: it is not withdrawn.
	if events := logger.Events(); len(events) != 1 || events[0].Subject != "usr_target" {
		t.Fatalf("audit trail after destroy = %+v", events)
	}
}

// TestDeleteAccountReportsAFailedPseudonymDestroy: the account is gone either way,
// but a failure to unlink its history must be visible rather than swallowed — the
// caller can retry, and every step is idempotent.
func TestDeleteAccountReportsAFailedPseudonymDestroy(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	sentinel := errors.New("pseudonym store unavailable")
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts:   fakeAccounts{recorder: r()},
		Tokens:     fakeTokens{recorder: r()},
		Vault:      fakeVault{recorder: r()},
		Pseudonyms: &fakePseudonyms{err: sentinel},
		Audit:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the destroy failure surfaced", err)
	}
	if !strings.Contains(err.Error(), "still linkable") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}

	// The failure must also be readable in the log: the pre-Destroy record stays
	// (it cannot be rewritten), and a second, truthful error record names the step
	// that stopped the run.
	events := logger.Events()
	if len(events) != 2 {
		t.Fatalf("events = %+v, want the pre-Destroy record plus the failure record", events)
	}
	last := events[len(events)-1]
	if last.Outcome != audit.OutcomeError {
		t.Errorf("last record outcome = %q, want %q", last.Outcome, audit.OutcomeError)
	}
	if got := last.Detail["failed_at"]; got != "pseudonym" {
		t.Errorf("failed_at = %q, want pseudonym", got)
	}
	if got := last.Detail["pseudonym"]; got != "failed" {
		t.Errorf("detail[pseudonym] = %q, want \"failed\"", got)
	}
	if got := last.Detail["pseudonym_destroyed"]; got != "false" {
		t.Errorf("detail[pseudonym_destroyed] = %q, want \"false\"", got)
	}
}

// TestDeleteAccountWithoutPseudonymsStillWorks: a deployment whose audit log does
// not pseudonymise leaves the port nil, and that must not be an error.
func TestDeleteAccountWithoutPseudonymsStillWorks(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r()},
		Vault:    fakeVault{recorder: r()},
		Audit:    audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target"); err != nil {
		t.Fatalf("a nil Pseudonyms port should be fine: %v", err)
	}
}

// TestDeleteAccountWithoutPseudonymsIsNotReportedAsDestroyed: a skipped
// unlinkability step must be readable in the result and the audit record, not
// folded into a success that says nothing about it.
func TestDeleteAccountWithoutPseudonymsIsNotReportedAsDestroyed(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts: fakeAccounts{recorder: r()},
		Tokens:   fakeTokens{recorder: r()},
		Vault:    fakeVault{recorder: r()},
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err != nil {
		t.Fatal(err)
	}
	if res.PseudonymDestroyed {
		t.Fatalf("pseudonym_destroyed = true with no pseudonym store wired (result %+v)", res)
	}
	events := logger.Events()
	if len(events) != 1 || events[0].Action != "account.delete" {
		t.Fatalf("events = %+v", events)
	}
	if got := events[0].Detail["pseudonym_destroyed"]; got != "false" {
		t.Fatalf("detail[pseudonym_destroyed] = %q, want \"false\"", got)
	}
	// "false" alone cannot tell a skipped step from one that has not run yet, so
	// the record carries which it is.
	if got := events[0].Detail["pseudonym"]; got != "not_configured" {
		t.Fatalf("detail[pseudonym] = %q, want \"not_configured\"", got)
	}
}

// TestDeleteAccountWithPseudonymsReportsDestroyed: with the port wired and the
// destruction succeeding, the RETURNED RESULT says destroyed — but the record
// cannot, because it is written before Destroy runs (the ordering Destroy itself
// depends on; writing a record afterwards would make the sink mint a fresh subject
// key). So the single record says pseudonym=pending and pseudonym_destroyed=false,
// and success is read as "pending with no later error record for this subject".
func TestDeleteAccountWithPseudonymsReportsDestroyed(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts:   fakeAccounts{recorder: r()},
		Tokens:     fakeTokens{recorder: r()},
		Vault:      fakeVault{recorder: r()},
		Pseudonyms: &fakePseudonyms{},
		Audit:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.DeleteAccount(context.Background(), "usr_actor", "usr_target")
	if err != nil {
		t.Fatal(err)
	}
	if !res.PseudonymDestroyed {
		t.Fatalf("pseudonym_destroyed = false although the destroy ran (result %+v)", res)
	}
	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want the pre-Destroy record only (no post-Destroy record, "+
			"because writing one would re-mint the subject key)", events)
	}
	if got := events[0].Detail["pseudonym_destroyed"]; got != "false" {
		t.Fatalf("detail[pseudonym_destroyed] = %q: the record is written before Destroy and "+
			"must not claim it already happened", got)
	}
	if got := events[0].Detail["pseudonym"]; got != "pending" {
		t.Fatalf("detail[pseudonym] = %q, want \"pending\"", got)
	}
}
