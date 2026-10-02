package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// w1FailRevoker is a token store whose bulk revocation fails after reporting how
// many rows it had already removed.
type w1FailRevoker struct {
	removed int
	err     error
}

func (r w1FailRevoker) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) {
	return r.removed, r.err
}

// w1FailSessions is a session revoker that always fails.
type w1FailSessions struct{ err error }

func (s w1FailSessions) RevokeAllSessions(context.Context) (int64, error) { return 0, s.err }
func (s w1FailSessions) RevokeSubjectSessions(context.Context, string) (int64, error) {
	return 0, s.err
}

// TestW1Z10_5TokenStepFailureCarriesTheReport pins the typed error at the token
// step (admin.go:361). The sweep must report the counts it already applied, and
// errors.Is must still see the underlying failure through the wrapper.
func TestW1Z10_5TokenStepFailureCarriesTheReport(t *testing.T) {
	cause := errors.New("token store down")
	svc, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(),
		Tokens:  w1FailRevoker{removed: 7, err: cause},
		Audit:   audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	rep, err := svc.KillSwitch(context.Background(), "usr_admin", Target{All: true})
	if err == nil {
		t.Fatal("KillSwitch returned nil although the token store failed")
	}
	var pe *PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %T (%v), want *PartialError", err, err)
	}
	if pe.Step != "tokens" {
		t.Errorf("Step = %q, want tokens", pe.Step)
	}
	if pe.Report.TokensRevoked != 7 {
		t.Errorf("Report.TokensRevoked = %d, want 7 (already removed)", pe.Report.TokensRevoked)
	}
	if rep.TokensRevoked != 7 {
		t.Errorf("returned Report.TokensRevoked = %d, want 7", rep.TokensRevoked)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is lost the underlying failure through the wrapper: %v", err)
	}
}

// TestW1Z10_5SessionStepFailureCarriesTheReport pins the second named landing
// (admin.go:388): a failure after the token purge completed must carry that
// completed count.
func TestW1Z10_5SessionStepFailureCarriesTheReport(t *testing.T) {
	cause := errors.New("session store down")
	svc, err := New(Config{
		Clients:  oauth.NewMemoryClientRegistry(),
		Tokens:   oauth.NewMemoryStore(),
		Sessions: w1FailSessions{err: cause},
		Audit:    audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.KillSwitch(context.Background(), "usr_admin", Target{Subject: "usr_1"})
	var pe *PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %T (%v), want *PartialError", err, err)
	}
	if pe.Step != "sessions" {
		t.Errorf("Step = %q, want sessions", pe.Step)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is lost the underlying failure through the wrapper: %v", err)
	}
}
