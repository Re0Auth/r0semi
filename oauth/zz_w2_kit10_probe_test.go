package oauth

import (
	"context"
	"errors"
	"testing"
)

// W2 KIT-10 probe: a deleted client must not keep a usable credential.
//
// Before the fix, MemoryClientRegistry.Delete only removed the client row. The
// service reported the client as unknown at every protocol entrance, so the
// "the client is deleted" claim looked honoured — but the access token it had
// already obtained was still a live row (introspection stayed Active) and an
// unspent authorization code could still mint a fresh pair.
//
// The three assertions the finding calls for are all here:
//
//	(a) the token cannot be introspected after the delete,
//	(b) no token row and no authorization survives it,
//	(c) the control: deleting a client that holds nothing still succeeds.
//
// The registry is wired by NewService — the same composition production uses for
// the in-memory engine — so this probe fails again the moment that wiring (or
// Delete's revocation) is removed.
func TestW2KIT10DeleteClientRevokesItsTokens(t *testing.T) {
	ctx := context.Background()
	const (
		clientID = "cli_w2_kit10"
		emptyID  = "cli_w2_kit10_empty"
		subject  = "usr_w2_kit10"
		verifier = "verifier-verifier-verifier-verifier"
		redirect = "https://app.example/cb"
	)

	svc, clients, tokens, _, _ := newTestAS(t)
	registerClient(t, clients, clientID, ClientPublic, "", []Scope{ScopeAccountID})

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: clientID, RedirectURI: redirect, Subject: subject,
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: clientID, Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Vacuity: the credential is live and visible before the delete. Without this
	// a delete that never ran, or a token that was never issued, would pass the
	// post-conditions below for the wrong reason.
	before, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Active {
		t.Fatalf("vacuity: the freshly issued access token is already inactive: %+v", before)
	}
	rows, err := tokens.ListBySubject(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("vacuity: the exchange left no token rows for the subject")
	}

	// (c) The control: a client with no tokens of its own is still deletable, and
	// the delete is idempotent.
	registerClient(t, clients, emptyID, ClientPublic, "", []Scope{ScopeAccountID})
	if err := clients.Delete(ctx, emptyID); err != nil {
		t.Fatalf("deleting a client that holds no tokens failed: %v", err)
	}
	if err := clients.Delete(ctx, emptyID); err != nil {
		t.Fatalf("deleting an absent client failed on retry: %v", err)
	}
	if _, err := clients.Get(ctx, emptyID); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("deleted client still resolves: %v", err)
	}

	// The delete under test.
	if err := clients.Delete(ctx, clientID); err != nil {
		t.Fatal(err)
	}

	// (a) The token is no longer introspectable.
	after, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if after.Active {
		t.Errorf("after ClientAdmin.Delete the access token is still Active "+
			"(subject=%s client=%s)", after.Subject, after.ClientID)
	}

	// (b) No token row and no authorization survives. ListBySubject is the grants
	// view's own read: an entry here is exactly the "they are still shown as
	// holding access" record the finding is about.
	rows, err = tokens.ListBySubject(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("ClientAdmin.Delete left %d token rows for the subject: %+v", len(rows), rows)
	}
	if _, err := tokens.GetRefresh(ctx, tok.RefreshToken); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("the refresh token survived ClientAdmin.Delete: err=%v", err)
	}
}
