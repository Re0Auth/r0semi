package oidchttp

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/authorization"
)

// w2NewAuthRequest registers a pending request straight in the real store, the way
// the OP's authorize endpoint would.
func w2NewAuthRequest(t *testing.T, f fixture, clientID string) op.AuthRequest {
	t.Helper()
	ar, err := f.store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://client.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
		State:        "w2-state-1234567890",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return ar
}

// TestW2ConsentSeamReturnsTheExpiredSentinel drives the three interaction methods
// through the real oidchttp handler on the real memory store. S04-7 splits the
// consent screen's answers in two, and only the sentinel makes that possible: the
// HTTP layer has no other way to learn that the engine merely does not hold the
// request. Before the store carried it, all three returned a bare error and every
// real expired link was classified as a server fault.
func TestW2ConsentSeamReturnsTheExpiredSentinel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	calls := []struct {
		name string
		call func(id string) error
	}{
		{"DescribeAuthorization", func(id string) error {
			_, err := f.handler.DescribeAuthorization(ctx, id)
			return err
		}},
		{"ApproveAuthorization", func(id string) error {
			_, err := f.handler.ApproveAuthorization(ctx, id, "usr_1", nil, nil)
			return err
		}},
		{"DenyAuthorization", func(id string) error {
			_, err := f.handler.DenyAuthorization(ctx, id)
			return err
		}},
	}
	for _, tc := range calls {
		if err := tc.call("no-such-request"); !errors.Is(err, authorization.ErrRequestExpired) {
			t.Errorf("%s(unknown) = %v, want it to wrap authorization.ErrRequestExpired (S04-7)", tc.name, err)
		}
	}

	// Control 1: a live request is not the sentinel.
	live := w2NewAuthRequest(t, f, f.webID)
	if _, err := f.handler.DescribeAuthorization(ctx, live.GetID()); err != nil {
		t.Fatalf("DescribeAuthorization(live) = %v, want nil", err)
	}

	// Control 2: an engine fault stays itself. The client registry cannot answer
	// for this request's client, and that must not be relabelled as an expired
	// link — that mislabelling is the whole defect S04-7 names.
	ghost := w2NewAuthRequest(t, f, "w2-ghost-client")
	if _, err := f.handler.DescribeAuthorization(ctx, ghost.GetID()); err == nil {
		t.Fatal("DescribeAuthorization of a request whose client is unknown returned nil")
	} else if errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("an engine fault was reported as an expired request: %v", err)
	}

	// A consumed request is gone too: deny discards it, and the next describe is
	// the caller's situation again.
	denied := w2NewAuthRequest(t, f, f.webID)
	if _, err := f.handler.DenyAuthorization(ctx, denied.GetID()); err != nil {
		t.Fatalf("DenyAuthorization(live) = %v", err)
	}
	if _, err := f.handler.DescribeAuthorization(ctx, denied.GetID()); !errors.Is(err, authorization.ErrRequestExpired) {
		t.Errorf("DescribeAuthorization(after deny) = %v, want authorization.ErrRequestExpired", err)
	}
}
