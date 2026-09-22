package federation

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/Re0Auth/r0semi/internal/account"
)

// Bindings lists the sources a user has connected, so the account page can show
// what is connected and offer to disconnect it.
func (s *service) Bindings(ctx context.Context, user account.UserID) ([]Binding, error) {
	if user == "" {
		return nil, errors.New("federation: user is required")
	}
	return s.bindings.List(ctx, user)
}

// Unbind disconnects a source from an account.
//
// It is idempotent: unbinding something that is not bound reports nothing to do
// rather than failing, so a retry after a dropped response is harmless.
//
// Known and bounded gap: a refresh token the source has already rotated away from
// is not revoked, because only the current one is in the vault. That follows from
// rotation rather than from this call, and is recorded rather than papered over.
func (s *service) Unbind(ctx context.Context, user account.UserID, game, source string) (RevocationResult, error) {
	if user == "" || game == "" || source == "" {
		return RevocationResult{}, errors.New("federation: user, game and source are required")
	}
	src, ok := s.registry.Get(game, source)
	if !ok {
		return RevocationResult{}, ErrUnknownSource
	}
	binding, err := s.bindings.Get(ctx, user, game, source)
	if errors.Is(err, ErrNotBound) {
		return RevocationResult{Upstream: RevocationNothingToDo}, nil
	}
	if err != nil {
		return RevocationResult{}, err
	}

	result := RevocationResult{Upstream: RevocationNothingToDo}
	if src.TokenClass == tokenClassLongLived {
		// The source declared up front that it cannot revoke per client. Saying so
		// out loud is the entire reason token_class exists; quietly reporting
		// success would defeat it.
		result.Upstream = RevocationUnsupported
	} else {
		result.Upstream, result.UpstreamError = s.revokeUpstream(ctx, src, binding)
	}

	// The local removal happens whatever the source said. A user must always be
	// able to cut a source off from their own account, and a source that is down,
	// broken or unwilling must not be able to hold that hostage.
	//
	// The secret goes first because it is the part that could still be used. If the
	// row delete then fails, the binding is left pointing at a shredded
	// credential, and retrying the unbind finishes the job.
	if err := s.vault.Revoke(ctx, BindingIdentity(binding)); err != nil {
		return result, fmt.Errorf("federation: shred binding secret: %w", err)
	}
	if err := s.bindings.Delete(ctx, user, game, source); err != nil {
		return result, fmt.Errorf("federation: delete binding: %w", err)
	}
	return result, nil
}

// revokeUpstream asks the source to drop the token it issued.
//
// Best effort by design: the caller has already decided the disconnection will
// happen, and reports this outcome separately.
func (s *service) revokeUpstream(ctx context.Context, src Source, binding Binding) (UpstreamRevocation, string) {
	var secret bindingSecret
	if err := s.useBindingSecret(ctx, binding, func(sec *bindingSecret) error {
		secret = *sec
		return nil
	}); err != nil {
		// No readable secret means there is nothing to revoke upstream. Not an
		// error: the goal of the call has already been achieved.
		return RevocationNothingToDo, ""
	}

	token, hint := preferredToken(secret)
	if token == "" {
		return RevocationNothingToDo, ""
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	if err := s.postRevocation(ctx, src, src.RevocationEndpoint, form); err != nil {
		return RevocationUnavailable, err.Error()
	}
	return RevocationDone, ""
}
