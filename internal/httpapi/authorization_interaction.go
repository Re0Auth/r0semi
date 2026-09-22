package httpapi

import (
	"context"
	"errors"

	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/oauth"
)

// authzInteraction adapts the hand-rolled authz.Service to the consent seam.
// The OpenID Provider implements the same interface directly.
type authzInteraction struct{ svc authz.Service }

func (a authzInteraction) ValidID(id string) bool { return !authz.InvalidID(id) }

func (a authzInteraction) DescribeAuthorization(ctx context.Context, id string) (authorization.View, error) {
	req, err := a.svc.Get(ctx, id)
	if err != nil {
		return authorization.View{}, err
	}
	return authorization.View{
		ID:         req.ID,
		ClientID:   req.ClientID,
		ClientName: req.ClientName,
		Scopes:     req.Scopes,
	}, nil
}

func (a authzInteraction) ApproveAuthorization(ctx context.Context, id, subject string, scopes, explicit []oauth.Scope) (string, error) {
	resp, err := a.svc.Approve(ctx, id, subject, scopes, explicit)
	if err != nil {
		return "", normalizeAuthorizationError(err)
	}
	return oauth.BuildRedirect(resp.RedirectURI, map[string]string{
		"code": resp.Code, "state": resp.State,
	}), nil
}

func (a authzInteraction) DenyAuthorization(ctx context.Context, id string) (string, error) {
	req, err := a.svc.Deny(ctx, id)
	if err != nil {
		return "", normalizeAuthorizationError(err)
	}
	return oauth.BuildRedirect(req.RedirectURI, map[string]string{
		"error": "access_denied", "state": req.State,
	}), nil
}

// normalizeAuthorizationError turns the old engine's sentinel into a protocol
// error the shared handler already knows how to render.
func normalizeAuthorizationError(err error) error {
	if errors.Is(err, authz.ErrScopeNotRequested) {
		return &oauth.Error{Code: "invalid_scope", Description: "approved scope was not requested"}
	}
	return err
}
