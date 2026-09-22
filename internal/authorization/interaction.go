// Package authorization defines the consent interaction: the engine-neutral
// contract between the /v1 consent screen and whichever authorization engine is
// running (the hand-rolled one or the OpenID Provider).
//
// It exists so the HTTP layer can offer the consent screen without importing an
// engine, and so both engines can implement one interface.
package authorization

import (
	"context"

	"github.com/Re0Auth/r0semi/oauth"
)

// View is the consent screen's view of a pending authorization. It carries no
// secret.
type View struct {
	ID         string
	ClientID   string
	ClientName string
	Scopes     []oauth.Scope
}

// Interaction is the consent screen's engine seam.
type Interaction interface {
	// ValidID reports whether id is structurally plausible for this engine,
	// letting the HTTP layer reject garbage before a store lookup.
	ValidID(id string) bool
	// DescribeAuthorization returns the pending request for the consent screen.
	DescribeAuthorization(ctx context.Context, id string) (View, error)
	// ApproveAuthorization completes the request and returns the browser's next
	// URL. It may only narrow the requested scopes.
	ApproveAuthorization(ctx context.Context, id, subject string, scopes, explicit []oauth.Scope) (string, error)
	// DenyAuthorization cancels the request and returns the browser's next URL.
	DenyAuthorization(ctx context.Context, id string) (string, error)
}
