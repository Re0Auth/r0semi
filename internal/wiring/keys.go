// Package wiring is Re0Auth's composition root glue. It binds the public
// libraries (audit, oauth) to the component runtime.
//
// The capability keys live here rather than in the libraries themselves, so
// that a library never depends on the dependency-injection container. The
// public packages (audit, oauth, upstreamkit) can then be imported on their own.
package wiring

import (
	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/core"
	"github.com/Re0Auth/r0semi/oauth"
)

// KeyLog is the audit-log capability.
var KeyLog = core.NewKey[audit.Logger]("audit", "log")

// KeyClients is the authorization server's client registry.
var KeyClients = core.NewKey[oauth.ClientRegistry]("oauth", "clients")

// KeyTokens is the authorization server's token store.
var KeyTokens = core.NewKey[oauth.Store]("oauth", "tokens")

// KeyAS is the authorization server capability.
var KeyAS = core.NewKey[oauth.Service]("oauth", "as")
