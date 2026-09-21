package wiring

import (
	"github.com/Re0Auth/r0semi/internal/core"
	"github.com/Re0Auth/r0semi/oauth"
)

// OAuthComponent returns the authorization server as a core.Component.
//
// It provides oauth/as and injects oauth/clients, oauth/tokens and audit/log.
// It activates only when all three are available and FAILS if the Config is
// incomplete.
func OAuthComponent(cfg oauth.Config) core.Component {
	return core.Component{
		Name:     "oauth",
		Provides: []core.KeyRef{KeyAS.Ref()},
		Inject: []core.KeyRef{
			KeyClients.Ref(),
			KeyTokens.Ref(),
			KeyLog.Ref(),
		},
		Apply: func(ctx *core.Context, _ any) (core.Disposer, error) {
			svc, err := oauth.NewService(
				KeyClients.MustGet(ctx),
				KeyTokens.MustGet(ctx),
				KeyLog.MustGet(ctx),
				cfg,
			)
			if err != nil {
				return nil, err
			}
			if _, err := KeyAS.Provide(ctx, svc); err != nil {
				return nil, err
			}
			return nil, nil
		},
	}
}
