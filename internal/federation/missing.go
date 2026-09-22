package federation

import (
	"context"
	"sort"

	"github.com/Re0Auth/r0semi/internal/account"
)

// BindingRequirement names a data source the account must connect before the
// requested scopes can actually be served.
//
// It is a prompt, not a verdict: the consent screen uses it to send the user to
// the binding flow, and the data plane still checks the binding on every call.
type BindingRequirement struct {
	Game        string
	Source      string
	DisplayName string
	// Scopes are the requested scopes this one source would make servable.
	Scopes []string
}

// MissingBindings reports which data sources the account must connect before
// the requested scopes can be served.
//
// A scope no configured source declares is ignored: it needs no data source
// (account.id, for example). A scope already satisfiable by a connected,
// non-retired source is also ignored, because the data plane will use that
// binding. When a scope several sources declare has no binding, the preferred
// source (active before degraded) is named; retired sources are never offered.
//
// One source can cover several scopes, so requirements are keyed by
// (game, source) and carry the whole scope set.
func (s *service) MissingBindings(ctx context.Context, user account.UserID, scopes []string) ([]BindingRequirement, error) {
	wanted := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope != "" {
			wanted[scope] = true
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	bindings, err := s.bindings.List(ctx, user)
	if err != nil {
		return nil, err
	}
	connected := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		connected[sourceKey(b.Game, b.Source)] = true
	}

	// Every source that declares a wanted scope, grouped by scope.
	byScope := make(map[string][]Source)
	for _, src := range s.registry.AllSources() {
		for _, res := range src.Resources {
			if res.Scope != "" && wanted[res.Scope] {
				byScope[res.Scope] = append(byScope[res.Scope], src)
			}
		}
	}
	if len(byScope) == 0 {
		return nil, nil
	}

	// Deterministic scope order, so the prompt is stable between two loads.
	scopeNames := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopeNames = append(scopeNames, scope)
	}
	sort.Strings(scopeNames)

	type requirement struct {
		game, source, display string
		scopes                []string
	}
	bySource := make(map[string]*requirement)
	var order []string

	for _, scope := range scopeNames {
		candidates := byScope[scope]

		// Satisfied when any connected source that declares the scope is still
		// servable, mirroring the data plane's "skip retired" rule.
		satisfied := false
		for _, src := range candidates {
			if src.Status != StatusRetired && connected[sourceKey(src.Game, src.Name)] {
				satisfied = true
				break
			}
		}
		if satisfied {
			continue
		}

		usable := make([]Source, 0, len(candidates))
		for _, src := range candidates {
			if src.Status != StatusRetired {
				usable = append(usable, src)
			}
		}
		if len(usable) == 0 {
			continue
		}
		sort.SliceStable(usable, func(i, j int) bool {
			if statusRank(usable[i].Status) != statusRank(usable[j].Status) {
				return statusRank(usable[i].Status) < statusRank(usable[j].Status)
			}
			return usable[i].Name < usable[j].Name
		})

		pick := usable[0]
		key := sourceKey(pick.Game, pick.Name)
		req := bySource[key]
		if req == nil {
			display := pick.DisplayName
			if display == "" {
				display = pick.Name
			}
			req = &requirement{game: pick.Game, source: pick.Name, display: display}
			bySource[key] = req
			order = append(order, key)
		}
		req.scopes = append(req.scopes, scope)
	}

	out := make([]BindingRequirement, 0, len(order))
	for _, key := range order {
		req := bySource[key]
		out = append(out, BindingRequirement{
			Game:        req.game,
			Source:      req.source,
			DisplayName: req.display,
			Scopes:      req.scopes,
		})
	}
	return out, nil
}
