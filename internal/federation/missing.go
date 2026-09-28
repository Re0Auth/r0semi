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
// (account.id, for example). A scope that is already servable through a connected
// source is also ignored, because the data plane will use that binding.
//
// "Servable" is the DATA PLANE's criterion, not the scope string: the read
// selects a source by RESOURCE NAME (candidates), so a scope is satisfied when
// any connected, non-retired source in the same game declares a resource of that
// name — which need not be a source that declares the scope string itself.
// docs/upstream-protocol.md fixes one scope per resource name, so the two
// coincide in a canonical registry; keying on the scope alone made the consent
// screen name a source the read does not need whenever they diverge.
//
// When a scope has no binding, the preferred source (active before degraded) is
// named; retired sources are never offered. One source can cover several scopes,
// so requirements are keyed by (game, source) and carry the whole scope set.
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

	// Every source the data plane would try for a resource whose declared scope is
	// wanted, grouped by scope — the same set candidates() builds, per resource.
	byScope := make(map[string][]Source)
	seen := make(map[string]map[string]bool)
	for _, src := range s.registry.AllSources() {
		for _, res := range src.Resources {
			if res.Scope == "" || !wanted[res.Scope] {
				continue
			}
			for _, cand := range s.registry.Sources(src.Game) {
				if cand.Status == StatusRetired {
					continue
				}
				if _, ok := cand.Resource(res.Name); !ok {
					continue
				}
				key := sourceKey(cand.Game, cand.Name)
				if seen[res.Scope] == nil {
					seen[res.Scope] = make(map[string]bool)
				}
				if seen[res.Scope][key] {
					continue
				}
				seen[res.Scope][key] = true
				byScope[res.Scope] = append(byScope[res.Scope], cand)
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

		// Satisfied when any connected source is a candidate for the resource,
		// exactly as the data plane will pick one.
		satisfied := false
		for _, src := range candidates {
			if connected[sourceKey(src.Game, src.Name)] {
				satisfied = true
				break
			}
		}
		if satisfied {
			continue
		}

		usable := candidates
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
