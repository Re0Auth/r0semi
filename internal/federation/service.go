package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// maxBody caps how much of an upstream resource we read.
const maxBody = 4 << 20

// NotBoundError reports that the chosen source needs to be bound first. It
// wraps ErrNotBound so callers can use errors.Is.
type NotBoundError struct {
	Game   string
	Source string
}

func (e *NotBoundError) Error() string {
	return fmt.Sprintf("federation: %s/%s is not bound", e.Game, e.Source)
}

func (e *NotBoundError) Is(target error) bool { return target == ErrNotBound }

// SourceError reports a non-200 from a source.
type SourceError struct {
	Source string
	Status int
}

func (e *SourceError) Error() string {
	return fmt.Sprintf("federation: source %s returned HTTP %d", e.Source, e.Status)
}

// FetchRequest asks for one resource on behalf of one user.
type FetchRequest struct {
	User     account.UserID
	Game     string
	Resource string
	// Source optionally pins a source; empty lets Re0Auth choose one that
	// declares the resource.
	Source string
}

// FetchResult is a normalized payload plus its provenance.
type FetchResult struct {
	Source   string
	Degraded bool
	Data     json.RawMessage
}

// Service is the federation capability.
type Service interface {
	// Sources lists a game's configured sources.
	Sources(game string) []Source
	// AllSources lists every configured source, for the page that offers what
	// could be connected.
	AllSources() []Source
	// ResourceScope returns the downstream scope a resource requires.
	ResourceScope(game, resource string) (string, bool)
	// Fetch proxies a normalized resource from a bound source.
	Fetch(ctx context.Context, req FetchRequest) (FetchResult, error)
	// Raw proxies a source's native API verbatim.
	Raw(ctx context.Context, req RawRequest) (RawResult, error)
	// BeginBind starts binding a source for a user.
	BeginBind(ctx context.Context, user account.UserID, game, source, returnTo string) (BindChallenge, error)
	// CompleteBind finishes a binding and stores it.
	CompleteBind(ctx context.Context, user account.UserID, state, code string) (Binding, BindFlow, error)
	// Bindings lists the sources a user has connected.
	Bindings(ctx context.Context, user account.UserID) ([]Binding, error)
	// MissingBindings reports which data sources the account must connect before
	// the requested scopes can actually be served. It is advisory input to the
	// consent screen; the data plane enforces bindings on every call regardless.
	MissingBindings(ctx context.Context, user account.UserID, scopes []string) ([]BindingRequirement, error)
	// Unbind disconnects a source from an account, revoking upstream where the
	// source can be told to. Its local half always happens.
	Unbind(ctx context.Context, user account.UserID, game, source string) (RevocationResult, error)
	// CascadeRevoke ends the subject's whole upstream session at a source, and
	// then removes the binding. It fails closed: nothing is removed unless the
	// source confirmed, because the credential is the only means of retrying.
	CascadeRevoke(ctx context.Context, user account.UserID, game, source string) (RevocationResult, error)
	// RevokeAllBindings disconnects every binding in the deployment. It is the
	// data-source half of the Kill Switch, and it is what lets an operator reach a
	// binding nobody told them about.
	RevokeAllBindings(ctx context.Context) (BindingRevocationSummary, error)
	// RevokeUserBindings disconnects every binding one account holds.
	RevokeUserBindings(ctx context.Context, user account.UserID) (BindingRevocationSummary, error)
}

// Config wires the federation service.
type Config struct {
	Registry *Registry
	Bindings BindingStore
	// Vault protects the upstream token of every binding. The binding store
	// itself holds metadata only.
	Vault vault.Service
	// Flows persists pending bind flows. Defaults to an in-memory store.
	Flows BindFlowStore
	Doer  httpclient.Doer
	// HTTPClient performs the OAuth token exchange. Defaults to Doer when it is
	// an *http.Client, else http.DefaultClient.
	HTTPClient *http.Client
	// BaseURL is Re0Auth's public base URL; the bind callback is
	// {BaseURL}/auth/upstream/{game}/{source}/callback.
	BaseURL string
	// BindTTL is how long a pending bind stays valid. Defaults to 10 minutes.
	BindTTL time.Duration
	Now     func() time.Time
}

// NewService validates cfg and returns a Service.
func NewService(cfg Config) (Service, error) {
	switch {
	case cfg.Registry == nil:
		return nil, errors.New("federation: Registry is required")
	case cfg.Bindings == nil:
		return nil, errors.New("federation: BindingStore is required")
	case cfg.Vault == nil:
		return nil, errors.New("federation: Vault is required")
	case cfg.Doer == nil:
		return nil, errors.New("federation: Doer is required")
	}
	if cfg.Flows == nil {
		cfg.Flows = NewMemoryBindFlowStore()
	}
	if cfg.BindTTL <= 0 {
		cfg.BindTTL = 10 * time.Minute
	}
	if cfg.HTTPClient == nil {
		if hc, ok := cfg.Doer.(*http.Client); ok {
			cfg.HTTPClient = hc
		} else {
			cfg.HTTPClient = http.DefaultClient
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &service{
		registry:   cfg.Registry,
		bindings:   cfg.Bindings,
		vault:      cfg.Vault,
		flows:      cfg.Flows,
		doer:       cfg.Doer,
		httpClient: cfg.HTTPClient,
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		bindTTL:    cfg.BindTTL,
		locks:      &keyedMutex{},
		now:        cfg.Now,
	}, nil
}

type service struct {
	registry   *Registry
	bindings   BindingStore
	vault      vault.Service
	flows      BindFlowStore
	doer       httpclient.Doer
	httpClient *http.Client
	baseURL    string
	bindTTL    time.Duration
	locks      *keyedMutex
	now        func() time.Time
}

func (s *service) Sources(game string) []Source { return s.registry.Sources(game) }

// AllSources implements Service.
func (s *service) AllSources() []Source { return s.registry.AllSources() }

func (s *service) ResourceScope(game, resource string) (string, bool) {
	for _, src := range s.registry.Sources(game) {
		if res, ok := src.Resource(resource); ok {
			return res.Scope, true
		}
	}
	return "", false
}

func (s *service) Fetch(ctx context.Context, req FetchRequest) (FetchResult, error) {
	candidates, err := s.candidates(req.Game, req.Resource, req.Source)
	if err != nil {
		return FetchResult{}, err
	}

	var (
		lastErr       error
		firstNotBound *NotBoundError
		sawOther      bool
	)
	for i, src := range candidates {
		result, err := s.trySource(ctx, src, req)
		if err == nil {
			// Skipping the preferred source is what "degraded" reports.
			result.Degraded = i > 0
			return result, nil
		}
		var notBound *NotBoundError
		if errors.As(err, &notBound) {
			if firstNotBound == nil {
				firstNotBound = notBound
			}
		} else {
			sawOther = true
		}
		lastErr = err
	}

	// If the only obstacle was missing bindings, guide the user to bind (once).
	if !sawOther && firstNotBound != nil {
		return FetchResult{}, firstNotBound
	}
	if lastErr == nil {
		return FetchResult{}, ErrUnknownResource
	}
	return FetchResult{}, lastErr
}

func (s *service) trySource(ctx context.Context, src Source, req FetchRequest) (FetchResult, error) {
	binding, err := s.bindings.Get(ctx, req.User, req.Game, src.Name)
	if errors.Is(err, ErrNotBound) {
		return FetchResult{}, &NotBoundError{Game: req.Game, Source: src.Name}
	}
	if err != nil {
		return FetchResult{}, err
	}

	var data json.RawMessage
	err = s.callWithRefresh(ctx, src, binding, func(token string) error {
		d, e := s.fetchResource(ctx, src, req.Resource, token)
		if e != nil {
			return e
		}
		data = d
		return nil
	})
	if err != nil {
		return FetchResult{}, err
	}
	return FetchResult{Source: src.Name, Data: data}, nil
}

// candidates returns the sources to try, in order. A pinned source is the only
// candidate (never substituted); otherwise active sources precede degraded ones
// and retired sources are excluded.
func (s *service) candidates(game, resource, pinned string) ([]Source, error) {
	all := s.registry.Sources(game)
	if len(all) == 0 {
		return nil, ErrUnknownGame
	}
	if pinned != "" {
		src, ok := s.registry.Get(game, pinned)
		if !ok {
			return nil, ErrUnknownSource
		}
		if src.Status == StatusRetired {
			return nil, ErrSourceRetired
		}
		if _, ok := src.Resource(resource); !ok {
			return nil, ErrUnknownResource
		}
		return []Source{src}, nil
	}

	out := make([]Source, 0, len(all))
	for _, src := range all {
		if src.Status == StatusRetired {
			continue
		}
		if _, ok := src.Resource(resource); ok {
			out = append(out, src)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return statusRank(out[i].Status) < statusRank(out[j].Status) })
	return out, nil
}

// RawRequest asks for a verbatim proxy of a source's native API.
type RawRequest struct {
	User   account.UserID
	Game   string
	Source string
	Path   string
	Query  url.Values
}

// RawResult is an unmodified upstream response.
type RawResult struct {
	Source      string
	Status      int
	ContentType string
	Body        []byte
}

// Raw proxies a source's native API without modifying the body, preserving the
// upstream status and content type.
func (s *service) Raw(ctx context.Context, req RawRequest) (RawResult, error) {
	src, ok := s.registry.Get(req.Game, req.Source)
	if !ok {
		return RawResult{}, ErrUnknownSource
	}
	if src.Status == StatusRetired {
		return RawResult{}, ErrSourceRetired
	}
	if src.RawBase == "" {
		return RawResult{}, ErrRawUnsupported
	}

	binding, err := s.bindings.Get(ctx, req.User, req.Game, src.Name)
	if errors.Is(err, ErrNotBound) {
		return RawResult{}, &NotBoundError{Game: req.Game, Source: src.Name}
	}
	if err != nil {
		return RawResult{}, err
	}

	var out RawResult
	err = s.callWithRefresh(ctx, src, binding, func(token string) error {
		result, e := s.rawFetch(ctx, src, req.Path, req.Query, token)
		if e != nil {
			return e
		}
		if result.Status == http.StatusUnauthorized {
			return &SourceError{Source: src.Name, Status: http.StatusUnauthorized}
		}
		out = result
		return nil
	})
	if err != nil {
		return RawResult{}, err
	}
	out.Source = src.Name
	return out, nil
}

func (s *service) rawFetch(ctx context.Context, src Source, path string, query url.Values, token string) (RawResult, error) {
	endpoint := src.RawBase + "/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RawResult{}, fmt.Errorf("federation: build raw request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "*/*")

	resp, err := s.doer.Do(req)
	if err != nil {
		return RawResult{}, fmt.Errorf("federation: raw %s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return RawResult{}, fmt.Errorf("federation: read raw %s: %w", src.Name, err)
	}
	return RawResult{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}, nil
}

func (s *service) fetchResource(ctx context.Context, src Source, resource, token string) (json.RawMessage, error) {
	endpoint := strings.TrimRight(src.Issuer, "/") + "/resources/" + url.PathEscape(resource)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation: source %s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("federation: read %s: %w", src.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &SourceError{Source: src.Name, Status: resp.StatusCode}
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("federation: source %s returned invalid JSON", src.Name)
	}
	return json.RawMessage(body), nil
}
