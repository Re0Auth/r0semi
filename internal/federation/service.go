package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/vault"
)

// maxBody caps how much of an upstream resource we read.
const maxBody = 4 << 20

// defaultMaxBufferedBytes is the default joint budget for upstream response
// bodies held in memory at once. See Config.MaxBufferedBytes for the derivation;
// 64 MiB is a quarter of the shipped container limit, and sixteen worst-case
// (4 MiB) reads.
const defaultMaxBufferedBytes = 64 << 20

// defaultTotalTimeout is how long one data-plane request may take, end to end. It
// bounds a path that can make several outbound calls in series, and it is
// deliberately below the server's write timeout (60s) so the refusal has a
// connection to be written on. The 20s outbound deadline is a per-call bound and
// stays as it is.
const defaultTotalTimeout = 45 * time.Second

// ErrBufferBudget reports that the data plane is already holding as much upstream
// response body in memory as it is allowed to, so this read is shed instead of
// allocated. It is the fail-closed answer to "in-flight reads x body size":
// serving it anyway is exactly how the process reaches its memory limit and is
// killed, which loses every request in flight rather than this one.
var ErrBufferBudget = errors.New("federation: the upstream response buffer budget is exhausted")

// bufferBudget admits an upstream read by the BYTES it will hold, not by the
// number of requests.
//
// The distinction is the whole point. A request cap says nothing about memory when
// one endpoint may hold four megabytes per request and another a few hundred
// bytes: 512 in flight is harmless for a session read and 2 GiB for a proxied
// upstream body. Counting the bytes the reading path will actually hold makes the
// invariant the deployment can be sized against — held <= limit — instead of a
// request count that has to be re-derived for every body cap.
//
// It never blocks. Waiting would move the memory pressure into a queue of
// goroutines each still holding a connection and a request, so a caller that does
// not fit is shed (ErrBufferBudget), the same direction the in-flight limiter and
// the outbound bulkhead already fail in.
type bufferBudget struct {
	mu    sync.Mutex
	limit int
	held  int
}

func newBufferBudget(limit int) *bufferBudget { return &bufferBudget{limit: limit} }

// acquire reserves n bytes, reporting whether they fit. A budget that was never
// constructed (nil) refuses: "no budget" must not read as "unbounded", since that
// is the state the finding is about.
func (b *bufferBudget) acquire(n int) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.held+n > b.limit {
		return false
	}
	b.held += n
	return true
}

func (b *bufferBudget) release(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.held -= n
	if b.held < 0 {
		// A release without its acquire is a bug in the caller, and letting the
		// counter drift negative would hand out budget that was never reserved.
		b.held = 0
	}
	b.mu.Unlock()
}

// reserveFor is what one upstream read must hold: the cap it will read to, or
// one byte past the length the upstream declared when that is smaller — and only
// when the declaration is positive.
//
// A declared length is safe to use because Go's transport refuses a body longer
// than the Content-Length it was given, so an upstream that lies fails the read
// rather than outgrowing its reservation. A declared length of ZERO is different:
// for a response built by hand (a stub Doer, an adapter) it is the zero value and
// says nothing about the reader, so it reserves the cap. Shrinking on it would let
// a body that is not empty spend a reservation of one byte.
func reserveFor(resp *http.Response, readCap int) int {
	if n := resp.ContentLength; n > 0 && n < int64(readCap) {
		return int(n) + 1
	}
	return readCap
}

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

// ResourceRequirement is one source that could serve a resource, and the scope
// that source requires for it.
type ResourceRequirement struct {
	Source string
	Scope  string
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
	// ResourceRequirements returns, in the order Fetch will try them, every source
	// that could serve (game, resource) together with the scope that source
	// requires. A pinned source narrows the list to itself. It is what an
	// authorization gate has to ask: the resource does not have ONE scope, it has
	// one per source that can answer, and which of them answers is decided by
	// candidates() rather than by the config's name order.
	//
	// The errors are the fetch's own vocabulary — ErrUnknownGame, ErrUnknownSource,
	// ErrSourceRetired, ErrUnknownResource — so a caller maps them the same way.
	ResourceRequirements(game, resource, pinned string) ([]ResourceRequirement, error)
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
	// KillSwitchPageSize is how many bindings one page of the deployment-wide
	// sweep holds. Defaults to killSwitchPageSize; a test sets it small to
	// exercise the paging loop.
	KillSwitchPageSize int
	Now                func() time.Time
	// Metrics, when set, records upstream reads and token refreshes. Nil records
	// nothing; the *observability.Metrics methods are nil-safe.
	Metrics *observability.Metrics
	// MaxBufferedBytes is the joint budget for upstream response bodies held in
	// memory at once, across every in-flight read on BOTH data-plane paths (the
	// verbatim proxy and the normalized fetch). Zero takes
	// defaultMaxBufferedBytes.
	//
	// It is the "in-flight x body size" bound that a request cap cannot express.
	// Each buffering read reserves what it may hold — up to maxBody (4 MiB) for a
	// raw passthrough, or the upstream's declared Content-Length plus one when that
	// is smaller — and a read that does not fit is shed with ErrBufferBudget
	// instead of allocated. Size it against the container's memory limit, not
	// against the traffic: the number that matters is
	//
	//	MaxBufferedBytes <= (container limit - runtime, pool and audit overhead)
	//
	// The shipped default (64 MiB) is a quarter of the 512Mi limit in
	// deploy/k8s/base/deployment.yaml and permits sixteen worst-case reads; the
	// same manifest sets GOMEMLIMIT so the heap has a soft limit below the
	// container's hard one.
	MaxBufferedBytes int
	// TotalTimeout bounds ONE data-plane request end to end, across every outbound
	// call it makes in series (candidate sources, token refreshes, the fetch again
	// after a 401). Zero takes defaultTotalTimeout.
	//
	// It exists because per-call deadlines do not bound a request: this path makes
	// several calls, so its worst case is a multiple of the outbound deadline, and
	// that multiple was larger than the HTTP server's write timeout. The client
	// then got a dropped connection with no error body — the one answer it cannot
	// interpret. Whatever this is set to, the server's write timeout must be
	// larger; cmd/re0auth keeps the two in step and a guard test fails if they
	// drift.
	TotalTimeout time.Duration
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
	if cfg.KillSwitchPageSize <= 0 {
		cfg.KillSwitchPageSize = killSwitchPageSize
	}
	if cfg.HTTPClient == nil {
		if hc, ok := cfg.Doer.(*http.Client); ok {
			cfg.HTTPClient = hc
		} else {
			// Not http.DefaultClient: that is the one client in the process with no
			// timeout and no redirect policy, and this one posts the authorization
			// code and the client secret. A caller that supplies only a Doer still
			// gets a bounded client for the exchange.
			cfg.HTTPClient = httpclient.NewOutboundClient(httpclient.OutboundConfig{})
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxBufferedBytes == 0 {
		cfg.MaxBufferedBytes = defaultMaxBufferedBytes
	}
	if cfg.TotalTimeout == 0 {
		cfg.TotalTimeout = defaultTotalTimeout
	}
	if cfg.TotalTimeout < 0 {
		return nil, errors.New("federation: TotalTimeout must not be negative")
	}
	if cfg.MaxBufferedBytes < 0 {
		return nil, errors.New("federation: MaxBufferedBytes must not be negative")
	}
	return &service{
		registry:      cfg.Registry,
		bindings:      cfg.Bindings,
		vault:         cfg.Vault,
		flows:         cfg.Flows,
		doer:          cfg.Doer,
		httpClient:    cfg.HTTPClient,
		baseURL:       strings.TrimRight(cfg.BaseURL, "/"),
		bindTTL:       cfg.BindTTL,
		sweepPage:     cfg.KillSwitchPageSize,
		locks:         &keyedMutex{},
		now:           cfg.Now,
		metrics:       cfg.Metrics,
		buffers:       newBufferBudget(cfg.MaxBufferedBytes),
		totalDeadline: cfg.TotalTimeout,
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
	// sweepPage is how many bindings one page of the deployment-wide sweep holds;
	// see Config.KillSwitchPageSize.
	sweepPage int
	locks     *keyedMutex
	now       func() time.Time
	// metrics observes upstream reads and refreshes. Optional; a nil
	// *observability.Metrics records nothing.
	metrics *observability.Metrics
	// buffers is the joint budget for the response bodies held in memory by the
	// two data-plane read paths. See Config.MaxBufferedBytes.
	buffers *bufferBudget
	// totalDeadline bounds one data-plane request end to end. See
	// Config.TotalTimeout.
	totalDeadline time.Duration
}

func (s *service) Sources(game string) []Source { return s.registry.Sources(game) }

// withinTotalTimeout bounds one data-plane request as a whole.
//
// Every outbound call already has its own deadline, and that is not enough: one
// request can make several of them in series — a candidate source, a token
// refresh, the fetch again after a 401, then the same for the next candidate — so
// the real worst case is "how many calls can this path make" times the outbound
// deadline, a number nothing was checking. It is larger than the server's write
// timeout, which means the client gets a dropped connection instead of an error
// body: the one response a caller cannot interpret.
//
// The total deadline makes the worst case a single configured number, so the write
// timeout can be set above it and every refusal has somewhere to be written. When
// the caller has already imposed its own deadline (a client disconnect, an outer
// handler), the earlier one wins — context deadlines compose that way, which is
// why this wraps rather than replaces.
func (s *service) withinTotalTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.totalDeadline <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.totalDeadline)
}

// AllSources implements Service.
func (s *service) AllSources() []Source { return s.registry.AllSources() }

func (s *service) ResourceRequirements(game, resource, pinned string) ([]ResourceRequirement, error) {
	candidates, err := s.candidates(game, resource, pinned)
	if err != nil {
		return nil, err
	}
	out := make([]ResourceRequirement, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, src := range candidates {
		res, ok := src.Resource(resource)
		if !ok {
			continue
		}
		// Two sources declaring the same scope is one requirement: the common
		// deployment shape is several sources of one game, all declaring the same
		// resource scope, and listing it twice would tell a client to hold a scope
		// it already holds.
		if seen[res.Scope] {
			continue
		}
		seen[res.Scope] = true
		out = append(out, ResourceRequirement{Source: src.Name, Scope: res.Scope})
	}
	if len(out) == 0 {
		return nil, ErrUnknownResource
	}
	return out, nil
}

func (s *service) Fetch(ctx context.Context, req FetchRequest) (FetchResult, error) {
	ctx, cancel := s.withinTotalTimeout(ctx)
	defer cancel()

	candidates, err := s.candidates(req.Game, req.Resource, req.Source)
	if err != nil {
		return FetchResult{}, err
	}

	var (
		lastErr       error
		lastSource    string
		lastDuration  time.Duration
		firstNotBound *NotBoundError
		sawOther      bool
	)
	for i, src := range candidates {
		start := time.Now()
		result, err := s.trySource(ctx, src, req)
		elapsed := time.Since(start)
		if err == nil {
			// Skipping the preferred source is what "degraded" reports.
			result.Degraded = i > 0
			outcome := observability.UpstreamOK
			if result.Degraded {
				outcome = observability.UpstreamDegraded
			}
			s.metrics.ObserveUpstreamFetch(req.Game, result.Source, outcome)
			s.metrics.ObserveUpstreamFetchDuration(req.Game, result.Source, outcome, elapsed)
			return result, nil
		}
		lastSource = src.Name
		lastDuration = elapsed
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
		// No upstream call was made, so the latency histogram is left alone: a
		// binding-store lookup is not what "the source is slow" means.
		s.metrics.ObserveUpstreamFetch(req.Game, firstNotBound.Source, observability.UpstreamNotBound)
		return FetchResult{}, firstNotBound
	}
	if lastErr == nil {
		// No candidate could even be tried (an unknown or retired source): that is
		// a client error, not an upstream failure, so it is not recorded here.
		return FetchResult{}, ErrUnknownResource
	}
	// Only names from the registry reach this line, so the labels stay bounded.
	outcome := observability.UpstreamUnavailable
	if errors.Is(lastErr, httpclient.ErrCircuitOpen) {
		outcome = observability.UpstreamCircuitOpen
	}
	s.metrics.ObserveUpstreamFetch(req.Game, lastSource, outcome)
	s.metrics.ObserveUpstreamFetchDuration(req.Game, lastSource, outcome, lastDuration)
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
	ctx, cancel := s.withinTotalTimeout(ctx)
	defer cancel()

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
		s.metrics.ObserveUpstreamFetch(req.Game, src.Name, observability.UpstreamNotBound)
		return RawResult{}, &NotBoundError{Game: req.Game, Source: src.Name}
	}
	if err != nil {
		s.metrics.ObserveUpstreamFetch(req.Game, src.Name, observability.UpstreamUnavailable)
		return RawResult{}, err
	}

	var out RawResult
	start := time.Now()
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
	elapsed := time.Since(start)
	if err != nil {
		outcome := observability.UpstreamUnavailable
		if errors.Is(err, httpclient.ErrCircuitOpen) {
			outcome = observability.UpstreamCircuitOpen
		}
		s.metrics.ObserveUpstreamFetch(req.Game, src.Name, outcome)
		s.metrics.ObserveUpstreamFetchDuration(req.Game, src.Name, outcome, elapsed)
		return RawResult{}, err
	}
	out.Source = src.Name
	s.metrics.ObserveUpstreamFetch(req.Game, src.Name, observability.UpstreamOK)
	s.metrics.ObserveUpstreamFetchDuration(req.Game, src.Name, observability.UpstreamOK, elapsed)
	return out, nil
}

// cleanRawPath normalizes the caller-supplied path before it is joined to a
// source's base URL, and refuses one that would climb out of it.
//
// net/http's ServeMux already cleans `..` and `//` out of r.URL.Path before it
// matches a route, so inside the assembled server this is a second line rather
// than the first. It is here because "the safety of this join rests on a property
// of a different package" is not a property: a handler mounted on a bare mux, in
// a test, or behind a future router would not have it, and the failure mode is a
// request to an endpoint the operator never configured. A guard that travels with
// the code that depends on it is the only kind that cannot be left behind.
//
// An escaping path is refused rather than resolved. This endpoint proxies a
// source's own API verbatim; no caller needs to traverse upwards to use it, and
// answering `a/../../b` with `b` would be inventing a meaning the contract does
// not give it.
func cleanRawPath(raw string) (string, error) {
	if err := rejectEscapingPath(raw); err != nil {
		return "", err
	}
	cleaned := path.Clean("/" + raw)
	if cleaned == "/" {
		return "", nil
	}
	// Clean always yields an absolute path; the caller rejoins the relative form.
	return strings.TrimPrefix(cleaned, "/"), nil
}

// maxRawPathDecodeRounds bounds the re-decoding below. Two encodings are what an
// attacker actually sends; the cap is there so a crafted input cannot make the
// loop spin, and hitting it is itself a refusal.
const maxRawPathDecodeRounds = 4

// rejectEscapingPath fails a path that could climb out of the base URL — including
// a path that only does so after something downstream decodes it again.
//
// Checking the once-decoded value for a literal ".." segment is not enough, and
// round 4 showed why: net/http unescapes a wildcard value exactly once before this
// function ever sees it, so the caller still controls a second encoding. `%2e%2e`
// arrives as `%2e%2e`, survives a literal-`..` check, is concatenated on, and is
// decoded by the source — or by a proxy in front of it — into `..`. The result is
// a different resource on the same host (the host cannot be changed; see the
// tests), which is the operator's prefix being escaped rather than an SSRF.
//
// So the check is applied at every decoding depth, and the forms that have nothing
// to do with `..` are refused alongside it:
//
//   - a segment that *begins* with ".." — `..;` is `..` to any server that strips
//     path parameters before normalizing;
//   - a backslash, which is a path separator to a Windows-hosted source;
//   - still-changing input after the depth cap, rather than guessing what the
//     source will make of it.
//
// A malformed escape is deliberately NOT refused: `%` alone cannot decode into a
// traversal anywhere, and refusing it would break a legitimate path that contains
// a literal percent sign. The loop simply stops, which leaves the value for the
// source to read as the literal text it is.
func rejectEscapingPath(raw string) error {
	candidate := raw
	for round := 0; round < maxRawPathDecodeRounds; round++ {
		for _, segment := range strings.Split(candidate, "/") {
			if strings.HasPrefix(segment, "..") || strings.ContainsRune(segment, '\\') {
				return ErrRawPathEscapes
			}
		}
		decoded, err := url.PathUnescape(candidate)
		if err != nil {
			// Deliberately not refused: a malformed escape cannot decode into a
			// traversal anywhere, so it is accepted as the literal text it is. See
			// the note above.
			return nil //nolint:nilerr // the escape error is the accept condition, not a swallowed failure
		}
		if decoded == candidate {
			return nil
		}
		candidate = decoded
	}
	return ErrRawPathEscapes
}

func (s *service) rawFetch(ctx context.Context, src Source, path string, query url.Values, token string) (RawResult, error) {
	cleaned, err := cleanRawPath(path)
	if err != nil {
		return RawResult{}, err
	}
	endpoint := src.RawBase
	if cleaned != "" {
		endpoint += "/" + cleaned
	}
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
	defer func() { _ = resp.Body.Close() }()
	// One byte past the cap, so "exactly at the limit" and "past the limit" are
	// distinguishable. A truncated body returned as a complete 200 claims a
	// completeness it does not have, on the one endpoint whose contract is
	// "verbatim" — and for the byte-oriented payloads this endpoint exists for
	// (NDJSON, CSV, plain text) the truncation stays syntactically valid, so
	// nothing downstream can notice it. The normalized path cannot have this
	// problem: its body has to parse as JSON, and a cut one does not.
	//
	// The reservation happens BEFORE the read and covers the worst case, because
	// the bytes exist from the moment ReadAll starts copying them: admitting after
	// the fact would mean the budget can only report an overrun it has already
	// suffered.
	reserve := reserveFor(resp, maxBody+1)
	if !s.buffers.acquire(reserve) {
		return RawResult{}, ErrBufferBudget
	}
	defer s.buffers.release(reserve)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return RawResult{}, fmt.Errorf("federation: read raw %s: %w", src.Name, err)
	}
	if len(body) > maxBody {
		return RawResult{}, ErrResponseTooLarge
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
	defer func() { _ = resp.Body.Close() }()
	// Same joint budget as the raw path: a normalized fetch holds one body of up
	// to maxBody while it parses. See Config.MaxBufferedBytes.
	reserve := reserveFor(resp, maxBody)
	if !s.buffers.acquire(reserve) {
		return nil, ErrBufferBudget
	}
	defer s.buffers.release(reserve)
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
