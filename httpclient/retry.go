package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/retrypolicy"
)

// DoerFunc adapts a function to Doer.
type DoerFunc func(req *http.Request) (*http.Response, error)

// Do implements Doer.
func (f DoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// RetryOptions tunes Retry.
type RetryOptions struct {
	// MaxRetries is the number of extra attempts. Defaults to 3.
	MaxRetries int
	// InitialInterval defaults to 200ms.
	InitialInterval time.Duration
	// MaxInterval defaults to 5s.
	MaxInterval time.Duration
	// MaxElapsedTime caps total time across all attempts. Defaults to 15s.
	MaxElapsedTime time.Duration
	// ExtraStatuses adds status codes to retry on. 429, 502, 503 and 504 are
	// always retried. 500 deliberately is not: it usually means a bug, not a
	// transient fault.
	ExtraStatuses []int
}

const (
	defaultMaxRetries      = 3
	defaultInitialInterval = 200 * time.Millisecond
	defaultMaxInterval     = 5 * time.Second
	defaultMaxElapsedTime  = 15 * time.Second
	// maxRetryAfter caps how long an upstream Retry-After can hold a request.
	maxRetryAfter = 30 * time.Second
	// backoffFactor is how much each attempt's delay grows by. Two is the
	// conventional exponential schedule.
	backoffFactor = 2.0
	// jitterFactor randomizes each delay by ±50%, so a fleet of callers that
	// all saw the same upstream failure does not come back in lockstep.
	jitterFactor = 0.5
)

// Retry decorates a Doer with exponential backoff on transient failures.
//
// The loop, the schedule and the cancellation handling are failsafe-go's
// retrypolicy. What stays here is the policy that library is configured with,
// because these are this service's rules rather than general ones:
//
//   - only idempotent methods are retried, and only when the body can be
//     replayed: repeating a POST can create a second resource;
//   - 429/502/503/504 are transient, 500 is not;
//   - Retry-After is honoured, in seconds or as an HTTP date, and capped.
//
// HandleIf replaces the library's default "any error is retryable" rule, so a
// caller-side cancellation is classified as retryable=false and ends the
// sequence, and AbortOnErrors makes the same statement where failsafe checks
// cancellation between attempts. A cancelled request is reported as cancelled
// even when the last attempt produced an error of its own: the caller needs to
// tell "timed out" apart from "upstream is down".
//
// The choice of library, the rejected alternatives, and the three deliberate
// semantic changes this replacement made are recorded in
// docs/resilience-decision.md (ADR-0009).
func Retry(next Doer, opts RetryOptions) Doer {
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = defaultMaxRetries
	}
	if opts.InitialInterval <= 0 {
		opts.InitialInterval = defaultInitialInterval
	}
	if opts.MaxInterval <= 0 {
		opts.MaxInterval = defaultMaxInterval
	}
	if opts.MaxElapsedTime <= 0 {
		opts.MaxElapsedTime = defaultMaxElapsedTime
	}

	policy := retrypolicy.NewBuilder[guardedResponse]().
		HandleIf(func(resp *http.Response, err error) bool {
			if err != nil {
				return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
			}
			return resp != nil && retryableStatus(resp.StatusCode, opts.ExtraStatuses)
		}).
		AbortOnErrors(context.Canceled, context.DeadlineExceeded).
		WithMaxRetries(opts.MaxRetries).
		WithMaxDuration(opts.MaxElapsedTime).
		WithBackoffFactor(opts.InitialInterval, opts.MaxInterval, backoffFactor).
		WithJitterFactor(jitterFactor).
		WithDelayFunc(retryAfterDelay).
		// The caller sees the upstream's own last failure rather than a
		// synthetic "retries exceeded" error from the policy.
		ReturnLastFailure().
		// Release the failed attempt's connection while the retry waits, so it
		// is not queued behind a connection the previous attempt still holds.
		// It runs only when a retry is actually scheduled, which is why the
		// final response reaches the caller with its body intact.
		OnRetry(func(event failsafe.ExecutionEvent[guardedResponse]) {
			drain(event.LastResult())
		}).
		Build()

	return DoerFunc(func(req *http.Request) (*http.Response, error) {
		if !idempotent(req.Method) || (req.Body != nil && req.GetBody == nil) {
			return next.Do(req)
		}

		attempt := 0
		return failsafe.With[guardedResponse](policy).
			WithContext(req.Context()).
			Get(func() (*http.Response, error) {
				attempt++
				if attempt > 1 && req.Body != nil {
					body, err := req.GetBody()
					if err != nil {
						return nil, err
					}
					req.Body = body
				}
				return next.Do(req)
			})
	})
}

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func retryableStatus(status int, extra []int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	for _, e := range extra {
		if status == e {
			return true
		}
	}
	return false
}

// retryAfterDelay turns the attempt's Retry-After into its delay. Returning -1
// leaves the schedule to the configured backoff, which is what happens when the
// upstream sent no hint (or one this parse rejects).
func retryAfterDelay(exec failsafe.ExecutionAttempt[guardedResponse]) time.Duration {
	if after := retryAfter(exec.LastResult()); after > 0 {
		return after
	}
	return -1
}

// retryAfter reads RFC 9110 Retry-After, in seconds or as an HTTP date.
func retryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	value := resp.Header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return clampRetryAfter(time.Duration(seconds) * time.Second)
	}
	if when, err := http.ParseTime(value); err == nil {
		return clampRetryAfter(time.Until(when))
	}
	return 0
}

func clampRetryAfter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// drain reads and closes a body so the underlying connection can be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}
