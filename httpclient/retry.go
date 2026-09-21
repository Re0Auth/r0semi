package httpclient

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
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
)

// Retry decorates a Doer with exponential backoff on transient failures.
//
// Only idempotent methods are retried by default: repeating a POST can create a
// second resource. A retried attempt re-sends a fresh body, so a request with a
// body must be replayable (http.NewRequest sets GetBody for common body types);
// otherwise it is passed through untouched.
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

	return DoerFunc(func(req *http.Request) (*http.Response, error) {
		if !idempotent(req.Method) || (req.Body != nil && req.GetBody == nil) {
			return next.Do(req)
		}

		policy := backoff.NewExponentialBackOff()
		policy.InitialInterval = opts.InitialInterval
		policy.MaxInterval = opts.MaxInterval
		policy.MaxElapsedTime = opts.MaxElapsedTime
		policy.Reset()

		var (
			lastResp *http.Response
			lastErr  error
		)
		for attempt := 0; ; attempt++ {
			if attempt > 0 && req.Body != nil {
				body, err := req.GetBody()
				if err != nil {
					return lastResp, err
				}
				req.Body = body
			}

			resp, err := next.Do(req)
			lastResp, lastErr = resp, err
			if err == nil && !retryableStatus(resp.StatusCode, opts.ExtraStatuses) {
				return resp, nil
			}
			// A cancelled request is reported as such, even if the last attempt
			// produced its own error: the caller needs to tell "timed out" apart
			// from "upstream is down".
			if ctxErr := req.Context().Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if attempt >= opts.MaxRetries {
				return lastResp, lastErr
			}

			delay := policy.NextBackOff()
			if delay == backoff.Stop {
				return lastResp, lastErr
			}
			if err == nil {
				// Honour an explicit Retry-After, then release the connection.
				if after := retryAfter(resp); after > delay {
					delay = after
				}
				drain(resp)
				lastResp = nil
			}

			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
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

// retryAfter reads RFC 9110 Retry-After, in seconds or as an HTTP date.
func retryAfter(resp *http.Response) time.Duration {
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
