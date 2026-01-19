package http

import (
	"context"
	"math"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Retrier handles request retries with backoff
type Retrier struct {
	config types.RetryConfig
}

// NewRetrier creates a new retrier
func NewRetrier(config types.RetryConfig) *Retrier {
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Backoff == "" {
		config.Backoff = "exponential"
	}
	if len(config.RetryOn) == 0 {
		config.RetryOn = []int{429, 502, 503, 504}
	}

	return &Retrier{config: config}
}

// Do executes a function with retries
func (r *Retrier) Do(ctx context.Context, fn func() (*types.HTTPResponse, error)) (*types.HTTPResponse, error) {
	var lastErr error
	var lastResp *types.HTTPResponse

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := fn()
		if err != nil {
			lastErr = err
			// Retry on network errors
			if attempt < r.config.MaxRetries {
				r.sleep(ctx, attempt)
				continue
			}
			return nil, lastErr
		}

		lastResp = resp

		// Check if we should retry based on status code
		if r.shouldRetry(resp.StatusCode) && attempt < r.config.MaxRetries {
			r.sleep(ctx, attempt)
			continue
		}

		return resp, nil
	}

	// Return last response if we have one, otherwise return error
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

// shouldRetry checks if we should retry based on status code
func (r *Retrier) shouldRetry(statusCode int) bool {
	for _, code := range r.config.RetryOn {
		if statusCode == code {
			return true
		}
	}
	return false
}

// sleep waits before the next retry
func (r *Retrier) sleep(ctx context.Context, attempt int) {
	var delay time.Duration

	switch r.config.Backoff {
	case "linear":
		delay = time.Duration(attempt+1) * time.Second
	case "exponential":
		delay = time.Duration(math.Pow(2, float64(attempt))) * time.Second
	default:
		delay = time.Second
	}

	// Cap at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	select {
	case <-ctx.Done():
	case <-time.After(delay):
	}
}
