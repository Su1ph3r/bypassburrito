package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Client wraps http.Client with additional features for WAF testing
type Client struct {
	client      *gohttp.Client
	rateLimiter *AdaptiveRateLimiter
	config      types.HTTPConfig
	session     *Session
	retrier     *Retrier
}

// ClientOption configures the client
type ClientOption func(*Client)

// NewClient creates a new HTTP client
func NewClient(config types.HTTPConfig, opts ...ClientOption) (*Client, error) {
	// Create transport
	transport := &gohttp.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.VerifySSL,
		MinVersion:         tls.VersionTLS12,
	}
	transport.TLSClientConfig = tlsConfig

	// Configure proxy
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = gohttp.ProxyURL(proxyURL)
	}

	// Create rate limiter
	var rateLimiter *AdaptiveRateLimiter
	if config.RateLimit > 0 {
		minRate := config.RateLimit * 0.1
		maxRate := config.RateLimit * 2
		rateLimiter = NewAdaptiveRateLimiter(config.RateLimit, minRate, maxRate)
	}

	c := &Client{
		client: &gohttp.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		rateLimiter: rateLimiter,
		config:      config,
		session:     NewSession(),
		retrier:     NewRetrier(config.Retry),
	}

	// Apply default headers
	if config.UserAgent != "" {
		c.session.SetHeader("User-Agent", config.UserAgent)
	}
	for k, v := range config.Headers {
		c.session.SetHeader(k, v)
	}
	for k, v := range config.Cookies {
		c.session.SetCookie(k, v)
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Do executes an HTTP request with rate limiting and retries
func (c *Client) Do(ctx context.Context, req *types.HTTPRequest) (*types.HTTPResponse, error) {
	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

	// Build the request
	httpReq, err := c.buildRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// Execute with retries
	return c.retrier.Do(ctx, func() (*types.HTTPResponse, error) {
		return c.execute(httpReq, req)
	})
}

// buildRequest creates an http.Request from our request type
func (c *Client) buildRequest(ctx context.Context, req *types.HTTPRequest) (*gohttp.Request, error) {
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := gohttp.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply session headers first
	for k, v := range c.session.Headers() {
		httpReq.Header.Set(k, v)
	}

	// Apply request-specific headers (override session)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set content type
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	// Apply cookies
	for k, v := range c.session.Cookies() {
		httpReq.AddCookie(&gohttp.Cookie{Name: k, Value: v})
	}
	for k, v := range req.Cookies {
		httpReq.AddCookie(&gohttp.Cookie{Name: k, Value: v})
	}

	return httpReq, nil
}

// execute performs the actual HTTP request
func (c *Client) execute(httpReq *gohttp.Request, origReq *types.HTTPRequest) (*types.HTTPResponse, error) {
	start := time.Now()

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Extract headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Record for rate limiting
	if c.rateLimiter != nil {
		if resp.StatusCode >= 400 {
			c.rateLimiter.RecordError(resp.StatusCode)
			if resp.StatusCode == 403 {
				c.rateLimiter.RecordBlock()
			}
		} else {
			c.rateLimiter.RecordSuccess()
		}
	}

	// Persist cookies if enabled
	if c.config.Session.PersistCookies {
		for _, cookie := range resp.Cookies() {
			c.session.SetCookie(cookie.Name, cookie.Value)
		}
	}

	// Get TLS version
	var tlsVersion string
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS10:
			tlsVersion = "TLS 1.0"
		case tls.VersionTLS11:
			tlsVersion = "TLS 1.1"
		case tls.VersionTLS12:
			tlsVersion = "TLS 1.2"
		case tls.VersionTLS13:
			tlsVersion = "TLS 1.3"
		}
	}

	return &types.HTTPResponse{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       headers,
		Body:          string(body),
		ContentLength: len(body),
		Latency:       latency,
		Timestamp:     time.Now(),
		TLSVersion:    tlsVersion,
	}, nil
}

// DoRaw executes a raw HTTP request
func (c *Client) DoRaw(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*types.HTTPResponse, error) {
	req := &types.HTTPRequest{
		Method:    method,
		URL:       rawURL,
		Headers:   headers,
		Body:      body,
		Timestamp: time.Now(),
	}
	return c.Do(ctx, req)
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, rawURL string) (*types.HTTPResponse, error) {
	return c.DoRaw(ctx, "GET", rawURL, nil, "")
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, rawURL string, contentType string, body string) (*types.HTTPResponse, error) {
	headers := map[string]string{
		"Content-Type": contentType,
	}
	return c.DoRaw(ctx, "POST", rawURL, headers, body)
}

// Session returns the session manager
func (c *Client) Session() *Session {
	return c.session
}

// SetRateLimit updates the rate limit
func (c *Client) SetRateLimit(rps float64) {
	if c.rateLimiter != nil {
		c.rateLimiter.mu.Lock()
		c.rateLimiter.currentRate = rps
		c.rateLimiter.limiter.SetRate(rps)
		c.rateLimiter.mu.Unlock()
	}
}

// CurrentRate returns the current rate limit
func (c *Client) CurrentRate() float64 {
	if c.rateLimiter == nil {
		return 0
	}
	return c.rateLimiter.CurrentRate()
}

// Close closes the client
func (c *Client) Close() {
	c.client.CloseIdleConnections()
}
