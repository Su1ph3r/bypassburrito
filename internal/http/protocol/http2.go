package protocol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
	"golang.org/x/net/http2"
)

// HTTP2Client handles HTTP/2 specific operations
type HTTP2Client struct {
	transport *http2.Transport
	client    *http.Client
	config    HTTP2Options
}

// NewHTTP2Client creates a new HTTP/2 client
func NewHTTP2Client(config HTTP2Options) *HTTP2Client {
	transport := &http2.Transport{
		AllowHTTP: true, // Allow h2c (HTTP/2 cleartext)
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing
			NextProtos:         []string{"h2"},
		},
	}

	return &HTTP2Client{
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		config: config,
	}
}

// SendRequest sends an HTTP/2 request with optional manipulations
func (h *HTTP2Client) SendRequest(ctx context.Context, req *types.HTTPRequest, opts HTTP2Options) (*types.HTTPResponse, error) {
	start := time.Now()

	// Build the HTTP request
	httpReq, err := h.buildRequest(ctx, req, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Execute request
	resp, err := h.client.Do(httpReq)
	if err != nil {
		return &types.HTTPResponse{
			Error:   err.Error(),
			Latency: time.Since(start),
		}, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = strings.Join(v, ", ")
		}
	}

	return &types.HTTPResponse{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       headers,
		Body:          string(body),
		ContentLength: len(body),
		Latency:       time.Since(start),
		Timestamp:     time.Now(),
	}, nil
}

// buildRequest creates an HTTP request with HTTP/2 specific options
func (h *HTTP2Client) buildRequest(ctx context.Context, req *types.HTTPRequest, opts HTTP2Options) (*http.Request, error) {
	// Determine method
	method := req.Method
	if method == "" {
		method = "GET"
	}

	// Create base request
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	// Add headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Reorder pseudo-headers if configured
	if len(opts.PseudoHeaderOrder) > 0 {
		// Note: Go's HTTP/2 implementation doesn't directly expose pseudo-header ordering
		// This is a placeholder for custom HTTP/2 frame manipulation
		httpReq.Header.Set("X-H2-Pseudo-Order", strings.Join(opts.PseudoHeaderOrder, ","))
	}

	return httpReq, nil
}

// SendWithPriorityManipulation sends request with priority frame manipulation
func (h *HTTP2Client) SendWithPriorityManipulation(ctx context.Context, req *types.HTTPRequest, priority uint8, exclusive bool) (*types.HTTPResponse, error) {
	opts := h.config
	opts.PriorityManipulation = true

	// Add priority hints via headers (actual frame manipulation requires lower-level access)
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	req.Headers["Priority"] = fmt.Sprintf("u=%d", priority)

	return h.SendRequest(ctx, req, opts)
}

// HTTP2Mutator generates HTTP/2 specific mutations
type HTTP2Mutator struct {
	config HTTP2Options
}

// NewHTTP2Mutator creates a new HTTP/2 mutator
func NewHTTP2Mutator(config HTTP2Options) *HTTP2Mutator {
	return &HTTP2Mutator{config: config}
}

// GenerateMutations returns HTTP/2 specific request mutations
func (m *HTTP2Mutator) GenerateMutations(req *types.HTTPRequest) []*types.HTTPRequest {
	var mutations []*types.HTTPRequest

	// Pseudo-header reordering mutations
	pseudoHeaderOrders := [][]string{
		{":method", ":authority", ":scheme", ":path"},       // Standard order
		{":path", ":method", ":authority", ":scheme"},       // Path first
		{":scheme", ":path", ":authority", ":method"},       // Scheme first
		{":authority", ":method", ":path", ":scheme"},       // Authority first
		{":method", ":path", ":scheme", ":authority"},       // No authority priority
	}

	for i, order := range pseudoHeaderOrders {
		mutated := copyRequest(req)
		if mutated.Headers == nil {
			mutated.Headers = make(map[string]string)
		}
		mutated.Headers["X-H2-Pseudo-Order"] = strings.Join(order, ",")
		mutated.Headers["X-Mutation"] = fmt.Sprintf("h2_pseudo_order_%d", i)
		mutations = append(mutations, mutated)
	}

	// Priority manipulation mutations
	priorities := []struct {
		priority  uint8
		exclusive bool
		name      string
	}{
		{255, false, "max_priority"},
		{0, false, "min_priority"},
		{128, true, "exclusive_mid"},
		{1, true, "exclusive_low"},
	}

	for _, p := range priorities {
		mutated := copyRequest(req)
		if mutated.Headers == nil {
			mutated.Headers = make(map[string]string)
		}
		mutated.Headers["Priority"] = fmt.Sprintf("u=%d", p.priority)
		mutated.Headers["X-Mutation"] = fmt.Sprintf("h2_priority_%s", p.name)
		mutations = append(mutations, mutated)
	}

	// Window size manipulation hints
	windowSizes := []int{1024, 65535, 16777215} // Various window sizes
	for _, size := range windowSizes {
		mutated := copyRequest(req)
		if mutated.Headers == nil {
			mutated.Headers = make(map[string]string)
		}
		mutated.Headers["X-H2-Window-Size"] = fmt.Sprintf("%d", size)
		mutated.Headers["X-Mutation"] = fmt.Sprintf("h2_window_%d", size)
		mutations = append(mutations, mutated)
	}

	return mutations
}

// copyRequest creates a deep copy of an HTTP request
func copyRequest(req *types.HTTPRequest) *types.HTTPRequest {
	copied := &types.HTTPRequest{
		URL:         req.URL,
		Method:      req.Method,
		Body:        req.Body,
		ContentType: req.ContentType,
		Headers:     make(map[string]string),
		Cookies:     make(map[string]string),
		Timestamp:   req.Timestamp,
	}

	for k, v := range req.Headers {
		copied.Headers[k] = v
	}
	for k, v := range req.Cookies {
		copied.Cookies[k] = v
	}

	return copied
}

// CreateHTTP2Connection creates a raw HTTP/2 connection for advanced manipulation
func CreateHTTP2Connection(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	// Dial the server
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Verify HTTP/2 was negotiated
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, fmt.Errorf("HTTP/2 not negotiated")
	}

	return conn, nil
}
