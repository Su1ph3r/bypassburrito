// Package protocol provides protocol-level evasion techniques for WAF bypass
package protocol

import (
	"context"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ProtocolEvasion provides protocol-level bypass techniques
type ProtocolEvasion interface {
	// SendHTTP2 sends request over HTTP/2 with optional manipulations
	SendHTTP2(ctx context.Context, req *types.HTTPRequest, opts HTTP2Options) (*types.HTTPResponse, error)

	// SendWebSocket upgrades to WebSocket and sends payload
	SendWebSocket(ctx context.Context, url string, payload string, opts WebSocketOptions) (*WebSocketResponse, error)

	// SendChunked sends request with chunked transfer encoding tricks
	SendChunked(ctx context.Context, req *types.HTTPRequest, opts ChunkedOptions) (*types.HTTPResponse, error)

	// SendPipelined sends multiple requests on single connection
	SendPipelined(ctx context.Context, reqs []*types.HTTPRequest) ([]*types.HTTPResponse, error)
}

// HTTP2Options configures HTTP/2 specific behavior
type HTTP2Options struct {
	Enabled              bool     `json:"enabled" yaml:"enabled"`
	PriorityManipulation bool     `json:"priority_manipulation" yaml:"priority_manipulation"`
	StreamIDOffset       uint32   `json:"stream_id_offset" yaml:"stream_id_offset"`
	PseudoHeaderOrder    []string `json:"pseudo_header_order" yaml:"pseudo_header_order"`
	ContinuationFrames   bool     `json:"continuation_frames" yaml:"continuation_frames"`
	WindowSizeManipulation bool   `json:"window_size_manipulation" yaml:"window_size_manipulation"`
	ForceHTTP2           bool     `json:"force_http2" yaml:"force_http2"`
}

// DefaultHTTP2Options returns default HTTP/2 options
func DefaultHTTP2Options() HTTP2Options {
	return HTTP2Options{
		Enabled:              false,
		PriorityManipulation: false,
		StreamIDOffset:       0,
		PseudoHeaderOrder:    []string{":method", ":authority", ":scheme", ":path"},
		ContinuationFrames:   false,
		WindowSizeManipulation: false,
		ForceHTTP2:           false,
	}
}

// WebSocketOptions configures WebSocket behavior
type WebSocketOptions struct {
	Enabled          bool              `json:"enabled" yaml:"enabled"`
	Subprotocols     []string          `json:"subprotocols" yaml:"subprotocols"`
	Extensions       []string          `json:"extensions" yaml:"extensions"`
	CustomHeaders    map[string]string `json:"custom_headers" yaml:"custom_headers"`
	FragmentMessages bool              `json:"fragment_messages" yaml:"fragment_messages"`
	FragmentSize     int               `json:"fragment_size" yaml:"fragment_size"`
	Timeout          time.Duration     `json:"timeout" yaml:"timeout"`
}

// DefaultWebSocketOptions returns default WebSocket options
func DefaultWebSocketOptions() WebSocketOptions {
	return WebSocketOptions{
		Enabled:          false,
		Subprotocols:     []string{},
		Extensions:       []string{},
		CustomHeaders:    make(map[string]string),
		FragmentMessages: false,
		FragmentSize:     1024,
		Timeout:          30 * time.Second,
	}
}

// WebSocketResponse holds WebSocket interaction result
type WebSocketResponse struct {
	Upgraded      bool               `json:"upgraded"`
	StatusCode    int                `json:"status_code"`
	Messages      []WebSocketMessage `json:"messages"`
	Error         string             `json:"error,omitempty"`
	CloseCode     int                `json:"close_code"`
	CloseReason   string             `json:"close_reason"`
	Latency       time.Duration      `json:"latency"`
}

// WebSocketMessage represents a single WS message
type WebSocketMessage struct {
	Type      int       `json:"type"` // TextMessage=1, BinaryMessage=2
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "sent", "received"
}

// ChunkedOptions configures chunked transfer tricks
type ChunkedOptions struct {
	Enabled            bool              `json:"enabled" yaml:"enabled"`
	ChunkSizes         []int             `json:"chunk_sizes" yaml:"chunk_sizes"`
	DelayBetweenChunks time.Duration     `json:"delay_between_chunks" yaml:"delay_between_chunks"`
	InvalidChunkSize   bool              `json:"invalid_chunk_size" yaml:"invalid_chunk_size"`
	TrailerHeaders     map[string]string `json:"trailer_headers" yaml:"trailer_headers"`
	ZeroChunkInMiddle  bool              `json:"zero_chunk_in_middle" yaml:"zero_chunk_in_middle"`
}

// DefaultChunkedOptions returns default chunked options
func DefaultChunkedOptions() ChunkedOptions {
	return ChunkedOptions{
		Enabled:            false,
		ChunkSizes:         []int{},
		DelayBetweenChunks: 0,
		InvalidChunkSize:   false,
		TrailerHeaders:     make(map[string]string),
		ZeroChunkInMiddle:  false,
	}
}

// ProtocolConfig holds all protocol-related configuration
type ProtocolConfig struct {
	PreferHTTP2      bool              `yaml:"prefer_http2" mapstructure:"prefer_http2"`
	EnableWebSocket  bool              `yaml:"enable_websocket" mapstructure:"enable_websocket"`
	ChunkedEvasion   bool              `yaml:"chunked_evasion" mapstructure:"chunked_evasion"`
	ConnectionReuse  bool              `yaml:"connection_reuse" mapstructure:"connection_reuse"`
	PipelineRequests bool              `yaml:"pipeline_requests" mapstructure:"pipeline_requests"`
	HTTP2            HTTP2Options      `yaml:"http2" mapstructure:"http2"`
	WebSocket        WebSocketOptions  `yaml:"websocket" mapstructure:"websocket"`
	Chunked          ChunkedOptions    `yaml:"chunked" mapstructure:"chunked"`
}

// DefaultProtocolConfig returns sensible defaults
func DefaultProtocolConfig() ProtocolConfig {
	return ProtocolConfig{
		PreferHTTP2:      false,
		EnableWebSocket:  false,
		ChunkedEvasion:   false,
		ConnectionReuse:  true,
		PipelineRequests: false,
		HTTP2:            DefaultHTTP2Options(),
		WebSocket:        DefaultWebSocketOptions(),
		Chunked:          DefaultChunkedOptions(),
	}
}
