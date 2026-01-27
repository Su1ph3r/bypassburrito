package protocol

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketClient handles WebSocket-based payload delivery
type WebSocketClient struct {
	config   WebSocketOptions
	dialer   *websocket.Dialer
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(config WebSocketOptions) *WebSocketClient {
	dialer := &websocket.Dialer{
		Subprotocols:     config.Subprotocols,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		HandshakeTimeout: config.Timeout,
	}

	return &WebSocketClient{
		config: config,
		dialer: dialer,
	}
}

// SendPayload upgrades to WebSocket and sends a payload
func (w *WebSocketClient) SendPayload(ctx context.Context, url string, payload string, opts WebSocketOptions) (*WebSocketResponse, error) {
	start := time.Now()
	response := &WebSocketResponse{
		Messages: make([]WebSocketMessage, 0),
	}

	// Build request headers
	headers := make(http.Header)
	for k, v := range opts.CustomHeaders {
		headers.Set(k, v)
	}

	// Add extensions if specified
	if len(opts.Extensions) > 0 {
		for _, ext := range opts.Extensions {
			headers.Add("Sec-WebSocket-Extensions", ext)
		}
	}

	// Dial the WebSocket
	conn, httpResp, err := w.dialer.DialContext(ctx, url, headers)
	if err != nil {
		response.Error = err.Error()
		if httpResp != nil {
			response.StatusCode = httpResp.StatusCode
		}
		response.Latency = time.Since(start)
		return response, nil
	}
	defer conn.Close()

	response.Upgraded = true
	response.StatusCode = 101 // Switching Protocols

	// Set read deadline
	if opts.Timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(opts.Timeout))
	}

	// Send the payload
	if opts.FragmentMessages && len(payload) > opts.FragmentSize {
		// Fragment the message
		err = w.sendFragmented(conn, payload, opts.FragmentSize)
	} else {
		err = conn.WriteMessage(websocket.TextMessage, []byte(payload))
	}

	if err != nil {
		response.Error = fmt.Sprintf("write error: %s", err.Error())
		response.Latency = time.Since(start)
		return response, nil
	}

	// Record sent message
	response.Messages = append(response.Messages, WebSocketMessage{
		Type:      websocket.TextMessage,
		Data:      []byte(payload),
		Timestamp: time.Now(),
		Direction: "sent",
	})

	// Read response(s)
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			response.Latency = time.Since(start)
			return response, nil
		default:
		}

		msgType, data, err := conn.ReadMessage()
		if err != nil {
			// Check if it's a close frame
			if closeErr, ok := err.(*websocket.CloseError); ok {
				response.CloseCode = closeErr.Code
				response.CloseReason = closeErr.Text
			}
			break
		}

		response.Messages = append(response.Messages, WebSocketMessage{
			Type:      msgType,
			Data:      data,
			Timestamp: time.Now(),
			Direction: "received",
		})

		// Only read one response for now
		break
	}

	response.Latency = time.Since(start)
	return response, nil
}

// sendFragmented sends a message in fragments
func (w *WebSocketClient) sendFragmented(conn *websocket.Conn, payload string, fragmentSize int) error {
	data := []byte(payload)
	total := len(data)

	for i := 0; i < total; i += fragmentSize {
		end := i + fragmentSize
		if end > total {
			end = total
		}
		fragment := data[i:end]

		// Determine message type for fragment
		var messageType int
		if i == 0 {
			messageType = websocket.TextMessage
		} else {
			messageType = websocket.TextMessage // Continuation would require lower-level API
		}

		if err := conn.WriteMessage(messageType, fragment); err != nil {
			return err
		}
	}

	return nil
}

// ProbeWebSocket checks if a URL supports WebSocket
func (w *WebSocketClient) ProbeWebSocket(ctx context.Context, url string) (bool, error) {
	// Convert http(s) to ws(s)
	wsURL := url
	if len(url) > 5 && url[:5] == "https" {
		wsURL = "wss" + url[5:]
	} else if len(url) > 4 && url[:4] == "http" {
		wsURL = "ws" + url[4:]
	}

	conn, _, err := w.dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

// WebSocketMutator generates WebSocket-based bypass mutations
type WebSocketMutator struct {
	config WebSocketOptions
}

// NewWebSocketMutator creates a new WebSocket mutator
func NewWebSocketMutator(config WebSocketOptions) *WebSocketMutator {
	return &WebSocketMutator{config: config}
}

// GeneratePayloadMutations returns WebSocket-specific payload mutations
func (m *WebSocketMutator) GeneratePayloadMutations(payload string) []string {
	var mutations []string

	// Binary encoding
	mutations = append(mutations, payload) // Original as text

	// Split across multiple messages
	if len(payload) > 10 {
		mid := len(payload) / 2
		mutations = append(mutations, payload[:mid]) // First half
		mutations = append(mutations, payload[mid:]) // Second half (would need to be sent after)
	}

	// With ping/pong interleaving (conceptual)
	mutations = append(mutations, "\x89\x00"+payload) // Prepend ping frame bytes (conceptual)

	// Masked differently (WebSocket uses XOR masking)
	// Note: gorilla/websocket handles masking, this is for awareness
	mutations = append(mutations, payload)

	return mutations
}

// GetUpgradeHeaders returns headers for WebSocket upgrade
func GetUpgradeHeaders(customHeaders map[string]string) map[string]string {
	headers := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Version": "13",
	}

	for k, v := range customHeaders {
		headers[k] = v
	}

	return headers
}
