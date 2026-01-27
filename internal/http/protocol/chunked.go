package protocol

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ChunkedClient handles chunked transfer encoding tricks
type ChunkedClient struct {
	config  ChunkedOptions
	timeout time.Duration
}

// NewChunkedClient creates a new chunked client
func NewChunkedClient(config ChunkedOptions, timeout time.Duration) *ChunkedClient {
	return &ChunkedClient{
		config:  config,
		timeout: timeout,
	}
}

// SendChunkedRequest sends a request with chunked transfer encoding
func (c *ChunkedClient) SendChunkedRequest(ctx context.Context, req *types.HTTPRequest, opts ChunkedOptions) (*types.HTTPResponse, error) {
	start := time.Now()

	// Parse URL to get host and path
	host, path, useTLS, err := parseURL(req.URL)
	if err != nil {
		return nil, err
	}

	// Establish connection
	conn, err := c.dial(host, useTLS)
	if err != nil {
		return &types.HTTPResponse{
			Error:   err.Error(),
			Latency: time.Since(start),
		}, nil
	}
	defer conn.Close()

	// Set deadline
	if c.timeout > 0 {
		conn.SetDeadline(time.Now().Add(c.timeout))
	}

	// Build and send chunked request
	if err := c.writeChunkedRequest(conn, req, path, host, opts); err != nil {
		return &types.HTTPResponse{
			Error:   err.Error(),
			Latency: time.Since(start),
		}, nil
	}

	// Read response
	resp, err := c.readResponse(conn)
	if err != nil {
		return &types.HTTPResponse{
			Error:   err.Error(),
			Latency: time.Since(start),
		}, nil
	}

	resp.Latency = time.Since(start)
	resp.Timestamp = time.Now()
	return resp, nil
}

// dial establishes a connection
func (c *ChunkedClient) dial(host string, useTLS bool) (net.Conn, error) {
	if useTLS {
		return tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
	}
	return net.Dial("tcp", host)
}

// writeChunkedRequest writes a chunked request to the connection
func (c *ChunkedClient) writeChunkedRequest(conn net.Conn, req *types.HTTPRequest, path, host string, opts ChunkedOptions) error {
	// Write request line
	method := req.Method
	if method == "" {
		method = "POST"
	}
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", method, path)

	// Write headers
	fmt.Fprintf(conn, "Host: %s\r\n", strings.Split(host, ":")[0])
	fmt.Fprintf(conn, "Transfer-Encoding: chunked\r\n")

	for k, v := range req.Headers {
		fmt.Fprintf(conn, "%s: %s\r\n", k, v)
	}

	// End headers
	fmt.Fprintf(conn, "\r\n")

	// Write body in chunks
	body := []byte(req.Body)
	if err := c.writeChunkedBody(conn, body, opts); err != nil {
		return err
	}

	// Write trailer headers if specified
	for k, v := range opts.TrailerHeaders {
		fmt.Fprintf(conn, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(conn, "\r\n")

	return nil
}

// writeChunkedBody writes the body in chunks
func (c *ChunkedClient) writeChunkedBody(conn net.Conn, body []byte, opts ChunkedOptions) error {
	// Determine chunk sizes
	var chunkSizes []int
	if len(opts.ChunkSizes) > 0 {
		chunkSizes = opts.ChunkSizes
	} else {
		// Default: single chunk
		chunkSizes = []int{len(body)}
	}

	offset := 0
	chunkIdx := 0

	for offset < len(body) {
		// Get chunk size
		size := chunkSizes[chunkIdx%len(chunkSizes)]
		if offset+size > len(body) {
			size = len(body) - offset
		}

		// Write chunk size
		if opts.InvalidChunkSize {
			// Write malformed chunk size (may confuse some parsers)
			fmt.Fprintf(conn, " %x\r\n", size)
		} else {
			fmt.Fprintf(conn, "%x\r\n", size)
		}

		// Write chunk data
		conn.Write(body[offset : offset+size])
		fmt.Fprintf(conn, "\r\n")

		offset += size
		chunkIdx++

		// Add delay between chunks if specified
		if opts.DelayBetweenChunks > 0 {
			time.Sleep(opts.DelayBetweenChunks)
		}

		// Insert zero-length chunk in middle (some WAFs might mishandle)
		if opts.ZeroChunkInMiddle && offset < len(body) && chunkIdx == len(chunkSizes)/2 {
			fmt.Fprintf(conn, "0\r\n\r\n")
		}
	}

	// Write final chunk (zero length)
	fmt.Fprintf(conn, "0\r\n")

	return nil
}

// readResponse reads and parses the HTTP response
func (c *ChunkedClient) readResponse(conn net.Conn) (*types.HTTPResponse, error) {
	reader := bufio.NewReader(conn)

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	statusLine = strings.TrimSpace(statusLine)

	// Parse status
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid status line: %s", statusLine)
	}

	statusCode, _ := strconv.Atoi(parts[1])
	status := statusLine

	// Read headers
	headers := make(map[string]string)
	isChunked := false
	contentLength := -1

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			headers[key] = value

			if strings.ToLower(key) == "transfer-encoding" && strings.Contains(strings.ToLower(value), "chunked") {
				isChunked = true
			}
			if strings.ToLower(key) == "content-length" {
				contentLength, _ = strconv.Atoi(value)
			}
		}
	}

	// Read body
	var body []byte
	if isChunked {
		body, err = c.readChunkedBody(reader)
	} else if contentLength > 0 {
		body = make([]byte, contentLength)
		_, err = io.ReadFull(reader, body)
	} else {
		body, err = io.ReadAll(reader)
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return &types.HTTPResponse{
		StatusCode:    statusCode,
		Status:        status,
		Headers:       headers,
		Body:          string(body),
		ContentLength: len(body),
	}, nil
}

// readChunkedBody reads a chunked response body
func (c *ChunkedClient) readChunkedBody(reader *bufio.Reader) ([]byte, error) {
	var body []byte

	for {
		// Read chunk size
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return body, err
		}
		sizeLine = strings.TrimSpace(sizeLine)

		// Parse chunk size (hex)
		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil {
			return body, err
		}

		if size == 0 {
			break
		}

		// Read chunk data
		chunk := make([]byte, size)
		_, err = io.ReadFull(reader, chunk)
		if err != nil {
			return body, err
		}
		body = append(body, chunk...)

		// Read trailing \r\n
		reader.ReadString('\n')
	}

	return body, nil
}

// parseURL extracts host, path, and TLS flag from URL
func parseURL(url string) (host, path string, useTLS bool, err error) {
	// Handle scheme
	if strings.HasPrefix(url, "https://") {
		useTLS = true
		url = url[8:]
	} else if strings.HasPrefix(url, "http://") {
		useTLS = false
		url = url[7:]
	} else {
		useTLS = false
	}

	// Split host and path
	slashIdx := strings.Index(url, "/")
	if slashIdx == -1 {
		host = url
		path = "/"
	} else {
		host = url[:slashIdx]
		path = url[slashIdx:]
	}

	// Add default port
	if !strings.Contains(host, ":") {
		if useTLS {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	return host, path, useTLS, nil
}

// ChunkedMutator generates chunked transfer mutations
type ChunkedMutator struct {
	config ChunkedOptions
}

// NewChunkedMutator creates a new chunked mutator
func NewChunkedMutator(config ChunkedOptions) *ChunkedMutator {
	return &ChunkedMutator{config: config}
}

// GenerateMutations returns chunked transfer variations
func (m *ChunkedMutator) GenerateMutations(body string) []ChunkedOptions {
	var mutations []ChunkedOptions

	bodyLen := len(body)

	// Single byte chunks
	singleByteChunks := make([]int, bodyLen)
	for i := range singleByteChunks {
		singleByteChunks[i] = 1
	}
	mutations = append(mutations, ChunkedOptions{
		Enabled:    true,
		ChunkSizes: singleByteChunks,
	})

	// Two-byte chunks
	if bodyLen > 2 {
		mutations = append(mutations, ChunkedOptions{
			Enabled:    true,
			ChunkSizes: []int{2},
		})
	}

	// Half and half
	if bodyLen > 4 {
		half := bodyLen / 2
		mutations = append(mutations, ChunkedOptions{
			Enabled:    true,
			ChunkSizes: []int{half, bodyLen - half},
		})
	}

	// With delays
	mutations = append(mutations, ChunkedOptions{
		Enabled:            true,
		ChunkSizes:         []int{10},
		DelayBetweenChunks: 100 * time.Millisecond,
	})

	// Invalid chunk size (leading space)
	mutations = append(mutations, ChunkedOptions{
		Enabled:          true,
		ChunkSizes:       []int{bodyLen},
		InvalidChunkSize: true,
	})

	// Zero chunk in middle
	if bodyLen > 10 {
		mutations = append(mutations, ChunkedOptions{
			Enabled:           true,
			ChunkSizes:        []int{5},
			ZeroChunkInMiddle: true,
		})
	}

	// With trailer headers
	mutations = append(mutations, ChunkedOptions{
		Enabled:        true,
		ChunkSizes:     []int{bodyLen},
		TrailerHeaders: map[string]string{"X-Checksum": "0"},
	})

	return mutations
}
