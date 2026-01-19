package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// AnthropicProvider implements the Provider interface for Anthropic Claude
type AnthropicProvider struct {
	BaseProvider
	client  *http.Client
	baseURL string
}

// AnthropicRequest represents an Anthropic API request
type AnthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Messages    []AnthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	Temperature float64            `json:"temperature,omitempty"`
}

// AnthropicMessage represents a message
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicResponse represents an Anthropic API response
type AnthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence string                  `json:"stop_sequence"`
	Usage        AnthropicUsage          `json:"usage"`
}

// AnthropicContentBlock represents a content block
type AnthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AnthropicUsage represents token usage
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnthropicError represents an API error
type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(config types.ProviderConfig) (*AnthropicProvider, error) {
	if config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	// Set default model if not specified
	if config.Model == "" {
		config.Model = "claude-sonnet-4-20250514"
	}

	// Set default max tokens if not specified
	if config.MaxTokens == 0 {
		config.MaxTokens = 8192
	}

	return &AnthropicProvider{
		BaseProvider: BaseProvider{config: config},
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
		baseURL: baseURL,
	}, nil
}

// Analyze sends a prompt to Anthropic and returns the response
func (p *AnthropicProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with a system message
func (p *AnthropicProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	req := AnthropicRequest{
		Model:     p.config.Model,
		MaxTokens: p.config.MaxTokens,
		Messages: []AnthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	if system != "" {
		req.System = system
	}

	if p.config.Temperature > 0 {
		req.Temperature = p.config.Temperature
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrRateLimited
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error AnthropicError `json:"error"`
		}
		if err := json.Unmarshal(respBody, &apiErr); err == nil {
			return "", fmt.Errorf("anthropic error: %s - %s", apiErr.Error.Type, apiErr.Error.Message)
		}
		return "", fmt.Errorf("anthropic error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(anthropicResp.Content) == 0 {
		return "", fmt.Errorf("%w: no content returned", ErrProviderError)
	}

	// Extract text from content blocks
	var result string
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			result += block.Text
		}
	}

	return result, nil
}

// AnalyzeStructured sends a prompt and parses the response as JSON
func (p *AnthropicProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}
