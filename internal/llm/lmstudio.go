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

// LMStudioProvider implements the Provider interface for LM Studio (OpenAI-compatible)
type LMStudioProvider struct {
	BaseProvider
	client  *http.Client
	baseURL string
}

// LMStudioRequest represents an LM Studio chat request (OpenAI-compatible)
type LMStudioRequest struct {
	Model       string            `json:"model"`
	Messages    []LMStudioMessage `json:"messages"`
	MaxTokens   int               `json:"max_tokens,omitempty"`
	Temperature float64           `json:"temperature,omitempty"`
	Stream      bool              `json:"stream"`
}

// LMStudioMessage represents a message in LM Studio format
type LMStudioMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LMStudioResponse represents an LM Studio chat response
type LMStudioResponse struct {
	ID      string           `json:"id"`
	Object  string           `json:"object"`
	Created int64            `json:"created"`
	Model   string           `json:"model"`
	Choices []LMStudioChoice `json:"choices"`
	Usage   *LMStudioUsage   `json:"usage,omitempty"`
}

// LMStudioChoice represents a choice in the response
type LMStudioChoice struct {
	Index        int             `json:"index"`
	Message      LMStudioMessage `json:"message"`
	FinishReason string          `json:"finish_reason"`
}

// LMStudioUsage represents token usage
type LMStudioUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// NewLMStudioProvider creates a new LM Studio provider
func NewLMStudioProvider(config types.ProviderConfig) (*LMStudioProvider, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:1234/v1"
	}

	// Set default model if not specified
	if config.Model == "" {
		config.Model = "local-model"
	}

	return &LMStudioProvider{
		BaseProvider: BaseProvider{config: config},
		client: &http.Client{
			Timeout: 5 * time.Minute, // Long timeout for local inference
		},
		baseURL: baseURL,
	}, nil
}

// Analyze sends a prompt to LM Studio and returns the response
func (p *LMStudioProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with a system message
func (p *LMStudioProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	messages := []LMStudioMessage{}

	if system != "" {
		messages = append(messages, LMStudioMessage{
			Role:    "system",
			Content: system,
		})
	}

	messages = append(messages, LMStudioMessage{
		Role:    "user",
		Content: prompt,
	})

	req := LMStudioRequest{
		Model:       p.config.Model,
		Messages:    messages,
		MaxTokens:   p.config.MaxTokens,
		Temperature: p.config.Temperature,
		Stream:      false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// LM Studio may require auth header for some configurations
	if p.config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("lmstudio request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("lmstudio error (status %d): %s", resp.StatusCode, string(body))
	}

	var chatResp LMStudioResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("%w: no choices returned", ErrProviderError)
	}

	return chatResp.Choices[0].Message.Content, nil
}

// AnalyzeStructured sends a prompt and parses the response as JSON
func (p *LMStudioProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}
