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

// GroqProvider implements the Provider interface for Groq (fast inference)
type GroqProvider struct {
	BaseProvider
	client  *http.Client
	baseURL string
}

// GroqRequest represents a Groq API request (OpenAI-compatible)
type GroqRequest struct {
	Model       string        `json:"model"`
	Messages    []GroqMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	TopP        float64       `json:"top_p,omitempty"`
	Stream      bool          `json:"stream"`
}

// GroqMessage represents a message in Groq format
type GroqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GroqResponse represents a Groq API response
type GroqResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []GroqChoice `json:"choices"`
	Usage   *GroqUsage   `json:"usage,omitempty"`
}

// GroqChoice represents a choice in the response
type GroqChoice struct {
	Index        int         `json:"index"`
	Message      GroqMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// GroqUsage represents token usage
type GroqUsage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	QueueTime        float64 `json:"queue_time"`
	PromptTime       float64 `json:"prompt_time"`
	CompletionTime   float64 `json:"completion_time"`
	TotalTime        float64 `json:"total_time"`
}

// GroqError represents a Groq API error
type GroqError struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// NewGroqProvider creates a new Groq provider
func NewGroqProvider(config types.ProviderConfig) (*GroqProvider, error) {
	if config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.groq.com/openai/v1"
	}

	// Set default model if not specified (Llama 3 70B is fast and capable)
	if config.Model == "" {
		config.Model = "llama-3.3-70b-versatile"
	}

	// Set default max tokens if not specified
	if config.MaxTokens == 0 {
		config.MaxTokens = 8192
	}

	return &GroqProvider{
		BaseProvider: BaseProvider{config: config},
		client: &http.Client{
			Timeout: 2 * time.Minute, // Groq is fast, shorter timeout
		},
		baseURL: baseURL,
	}, nil
}

// Analyze sends a prompt to Groq and returns the response
func (p *GroqProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with a system message
func (p *GroqProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	messages := []GroqMessage{}

	if system != "" {
		messages = append(messages, GroqMessage{
			Role:    "system",
			Content: system,
		})
	}

	messages = append(messages, GroqMessage{
		Role:    "user",
		Content: prompt,
	})

	req := GroqRequest{
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
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("groq request failed: %w", err)
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
		var groqErr GroqError
		if err := json.Unmarshal(respBody, &groqErr); err == nil && groqErr.Error.Message != "" {
			return "", fmt.Errorf("groq error: %s - %s", groqErr.Error.Type, groqErr.Error.Message)
		}
		return "", fmt.Errorf("groq error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var groqResp GroqResponse
	if err := json.Unmarshal(respBody, &groqResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(groqResp.Choices) == 0 {
		return "", fmt.Errorf("%w: no choices returned", ErrProviderError)
	}

	return groqResp.Choices[0].Message.Content, nil
}

// AnalyzeStructured sends a prompt and parses the response as JSON
func (p *GroqProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}
