// Package llm provides LLM provider implementations for AI-powered bypass generation
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Provider defines the interface for LLM providers
type Provider interface {
	// Analyze sends a prompt and returns the response
	Analyze(ctx context.Context, prompt string) (string, error)

	// AnalyzeStructured sends a prompt and parses response into a struct
	AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error

	// AnalyzeWithSystem sends a prompt with a system message
	AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error)

	// Name returns the provider name
	Name() string

	// Model returns the model being used
	Model() string
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	Model       string    `json:"model,omitempty"`
}

// ChatResponse represents a chat completion response
type ChatResponse struct {
	Content      string `json:"content"`
	FinishReason string `json:"finish_reason,omitempty"`
	Usage        *Usage `json:"usage,omitempty"`
}

// Usage tracks token usage
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Errors
var (
	ErrNoAPIKey       = errors.New("API key not configured")
	ErrInvalidConfig  = errors.New("invalid provider configuration")
	ErrProviderError  = errors.New("provider returned an error")
	ErrRateLimited    = errors.New("rate limited by provider")
	ErrContextTooLong = errors.New("context length exceeded")
	ErrInvalidJSON    = errors.New("failed to parse response as JSON")
)

// NewProvider creates a new LLM provider based on configuration
func NewProvider(config types.ProviderConfig) (Provider, error) {
	switch config.Name {
	case "openai":
		return NewOpenAIProvider(config)
	case "anthropic":
		return NewAnthropicProvider(config)
	case "ollama":
		return NewOllamaProvider(config)
	case "lmstudio":
		return NewLMStudioProvider(config)
	case "groq":
		return NewGroqProvider(config)
	default:
		return nil, fmt.Errorf("%w: unknown provider %s", ErrInvalidConfig, config.Name)
	}
}

// NewProviderWithEnsemble creates a provider, potentially an ensemble
func NewProviderWithEnsemble(config types.ProviderConfig) (Provider, error) {
	if config.Ensemble.Enabled && len(config.Ensemble.Providers) > 0 {
		return NewEnsembleProvider(config)
	}
	return NewProvider(config)
}

// BaseProvider provides common functionality for providers
type BaseProvider struct {
	config types.ProviderConfig
}

// Name returns the provider name
func (p *BaseProvider) Name() string {
	return p.config.Name
}

// Model returns the configured model
func (p *BaseProvider) Model() string {
	return p.config.Model
}

// ParseJSONResponse attempts to parse a JSON response from LLM output
func ParseJSONResponse(content string, result interface{}) error {
	// Try to find JSON in the response (sometimes LLMs wrap it in markdown)
	start := findJSONStart(content)
	end := findJSONEnd(content, start)

	if start == -1 || end == -1 {
		// Try parsing the whole content
		if err := json.Unmarshal([]byte(content), result); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
		return nil
	}

	jsonStr := content[start : end+1]
	if err := json.Unmarshal([]byte(jsonStr), result); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return nil
}

// findJSONStart finds the start of JSON content
func findJSONStart(s string) int {
	for i, c := range s {
		if c == '{' || c == '[' {
			return i
		}
	}
	return -1
}

// findJSONEnd finds the end of JSON content
func findJSONEnd(s string, start int) int {
	if start == -1 || start >= len(s) {
		return -1
	}

	openChar := s[start]
	closeChar := byte('}')
	if openChar == '[' {
		closeChar = ']'
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		c := s[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' && inString {
			escaped = true
			continue
		}

		if c == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if c == openChar {
			depth++
		} else if c == closeChar {
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}
