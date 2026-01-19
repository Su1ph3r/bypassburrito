package llm

import (
	"context"
	"fmt"

	"github.com/sashabaranov/go-openai"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// OpenAIProvider implements the Provider interface for OpenAI
type OpenAIProvider struct {
	BaseProvider
	client *openai.Client
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(config types.ProviderConfig) (*OpenAIProvider, error) {
	if config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	clientConfig := openai.DefaultConfig(config.APIKey)
	if config.BaseURL != "" {
		clientConfig.BaseURL = config.BaseURL
	}

	// Set default model if not specified
	if config.Model == "" {
		config.Model = "gpt-4o"
	}

	// Set default max tokens if not specified
	if config.MaxTokens == 0 {
		config.MaxTokens = 8192
	}

	return &OpenAIProvider{
		BaseProvider: BaseProvider{config: config},
		client:       openai.NewClientWithConfig(clientConfig),
	}, nil
}

// Analyze sends a prompt to OpenAI and returns the response
func (p *OpenAIProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with a system message
func (p *OpenAIProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	messages := []openai.ChatCompletionMessage{}

	if system != "" {
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: system,
		})
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: prompt,
	})

	req := openai.ChatCompletionRequest{
		Model:       p.config.Model,
		Messages:    messages,
		MaxTokens:   p.config.MaxTokens,
		Temperature: float32(p.config.Temperature),
	}

	resp, err := p.client.CreateChatCompletion(ctx, req)
	if err != nil {
		// Check for rate limiting
		if apiErr, ok := err.(*openai.APIError); ok && apiErr.HTTPStatusCode == 429 {
			return "", ErrRateLimited
		}
		return "", fmt.Errorf("openai error: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("%w: no choices returned", ErrProviderError)
	}

	return resp.Choices[0].Message.Content, nil
}

// AnalyzeStructured sends a prompt and parses the response as JSON
func (p *OpenAIProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}
