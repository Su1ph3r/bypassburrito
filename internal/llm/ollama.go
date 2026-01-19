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

// OllamaProvider implements the Provider interface for Ollama
type OllamaProvider struct {
	BaseProvider
	client  *http.Client
	baseURL string
}

// OllamaChatRequest represents an Ollama chat request
type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *OllamaOptions  `json:"options,omitempty"`
}

// OllamaMessage represents a message in Ollama format
type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OllamaOptions represents Ollama-specific options
type OllamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

// OllamaChatResponse represents an Ollama chat response
type OllamaChatResponse struct {
	Model     string        `json:"model"`
	CreatedAt string        `json:"created_at"`
	Message   OllamaMessage `json:"message"`
	Done      bool          `json:"done"`
}

// NewOllamaProvider creates a new Ollama provider
func NewOllamaProvider(config types.ProviderConfig) (*OllamaProvider, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	// Set default model if not specified
	if config.Model == "" {
		config.Model = "llama3"
	}

	return &OllamaProvider{
		BaseProvider: BaseProvider{config: config},
		client: &http.Client{
			Timeout: 5 * time.Minute, // Long timeout for local inference
		},
		baseURL: baseURL,
	}, nil
}

// Analyze sends a prompt to Ollama and returns the response
func (p *OllamaProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with a system message
func (p *OllamaProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	messages := []OllamaMessage{}

	if system != "" {
		messages = append(messages, OllamaMessage{
			Role:    "system",
			Content: system,
		})
	}

	messages = append(messages, OllamaMessage{
		Role:    "user",
		Content: prompt,
	})

	req := OllamaChatRequest{
		Model:    p.config.Model,
		Messages: messages,
		Stream:   false,
	}

	if p.config.Temperature > 0 || p.config.MaxTokens > 0 {
		req.Options = &OllamaOptions{
			Temperature: p.config.Temperature,
			NumPredict:  p.config.MaxTokens,
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama error (status %d): %s", resp.StatusCode, string(body))
	}

	var chatResp OllamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return chatResp.Message.Content, nil
}

// AnalyzeStructured sends a prompt and parses the response as JSON
func (p *OllamaProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}
