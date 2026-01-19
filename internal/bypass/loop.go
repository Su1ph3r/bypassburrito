package bypass

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/su1ph3r/bypassburrito/internal/bypass/strategies"
	"github.com/su1ph3r/bypassburrito/internal/llm"
	"github.com/su1ph3r/bypassburrito/internal/waf"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// BypassLoop orchestrates iterative bypass generation
type BypassLoop struct {
	llmProvider llm.Provider
	wafDetector *waf.Detector
	httpClient  HTTPClient
	mutators    []strategies.Mutator
	analyzer    *ResponseAnalyzer
	config      types.BypassConfig

	// Event subscribers
	mu          sync.RWMutex
	subscribers map[string][]chan *BypassEvent
}

// HTTPClient interface for HTTP operations
type HTTPClient interface {
	Do(ctx context.Context, req *types.HTTPRequest) (*types.HTTPResponse, error)
}

// BypassEvent represents an event during bypass execution
type BypassEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// NewBypassLoop creates a new bypass loop orchestrator
func NewBypassLoop(
	provider llm.Provider,
	detector *waf.Detector,
	client HTTPClient,
	config types.BypassConfig,
) *BypassLoop {
	// Create mutators from config
	mutators := strategies.CreateMutatorsFromConfig(config.Strategies)

	return &BypassLoop{
		llmProvider: provider,
		wafDetector: detector,
		httpClient:  client,
		mutators:    mutators,
		analyzer:    NewResponseAnalyzer(),
		config:      config,
		subscribers: make(map[string][]chan *BypassEvent),
	}
}

// Run executes the bypass loop for a single payload
func (b *BypassLoop) Run(ctx context.Context, req types.BypassRequest) (*types.BypassResult, error) {
	result := &types.BypassResult{
		ID:              req.ID,
		OriginalPayload: req.Payloads[0], // Start with first payload
		AllAttempts:     []types.BypassAttempt{},
		Success:         false,
	}

	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	// Detect WAF if enabled
	if b.config.DetectWAF {
		wafResult, err := b.detectWAF(ctx, req.Target)
		if err == nil && wafResult.Detected {
			result.WAFDetected = wafResult.Fingerprint
			b.emit(req.ID, "waf_detected", wafResult.Fingerprint)
		}
	}

	// Process each base payload
	for _, basePayload := range req.Payloads {
		// Check if we already found a bypass
		if result.Success && !req.Options.Aggressive {
			break
		}

		payloadResult := b.processPayload(ctx, req, basePayload, result.WAFDetected)
		result.AllAttempts = append(result.AllAttempts, payloadResult.AllAttempts...)

		if payloadResult.Success {
			result.Success = true
			result.SuccessfulBypass = payloadResult.SuccessfulBypass
		}
	}

	result.TotalIterations = len(result.AllAttempts)

	// Generate curl command for successful bypass
	if result.SuccessfulBypass != nil && result.SuccessfulBypass.Request != nil {
		curl := types.GenerateCurlCommand(result.SuccessfulBypass.Request)
		result.CurlCommand = curl.Command
	}

	return result, nil
}

// processPayload processes a single base payload through iterations
func (b *BypassLoop) processPayload(
	ctx context.Context,
	req types.BypassRequest,
	basePayload types.Payload,
	wafFingerprint *types.WAFFingerprint,
) *types.BypassResult {
	result := &types.BypassResult{
		OriginalPayload: basePayload,
		AllAttempts:     []types.BypassAttempt{},
		Success:         false,
	}

	// Track tried mutations
	triedMutations := make(map[string]bool)
	currentPayload := basePayload.Value

	for iteration := 0; iteration < b.config.MaxIterations; iteration++ {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		b.emit(req.ID, "iteration_start", map[string]interface{}{
			"iteration": iteration,
			"payload":   currentPayload,
		})

		// Try the current payload
		attempt := b.tryPayload(ctx, req.Target, currentPayload, iteration, basePayload.Type)
		result.AllAttempts = append(result.AllAttempts, attempt)

		b.emit(req.ID, "attempt_complete", attempt)

		// Check if bypass succeeded
		if attempt.Result == types.ResultBypassed {
			result.Success = true
			result.SuccessfulBypass = &attempt
			b.emit(req.ID, "bypass_found", attempt)
			return result
		}

		// If blocked, generate mutations
		if attempt.Result == types.ResultBlocked {
			// Mark current mutations as tried
			for _, m := range attempt.Mutations {
				triedMutations[m] = true
			}

			// Generate next payload using LLM and mutations
			nextPayload, mutations, err := b.generateNextPayload(
				ctx, currentPayload, attempt, wafFingerprint, triedMutations,
			)
			if err != nil {
				// Fallback to mutation-only approach
				nextPayload, mutations = b.applyMutations(currentPayload, triedMutations)
			}

			if nextPayload == "" || nextPayload == currentPayload {
				// No new variations possible, move on
				break
			}

			attempt.LLMReasoning = fmt.Sprintf("Mutations applied: %v", mutations)
			currentPayload = nextPayload
		}
	}

	return result
}

// tryPayload attempts a single payload
func (b *BypassLoop) tryPayload(
	ctx context.Context,
	target types.TargetConfig,
	payload string,
	iteration int,
	attackType types.AttackType,
) types.BypassAttempt {
	attempt := types.BypassAttempt{
		Iteration: iteration,
		Payload: types.Payload{
			Value: payload,
			Type:  attackType,
		},
		Mutations: []string{},
		Timestamp: time.Now(),
	}

	start := time.Now()

	// Build request with payload
	req := b.buildRequest(target, payload)
	attempt.Request = req

	// Execute request
	resp, err := b.httpClient.Do(ctx, req)
	attempt.Duration = time.Since(start)

	if err != nil {
		attempt.Result = types.ResultError
		attempt.BlockReason = err.Error()
		return attempt
	}

	attempt.Response = resp

	// Analyze response
	analysis := b.analyzer.Analyze(resp)
	attempt.Result = b.classifyResult(analysis)
	attempt.BlockReason = analysis.ErrorMessage

	if analysis.BlockIndicators != nil && len(analysis.BlockIndicators) > 0 {
		attempt.TriggerPattern = analysis.BlockIndicators[0].Pattern
	}

	return attempt
}

// buildRequest builds an HTTP request with the payload
func (b *BypassLoop) buildRequest(target types.TargetConfig, payload string) *types.HTTPRequest {
	req := &types.HTTPRequest{
		Method:      target.Method,
		URL:         target.URL,
		Headers:     make(map[string]string),
		Cookies:     target.Cookies,
		ContentType: target.ContentType,
		Timestamp:   time.Now(),
	}

	// Copy headers
	for k, v := range target.Headers {
		req.Headers[k] = v
	}

	// Add auth header if present
	if target.AuthHeader != "" {
		req.Headers["Authorization"] = target.AuthHeader
	}

	// Insert payload based on position
	switch target.Position {
	case types.PositionQuery:
		if req.Method == "GET" {
			// Add to URL
			if target.Parameter != "" {
				separator := "?"
				if contains(req.URL, "?") {
					separator = "&"
				}
				req.URL = req.URL + separator + target.Parameter + "=" + payload
			}
		}
	case types.PositionBody:
		req.Body = injectIntoBody(target.Body, target.Parameter, payload, target.ContentType)
	case types.PositionHeader:
		req.Headers[target.Parameter] = payload
	case types.PositionCookie:
		if req.Cookies == nil {
			req.Cookies = make(map[string]string)
		}
		req.Cookies[target.Parameter] = payload
	case types.PositionPath:
		req.URL = replacePathParam(req.URL, target.Parameter, payload)
	}

	return req
}

// generateNextPayload uses LLM to generate the next payload
func (b *BypassLoop) generateNextPayload(
	ctx context.Context,
	currentPayload string,
	lastAttempt types.BypassAttempt,
	wafFingerprint *types.WAFFingerprint,
	triedMutations map[string]bool,
) (string, []string, error) {
	if b.llmProvider == nil {
		return "", nil, fmt.Errorf("no LLM provider configured")
	}

	prompt := b.buildBypassPrompt(currentPayload, lastAttempt, wafFingerprint, triedMutations)

	var suggestion types.BypassSuggestion
	err := b.llmProvider.AnalyzeStructured(ctx, prompt, &suggestion)
	if err != nil {
		return "", nil, err
	}

	return suggestion.Payload.Value, suggestion.Mutations, nil
}

// applyMutations applies registered mutators to generate variations
func (b *BypassLoop) applyMutations(payload string, tried map[string]bool) (string, []string) {
	for _, mutator := range b.mutators {
		results := mutator.Mutate(payload)
		for _, r := range results {
			if !tried[r.Mutation] && r.Payload != payload {
				return r.Payload, []string{r.Mutation}
			}
		}
	}
	return "", nil
}

// buildBypassPrompt builds the LLM prompt for bypass generation
func (b *BypassLoop) buildBypassPrompt(
	payload string,
	lastAttempt types.BypassAttempt,
	wafFingerprint *types.WAFFingerprint,
	triedMutations map[string]bool,
) string {
	wafType := "unknown"
	if wafFingerprint != nil {
		wafType = string(wafFingerprint.Type)
	}

	tried := make([]string, 0, len(triedMutations))
	for m := range triedMutations {
		tried = append(tried, m)
	}

	return fmt.Sprintf(`Analyze this blocked payload and generate a WAF bypass variant:

**Original Payload:** %s
**Attack Type:** %s
**WAF Type:** %s

**Block Analysis:**
- Response status: %d
- Block reason: %s
- Trigger pattern: %s

**Mutations Already Tried:** %v

Generate a bypass variant that:
1. Targets a different detection vector
2. Uses mutations not yet tried
3. Maintains payload functionality

Return JSON:
{
    "payload": {"value": "<bypass variant>", "type": "%s"},
    "mutations": ["<mutation1>", "<mutation2>"],
    "reasoning": "<why this might bypass>",
    "confidence": <0.0-1.0>
}`,
		payload,
		lastAttempt.Payload.Type,
		wafType,
		lastAttempt.Response.StatusCode,
		lastAttempt.BlockReason,
		lastAttempt.TriggerPattern,
		tried,
		lastAttempt.Payload.Type,
	)
}

// detectWAF performs WAF detection
func (b *BypassLoop) detectWAF(ctx context.Context, target types.TargetConfig) (*types.WAFDetectionResult, error) {
	// Make a baseline request
	req := &types.HTTPRequest{
		Method:    target.Method,
		URL:       target.URL,
		Headers:   target.Headers,
		Cookies:   target.Cookies,
		Timestamp: time.Now(),
	}

	resp, err := b.httpClient.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	return b.wafDetector.Detect(resp), nil
}

// classifyResult classifies the response analysis into a result
func (b *BypassLoop) classifyResult(analysis *types.ResponseAnalysis) types.AttemptResult {
	switch analysis.Classification {
	case types.ClassificationBlocked:
		return types.ResultBlocked
	case types.ClassificationAllowed:
		return types.ResultBypassed
	case types.ClassificationError:
		return types.ResultError
	default:
		return types.ResultUnknown
	}
}

// Subscribe subscribes to events for a specific bypass operation
func (b *BypassLoop) Subscribe(id string) <-chan *BypassEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan *BypassEvent, 100)
	b.subscribers[id] = append(b.subscribers[id], ch)
	return ch
}

// Unsubscribe unsubscribes from events
func (b *BypassLoop) Unsubscribe(id string, ch <-chan *BypassEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	subs := b.subscribers[id]
	for i, s := range subs {
		if s == ch {
			b.subscribers[id] = append(subs[:i], subs[i+1:]...)
			close(s)
			break
		}
	}
}

// emit sends an event to all subscribers
func (b *BypassLoop) emit(id, eventType string, data interface{}) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	event := &BypassEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	for _, ch := range b.subscribers[id] {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr) >= 0))
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func injectIntoBody(body, param, payload, contentType string) string {
	if body == "" {
		// Create new body
		switch contentType {
		case "application/json":
			return fmt.Sprintf(`{"%s":"%s"}`, param, payload)
		default:
			return fmt.Sprintf("%s=%s", param, payload)
		}
	}

	// Inject into existing body
	// This is simplified - a real implementation would properly parse and modify
	return body
}

func replacePathParam(url, param, value string) string {
	// Replace {param} or :param with value
	result := url
	result = replaceAll(result, "{"+param+"}", value)
	result = replaceAll(result, ":"+param, value)
	return result
}

func replaceAll(s, old, new string) string {
	for {
		i := findSubstring(s, old)
		if i < 0 {
			return s
		}
		s = s[:i] + new + s[i+len(old):]
	}
}

// GenerateID generates a unique ID for a bypass request
func GenerateID() string {
	return uuid.New().String()
}
