package statemachine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// HTTPClient interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// StateMachine orchestrates multi-request attack sequences
type StateMachine struct {
	client    HTTPClient
	config    MachineConfig
	state     *MachineState
	baseURL   string
	userAgent string
}

// MachineConfig holds state machine configuration
type MachineConfig struct {
	MaxSteps         int           `yaml:"max_steps" mapstructure:"max_steps"`
	DefaultTimeout   time.Duration `yaml:"default_timeout" mapstructure:"default_timeout"`
	PreserveSession  bool          `yaml:"preserve_session" mapstructure:"preserve_session"`
	StopOnBypass     bool          `yaml:"stop_on_bypass" mapstructure:"stop_on_bypass"`
	DefaultUserAgent string        `yaml:"default_user_agent" mapstructure:"default_user_agent"`
}

// DefaultMachineConfig returns sensible defaults
func DefaultMachineConfig() MachineConfig {
	return MachineConfig{
		MaxSteps:         50,
		DefaultTimeout:   30 * time.Second,
		PreserveSession:  true,
		StopOnBypass:     true,
		DefaultUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// NewStateMachine creates a new state machine
func NewStateMachine(client HTTPClient, baseURL string, config MachineConfig) *StateMachine {
	return &StateMachine{
		client:    client,
		config:    config,
		state:     NewMachineState(),
		baseURL:   strings.TrimSuffix(baseURL, "/"),
		userAgent: config.DefaultUserAgent,
	}
}

// Execute runs a complete attack sequence
func (m *StateMachine) Execute(ctx context.Context, sequence *AttackSequence) (*SequenceResult, error) {
	start := time.Now()
	result := &SequenceResult{
		SequenceID:   sequence.ID,
		SequenceName: sequence.Name,
		StepResults:  make([]StepResult, 0),
	}

	// Initialize state with sequence variables
	if sequence.Variables != nil {
		for k, v := range sequence.Variables {
			m.state.SetVariable(k, v)
		}
	}

	// Get first step
	currentStep := sequence.GetFirstStep()
	if currentStep == nil {
		return nil, fmt.Errorf("sequence has no steps")
	}

	stepCount := 0
	for currentStep != nil {
		// Check step limit
		stepCount++
		if stepCount > m.config.MaxSteps {
			result.Error = fmt.Sprintf("exceeded max steps (%d)", m.config.MaxSteps)
			break
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			result.TotalDuration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		// Execute step
		stepResult, err := m.ExecuteStep(ctx, currentStep)
		if err != nil {
			stepResult.Error = err.Error()
			stepResult.Success = false
		}

		// Record result
		result.StepResults = append(result.StepResults, *stepResult)
		m.state.RecordStep(*stepResult)

		// Check for bypass
		if m.detectBypass(stepResult) {
			result.BypassFound = true
			result.BypassStep = currentStep.ID
			if m.config.StopOnBypass {
				result.Success = true
				break
			}
		}

		// Add delay if specified
		if currentStep.DelayMs > 0 {
			time.Sleep(time.Duration(currentStep.DelayMs) * time.Millisecond)
		}

		// Determine next step
		nextStepID := DetermineNextStep(currentStep, m.state, stepResult.Response, stepResult.Success)
		if nextStepID == "complete" || nextStepID == "" {
			result.Success = stepResult.Success
			break
		}
		if nextStepID == "abort" {
			result.Success = false
			result.Error = "sequence aborted"
			break
		}

		currentStep = sequence.GetStep(nextStepID)
	}

	result.TotalDuration = time.Since(start)
	result.FinalState = m.state.Clone()

	return result, nil
}

// ExecuteStep executes a single step in the sequence
func (m *StateMachine) ExecuteStep(ctx context.Context, step *SequenceStep) (*StepResult, error) {
	start := time.Now()
	result := &StepResult{
		StepID:        step.ID,
		StepName:      step.Name,
		ExtractedVars: make(map[string]string),
		Timestamp:     start,
	}

	// Interpolate variables in step
	interpolatedStep := InterpolateStep(step, m.state.Variables)

	// Build request
	req, err := m.buildRequest(ctx, interpolatedStep)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	// Execute request
	resp, err := m.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read body: %s", err.Error())
		result.Duration = time.Since(start)
		return result, err
	}

	// Convert to our response type
	response := &types.HTTPResponse{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       make(map[string]string),
		Body:          string(body),
		ContentLength: len(body),
		Latency:       time.Since(start),
		Timestamp:     time.Now(),
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			response.Headers[k] = strings.Join(v, ", ")
		}
	}

	result.Response = response
	result.Duration = time.Since(start)

	// Determine success based on status code
	result.Success = IsStatusSuccess(resp.StatusCode, step.ExpectedStatus)

	// Extract variables
	if len(step.ExtractVars) > 0 {
		result.ExtractedVars = ExtractVariables(step.ExtractVars, response)
		// Add to state
		for k, v := range result.ExtractedVars {
			m.state.SetVariable(k, v)
		}
	}

	// Extract and store cookies if session preservation is enabled
	if m.config.PreserveSession {
		cookies := ExtractCookiesFromResponse(response)
		for k, v := range cookies {
			m.state.AddCookie(k, v)
		}
	}

	// Store request in result
	result.Request = &types.HTTPRequest{
		Method:      interpolatedStep.Method,
		URL:         m.baseURL + interpolatedStep.Path,
		Headers:     interpolatedStep.Headers,
		Body:        interpolatedStep.Body,
		ContentType: interpolatedStep.ContentType,
		Timestamp:   start,
	}

	m.state.LastResponse = response

	return result, nil
}

// buildRequest creates an HTTP request from a step
func (m *StateMachine) buildRequest(ctx context.Context, step *SequenceStep) (*http.Request, error) {
	url := m.baseURL + step.Path

	var bodyReader io.Reader
	if step.Body != "" {
		bodyReader = strings.NewReader(step.Body)
	}

	req, err := http.NewRequestWithContext(ctx, step.Method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Add headers from step
	for k, v := range step.Headers {
		req.Header.Set(k, v)
	}

	// Add content type
	if step.ContentType != "" {
		req.Header.Set("Content-Type", step.ContentType)
	}

	// Add user agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", m.userAgent)
	}

	// Add state headers
	for k, v := range m.state.Headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Add state cookies
	if len(m.state.Cookies) > 0 {
		var cookieParts []string
		for k, v := range m.state.Cookies {
			cookieParts = append(cookieParts, k+"="+v)
		}
		existing := req.Header.Get("Cookie")
		if existing != "" {
			req.Header.Set("Cookie", existing+"; "+strings.Join(cookieParts, "; "))
		} else {
			req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
		}
	}

	return req, nil
}

// detectBypass checks if the step result indicates a successful bypass
func (m *StateMachine) detectBypass(result *StepResult) bool {
	if result.Response == nil {
		return false
	}

	// Check for success indicators
	resp := result.Response

	// Look for SQL errors (indicates SQLi worked)
	sqlErrors := []string{
		"sql syntax", "mysql", "postgresql", "oracle", "sqlite",
		"mssql", "mariadb", "odbc",
	}
	lowerBody := strings.ToLower(resp.Body)
	for _, err := range sqlErrors {
		if strings.Contains(lowerBody, err) {
			return true
		}
	}

	// Look for XSS reflection
	if strings.Contains(resp.Body, "<script") ||
		strings.Contains(resp.Body, "javascript:") ||
		strings.Contains(resp.Body, "onerror=") {
		return true
	}

	// Look for command execution
	if strings.Contains(resp.Body, "root:") ||
		strings.Contains(resp.Body, "uid=") ||
		strings.Contains(resp.Body, "[boot loader]") {
		return true
	}

	return false
}

// GetState returns the current machine state
func (m *StateMachine) GetState() *MachineState {
	return m.state
}

// Reset resets the machine to initial state
func (m *StateMachine) Reset() {
	m.state = NewMachineState()
}

// SetVariable sets a variable in the state
func (m *StateMachine) SetVariable(name, value string) {
	m.state.SetVariable(name, value)
}

// SetPayload sets the payload variable
func (m *StateMachine) SetPayload(payload string) {
	m.state.SetVariable("payload", payload)
}
