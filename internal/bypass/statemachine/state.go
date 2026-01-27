// Package statemachine provides multi-request stateful attack sequence support
package statemachine

import (
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// MachineState holds the current execution state
type MachineState struct {
	CurrentStep   string            `json:"current_step" yaml:"current_step"`
	Variables     map[string]string `json:"variables" yaml:"variables"`
	Cookies       map[string]string `json:"cookies" yaml:"cookies"`
	Headers       map[string]string `json:"headers" yaml:"headers"`
	StepHistory   []StepResult      `json:"step_history" yaml:"step_history"`
	StartTime     time.Time         `json:"start_time" yaml:"start_time"`
	TotalRequests int               `json:"total_requests" yaml:"total_requests"`
	LastResponse  *types.HTTPResponse `json:"last_response,omitempty" yaml:"last_response,omitempty"`
}

// NewMachineState creates a new machine state with initialized maps
func NewMachineState() *MachineState {
	return &MachineState{
		Variables:   make(map[string]string),
		Cookies:     make(map[string]string),
		Headers:     make(map[string]string),
		StepHistory: make([]StepResult, 0),
		StartTime:   time.Now(),
	}
}

// GetVariable retrieves a variable value
func (s *MachineState) GetVariable(name string) (string, bool) {
	val, ok := s.Variables[name]
	return val, ok
}

// SetVariable sets a variable value
func (s *MachineState) SetVariable(name, value string) {
	s.Variables[name] = value
}

// AddCookie adds a cookie to the state
func (s *MachineState) AddCookie(name, value string) {
	s.Cookies[name] = value
}

// AddHeader adds a header to the state
func (s *MachineState) AddHeader(name, value string) {
	s.Headers[name] = value
}

// RecordStep adds a step result to history
func (s *MachineState) RecordStep(result StepResult) {
	s.StepHistory = append(s.StepHistory, result)
	s.TotalRequests++
}

// Clone creates a deep copy of the state
func (s *MachineState) Clone() *MachineState {
	clone := &MachineState{
		CurrentStep:   s.CurrentStep,
		Variables:     make(map[string]string),
		Cookies:       make(map[string]string),
		Headers:       make(map[string]string),
		StepHistory:   make([]StepResult, len(s.StepHistory)),
		StartTime:     s.StartTime,
		TotalRequests: s.TotalRequests,
		LastResponse:  s.LastResponse,
	}

	for k, v := range s.Variables {
		clone.Variables[k] = v
	}
	for k, v := range s.Cookies {
		clone.Cookies[k] = v
	}
	for k, v := range s.Headers {
		clone.Headers[k] = v
	}
	copy(clone.StepHistory, s.StepHistory)

	return clone
}

// StepResult holds the result of one step
type StepResult struct {
	StepID        string              `json:"step_id" yaml:"step_id"`
	StepName      string              `json:"step_name" yaml:"step_name"`
	Success       bool                `json:"success" yaml:"success"`
	Request       *types.HTTPRequest  `json:"request,omitempty" yaml:"request,omitempty"`
	Response      *types.HTTPResponse `json:"response,omitempty" yaml:"response,omitempty"`
	ExtractedVars map[string]string   `json:"extracted_vars,omitempty" yaml:"extracted_vars,omitempty"`
	Duration      time.Duration       `json:"duration" yaml:"duration"`
	Error         string              `json:"error,omitempty" yaml:"error,omitempty"`
	Timestamp     time.Time           `json:"timestamp" yaml:"timestamp"`
}

// SequenceResult holds the complete sequence execution result
type SequenceResult struct {
	SequenceID    string        `json:"sequence_id" yaml:"sequence_id"`
	SequenceName  string        `json:"sequence_name" yaml:"sequence_name"`
	Success       bool          `json:"success" yaml:"success"`
	FinalState    *MachineState `json:"final_state" yaml:"final_state"`
	StepResults   []StepResult  `json:"step_results" yaml:"step_results"`
	TotalDuration time.Duration `json:"total_duration" yaml:"total_duration"`
	BypassFound   bool          `json:"bypass_found" yaml:"bypass_found"`
	BypassStep    string        `json:"bypass_step,omitempty" yaml:"bypass_step,omitempty"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
}
