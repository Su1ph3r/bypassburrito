package statemachine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AttackSequence defines a multi-step attack
type AttackSequence struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Author      string            `json:"author,omitempty" yaml:"author,omitempty"`
	Steps       []SequenceStep    `json:"steps" yaml:"steps"`
	Variables   map[string]string `json:"variables,omitempty" yaml:"variables,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// SequenceStep represents one step in an attack sequence
type SequenceStep struct {
	ID             string              `json:"id" yaml:"id"`
	Name           string              `json:"name" yaml:"name"`
	Description    string              `json:"description,omitempty" yaml:"description,omitempty"`
	Method         string              `json:"method" yaml:"method"`
	Path           string              `json:"path" yaml:"path"`
	Headers        map[string]string   `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body           string              `json:"body,omitempty" yaml:"body,omitempty"`
	ContentType    string              `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	PayloadPosition string             `json:"payload_position,omitempty" yaml:"payload_position,omitempty"`
	ExpectedStatus []int               `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	ExtractVars    []VariableExtractor `json:"extract_vars,omitempty" yaml:"extract_vars,omitempty"`
	Conditions     []Condition         `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	OnSuccess      string              `json:"on_success,omitempty" yaml:"on_success,omitempty"`
	OnFailure      string              `json:"on_failure,omitempty" yaml:"on_failure,omitempty"`
	MaxRetries     int                 `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
	DelayMs        int                 `json:"delay_ms,omitempty" yaml:"delay_ms,omitempty"`
}

// VariableExtractor defines how to extract values from responses
type VariableExtractor struct {
	Name     string `json:"name" yaml:"name"`
	Source   string `json:"source" yaml:"source"` // "body", "header", "cookie", "status"
	Pattern  string `json:"pattern" yaml:"pattern"`
	JSONPath string `json:"jsonpath,omitempty" yaml:"jsonpath,omitempty"`
	Default  string `json:"default,omitempty" yaml:"default,omitempty"`
}

// Condition defines a condition for branching
type Condition struct {
	Variable string `json:"variable" yaml:"variable"`
	Operator string `json:"operator" yaml:"operator"` // "eq", "ne", "contains", "matches", "gt", "lt", "exists"
	Value    string `json:"value" yaml:"value"`
	NextStep string `json:"next_step,omitempty" yaml:"next_step,omitempty"`
}

// LoadSequence loads a sequence from a YAML file
func LoadSequence(path string) (*AttackSequence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read sequence file: %w", err)
	}

	var seq AttackSequence
	if err := yaml.Unmarshal(data, &seq); err != nil {
		return nil, fmt.Errorf("failed to parse sequence YAML: %w", err)
	}

	// Validate the sequence
	if err := seq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sequence: %w", err)
	}

	return &seq, nil
}

// LoadSequencesFromDir loads all sequences from a directory
func LoadSequencesFromDir(dir string) ([]*AttackSequence, error) {
	var sequences []*AttackSequence

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only load .yaml and .yml files
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		seq, err := LoadSequence(path)
		if err != nil {
			// Log but don't fail on individual file errors
			fmt.Printf("Warning: failed to load %s: %v\n", path, err)
			return nil
		}

		sequences = append(sequences, seq)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return sequences, nil
}

// Validate checks if the sequence is valid
func (s *AttackSequence) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("sequence ID is required")
	}
	if s.Name == "" {
		return fmt.Errorf("sequence name is required")
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("sequence must have at least one step")
	}

	stepIDs := make(map[string]bool)
	for i, step := range s.Steps {
		if step.ID == "" {
			return fmt.Errorf("step %d: ID is required", i)
		}
		if stepIDs[step.ID] {
			return fmt.Errorf("step %d: duplicate ID '%s'", i, step.ID)
		}
		stepIDs[step.ID] = true

		if step.Method == "" {
			return fmt.Errorf("step %s: method is required", step.ID)
		}
		if step.Path == "" {
			return fmt.Errorf("step %s: path is required", step.ID)
		}

		// Validate step references
		if step.OnSuccess != "" && step.OnSuccess != "complete" && !stepIDs[step.OnSuccess] {
			// Allow forward references by checking all steps
			found := false
			for _, s := range s.Steps {
				if s.ID == step.OnSuccess {
					found = true
					break
				}
			}
			if !found && step.OnSuccess != "complete" {
				return fmt.Errorf("step %s: on_success references unknown step '%s'", step.ID, step.OnSuccess)
			}
		}
	}

	return nil
}

// GetStep returns a step by ID
func (s *AttackSequence) GetStep(id string) *SequenceStep {
	for i := range s.Steps {
		if s.Steps[i].ID == id {
			return &s.Steps[i]
		}
	}
	return nil
}

// GetNextStep returns the next step to execute based on current step and success
func (s *AttackSequence) GetNextStep(currentID string, success bool) *SequenceStep {
	current := s.GetStep(currentID)
	if current == nil {
		return nil
	}

	var nextID string
	if success {
		nextID = current.OnSuccess
	} else {
		nextID = current.OnFailure
	}

	// Handle special values
	if nextID == "" || nextID == "complete" {
		return nil
	}
	if nextID == "retry" {
		return current
	}
	if nextID == "abort" {
		return nil
	}

	return s.GetStep(nextID)
}

// GetFirstStep returns the first step in the sequence
func (s *AttackSequence) GetFirstStep() *SequenceStep {
	if len(s.Steps) == 0 {
		return nil
	}
	return &s.Steps[0]
}

// InterpolateVariables replaces {{variable}} placeholders in a string
func InterpolateVariables(template string, vars map[string]string) string {
	result := template
	for key, value := range vars {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// InterpolateStep applies variable interpolation to a step
func InterpolateStep(step *SequenceStep, vars map[string]string) *SequenceStep {
	interpolated := &SequenceStep{
		ID:              step.ID,
		Name:            step.Name,
		Description:     step.Description,
		Method:          step.Method,
		Path:            InterpolateVariables(step.Path, vars),
		Body:            InterpolateVariables(step.Body, vars),
		ContentType:     step.ContentType,
		PayloadPosition: step.PayloadPosition,
		ExpectedStatus:  step.ExpectedStatus,
		ExtractVars:     step.ExtractVars,
		Conditions:      step.Conditions,
		OnSuccess:       step.OnSuccess,
		OnFailure:       step.OnFailure,
		MaxRetries:      step.MaxRetries,
		DelayMs:         step.DelayMs,
	}

	// Interpolate headers
	if step.Headers != nil {
		interpolated.Headers = make(map[string]string)
		for k, v := range step.Headers {
			interpolated.Headers[k] = InterpolateVariables(v, vars)
		}
	}

	return interpolated
}
