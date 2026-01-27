// Package solver provides automated CAPTCHA and JavaScript challenge solving
package solver

import (
	"context"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ChallengeSolver solves JavaScript and CAPTCHA challenges
type ChallengeSolver interface {
	// CanSolve checks if this solver can handle the challenge
	CanSolve(analysis *types.ResponseAnalysis) bool

	// Solve attempts to solve the challenge and returns session cookies
	Solve(ctx context.Context, url string, opts SolveOptions) (*SolveResult, error)

	// SolverType returns the type of challenges this solver handles
	SolverType() string
}

// SolveOptions configures solving behavior
type SolveOptions struct {
	Timeout        time.Duration     `json:"timeout" yaml:"timeout"`
	Proxy          string            `json:"proxy,omitempty" yaml:"proxy,omitempty"`
	UserAgent      string            `json:"user_agent" yaml:"user_agent"`
	Cookies        map[string]string `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	CaptchaAPIKey  string            `json:"captcha_api_key,omitempty" yaml:"captcha_api_key,omitempty"`
	CaptchaService string            `json:"captcha_service,omitempty" yaml:"captcha_service,omitempty"`
	Headless       bool              `json:"headless" yaml:"headless"`
	BrowserPath    string            `json:"browser_path,omitempty" yaml:"browser_path,omitempty"`
	MaxAttempts    int               `json:"max_attempts" yaml:"max_attempts"`
}

// DefaultSolveOptions returns sensible defaults
func DefaultSolveOptions() SolveOptions {
	return SolveOptions{
		Timeout:     60 * time.Second,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Headless:    true,
		MaxAttempts: 3,
	}
}

// SolveResult contains the result of challenge solving
type SolveResult struct {
	Success         bool              `json:"success"`
	Cookies         map[string]string `json:"cookies"`
	ClearanceCookie string            `json:"clearance_cookie,omitempty"`
	UserAgent       string            `json:"user_agent"`
	Duration        time.Duration     `json:"duration"`
	ChallengeType   string            `json:"challenge_type"`
	Error           string            `json:"error,omitempty"`
	Attempts        int               `json:"attempts"`
}

// SolverConfig holds solver configuration
type SolverConfig struct {
	Enabled        bool   `yaml:"enabled" mapstructure:"enabled"`
	BrowserPath    string `yaml:"browser_path" mapstructure:"browser_path"`
	Headless       bool   `yaml:"headless" mapstructure:"headless"`
	CaptchaService string `yaml:"captcha_service" mapstructure:"captcha_service"`
	CaptchaAPIKey  string `yaml:"captcha_api_key" mapstructure:"captcha_api_key"`
	MaxAttempts    int    `yaml:"max_attempts" mapstructure:"max_attempts"`
	TimeoutSeconds int    `yaml:"timeout_seconds" mapstructure:"timeout_seconds"`
}

// DefaultSolverConfig returns sensible defaults
func DefaultSolverConfig() SolverConfig {
	return SolverConfig{
		Enabled:        false,
		Headless:       true,
		CaptchaService: "",
		MaxAttempts:    3,
		TimeoutSeconds: 60,
	}
}

// ChallengeType represents the type of challenge detected
type ChallengeType string

const (
	ChallengeNone              ChallengeType = "none"
	ChallengeJavaScript        ChallengeType = "javascript"
	ChallengeCloudflare        ChallengeType = "cloudflare"
	ChallengeCloudflareTurnstile ChallengeType = "turnstile"
	ChallengeRecaptcha         ChallengeType = "recaptcha"
	ChallengeHCaptcha          ChallengeType = "hcaptcha"
	ChallengeDataDome          ChallengeType = "datadome"
	ChallengePerimeterX        ChallengeType = "perimeterx"
	ChallengeUnknown           ChallengeType = "unknown"
)

// DetectChallengeType analyzes a response to determine the challenge type
func DetectChallengeType(analysis *types.ResponseAnalysis) ChallengeType {
	if analysis == nil {
		return ChallengeNone
	}

	if !analysis.CaptchaPresent && !analysis.JSChallenge {
		return ChallengeNone
	}

	// Check for specific challenge types based on analysis
	// This would need the response body for more accurate detection
	if analysis.CaptchaPresent {
		return ChallengeRecaptcha // Default, would need body analysis for specifics
	}

	if analysis.JSChallenge {
		return ChallengeJavaScript
	}

	return ChallengeUnknown
}

// SolverManager manages multiple solvers and selects appropriate ones
type SolverManager struct {
	solvers []ChallengeSolver
	config  SolverConfig
}

// NewSolverManager creates a new solver manager
func NewSolverManager(config SolverConfig) *SolverManager {
	return &SolverManager{
		solvers: make([]ChallengeSolver, 0),
		config:  config,
	}
}

// RegisterSolver adds a solver to the manager
func (m *SolverManager) RegisterSolver(solver ChallengeSolver) {
	m.solvers = append(m.solvers, solver)
}

// FindSolver returns an appropriate solver for the given analysis
func (m *SolverManager) FindSolver(analysis *types.ResponseAnalysis) ChallengeSolver {
	for _, solver := range m.solvers {
		if solver.CanSolve(analysis) {
			return solver
		}
	}
	return nil
}

// Solve attempts to solve a challenge using registered solvers
func (m *SolverManager) Solve(ctx context.Context, url string, analysis *types.ResponseAnalysis, opts SolveOptions) (*SolveResult, error) {
	solver := m.FindSolver(analysis)
	if solver == nil {
		return &SolveResult{
			Success:       false,
			ChallengeType: string(DetectChallengeType(analysis)),
			Error:         "no suitable solver found",
		}, nil
	}

	return solver.Solve(ctx, url, opts)
}
