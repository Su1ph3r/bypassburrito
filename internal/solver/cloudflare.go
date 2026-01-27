package solver

import (
	"context"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// CloudflareSolver handles Cloudflare-specific challenges
type CloudflareSolver struct {
	config      SolverConfig
	browserSolver *BrowserSolver
}

// NewCloudflareSolver creates a new Cloudflare solver
func NewCloudflareSolver(config SolverConfig) *CloudflareSolver {
	return &CloudflareSolver{
		config:        config,
		browserSolver: NewBrowserSolver(config),
	}
}

// CanSolve checks if this solver can handle Cloudflare challenges
func (c *CloudflareSolver) CanSolve(analysis *types.ResponseAnalysis) bool {
	if analysis == nil {
		return false
	}

	// Check for Cloudflare indicators
	for _, header := range analysis.WAFHeaders {
		if strings.Contains(strings.ToLower(header), "cf-ray") ||
			strings.Contains(strings.ToLower(header), "cf-cache") {
			return true
		}
	}

	// Check block indicators for Cloudflare patterns
	for _, indicator := range analysis.BlockIndicators {
		if strings.Contains(strings.ToLower(indicator.Description), "cloudflare") ||
			strings.Contains(strings.ToLower(indicator.Matched), "cf-ray") {
			return true
		}
	}

	return false
}

// SolverType returns the solver type
func (c *CloudflareSolver) SolverType() string {
	return "cloudflare"
}

// Solve attempts to solve Cloudflare challenges
func (c *CloudflareSolver) Solve(ctx context.Context, url string, opts SolveOptions) (*SolveResult, error) {
	start := time.Now()
	result := &SolveResult{
		Cookies:       make(map[string]string),
		ChallengeType: string(ChallengeCloudflare),
		UserAgent:     opts.UserAgent,
	}

	// Cloudflare challenges typically require browser execution
	// to solve their JavaScript challenge and get cf_clearance cookie

	// Use browser solver
	browserResult, err := c.browserSolver.Solve(ctx, url, opts)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	// Copy browser result
	result.Success = browserResult.Success
	result.Cookies = browserResult.Cookies
	result.Error = browserResult.Error
	result.Attempts = browserResult.Attempts

	// Look for cf_clearance cookie specifically
	if clearance, ok := browserResult.Cookies["cf_clearance"]; ok {
		result.ClearanceCookie = clearance
	}

	result.Duration = time.Since(start)
	return result, nil
}

// IsCloudflareChallenge checks if a response is a Cloudflare challenge
func IsCloudflareChallenge(body string, headers map[string]string) bool {
	// Check headers
	if _, ok := headers["cf-ray"]; ok {
		// Has Cloudflare header, check if it's a challenge
		if strings.Contains(strings.ToLower(body), "checking your browser") ||
			strings.Contains(body, "__cf_chl_opt") ||
			strings.Contains(body, "cf-browser-verification") {
			return true
		}
	}

	// Check for Cloudflare error pages
	cloudflareIndicators := []string{
		"Attention Required!",
		"Please complete the security check",
		"Ray ID:",
		"Cloudflare Ray ID",
		"enable JavaScript and cookies",
		"cf-error-overview",
	}

	for _, indicator := range cloudflareIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

// ExtractCloudflareInfo extracts Cloudflare-specific information from response
type CloudflareInfo struct {
	RayID        string `json:"ray_id"`
	ErrorCode    string `json:"error_code"`
	ChallengeType string `json:"challenge_type"`
	DatacenterID string `json:"datacenter_id"`
}

// ParseCloudflareResponse extracts Cloudflare info from a response
func ParseCloudflareResponse(body string, headers map[string]string) *CloudflareInfo {
	info := &CloudflareInfo{}

	// Extract Ray ID from header
	if rayID, ok := headers["cf-ray"]; ok {
		info.RayID = rayID
		// Ray ID format: hex-datacenter (e.g., "7890abcdef123456-SJC")
		parts := strings.Split(rayID, "-")
		if len(parts) == 2 {
			info.DatacenterID = parts[1]
		}
	}

	// Detect challenge type
	if strings.Contains(body, "cf-turnstile") {
		info.ChallengeType = "turnstile"
	} else if strings.Contains(body, "__cf_chl_opt") {
		info.ChallengeType = "js_challenge"
	} else if strings.Contains(body, "hcaptcha") || strings.Contains(body, "g-recaptcha") {
		info.ChallengeType = "captcha"
	}

	// Extract error codes (e.g., 1020, 1015)
	errorPatterns := []string{"Error 1020", "Error 1015", "Error 1006", "Error 1000"}
	for _, pattern := range errorPatterns {
		if strings.Contains(body, pattern) {
			info.ErrorCode = strings.TrimPrefix(pattern, "Error ")
			break
		}
	}

	return info
}
