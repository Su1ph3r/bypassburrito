package solver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// BrowserSolver uses headless browser for JavaScript challenges
type BrowserSolver struct {
	config      SolverConfig
	browserPath string
	headless    bool
}

// NewBrowserSolver creates a new browser-based solver
func NewBrowserSolver(config SolverConfig) *BrowserSolver {
	return &BrowserSolver{
		config:      config,
		browserPath: config.BrowserPath,
		headless:    config.Headless,
	}
}

// CanSolve checks if this solver can handle the challenge
func (b *BrowserSolver) CanSolve(analysis *types.ResponseAnalysis) bool {
	if analysis == nil {
		return false
	}
	// Browser solver can handle JS challenges
	return analysis.JSChallenge
}

// SolverType returns the solver type
func (b *BrowserSolver) SolverType() string {
	return "browser"
}

// Solve attempts to solve the challenge using a headless browser
// Note: This is a stub implementation. Full implementation would require
// integrating with chromedp, rod, or similar browser automation library.
func (b *BrowserSolver) Solve(ctx context.Context, url string, opts SolveOptions) (*SolveResult, error) {
	start := time.Now()
	result := &SolveResult{
		Cookies:       make(map[string]string),
		ChallengeType: string(ChallengeJavaScript),
		UserAgent:     opts.UserAgent,
	}

	// Check if browser automation is available
	if !b.isBrowserAvailable() {
		result.Error = "browser automation not available - install go-rod or chromedp"
		result.Duration = time.Since(start)
		return result, nil
	}

	// Attempt to solve with retries
	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		result.Attempts = attempt

		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		// This is where browser automation would occur
		// For now, return a placeholder indicating the feature needs
		// the browser automation dependency
		cookies, clearance, err := b.executeBrowserSolve(ctx, url, opts)
		if err != nil {
			if attempt == opts.MaxAttempts {
				result.Error = fmt.Sprintf("failed after %d attempts: %s", attempt, err.Error())
			}
			continue
		}

		result.Success = true
		result.Cookies = cookies
		result.ClearanceCookie = clearance
		break
	}

	result.Duration = time.Since(start)
	return result, nil
}

// isBrowserAvailable checks if browser automation is configured
func (b *BrowserSolver) isBrowserAvailable() bool {
	// In a full implementation, this would check for:
	// 1. chromedp/rod package availability
	// 2. Chrome/Chromium binary presence
	// 3. Browser path configuration
	return b.browserPath != "" || b.findDefaultBrowser() != ""
}

// findDefaultBrowser looks for a browser in common locations
func (b *BrowserSolver) findDefaultBrowser() string {
	// Common browser paths
	paths := []string{
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}

	// Would check if these exist
	// For now, return empty (stub implementation)
	_ = paths
	return ""
}

// executeBrowserSolve performs the actual browser automation
// This is a stub that would be replaced with actual chromedp/rod code
func (b *BrowserSolver) executeBrowserSolve(ctx context.Context, url string, opts SolveOptions) (map[string]string, string, error) {
	// Stub implementation
	// In a real implementation with go-rod:
	//
	// browser := rod.New().MustConnect()
	// defer browser.MustClose()
	//
	// page := browser.MustPage(url)
	// page.MustWaitLoad()
	//
	// // Wait for challenge to be solved (JS execution)
	// time.Sleep(5 * time.Second)
	//
	// // Extract cookies
	// cookies := page.MustCookies()
	// ...

	return nil, "", fmt.Errorf("browser automation not implemented - add go-rod dependency")
}

// JSChallengeSolver specifically handles JavaScript challenges without CAPTCHA
type JSChallengeSolver struct {
	*BrowserSolver
}

// NewJSChallengeSolver creates a solver for pure JS challenges
func NewJSChallengeSolver(config SolverConfig) *JSChallengeSolver {
	return &JSChallengeSolver{
		BrowserSolver: NewBrowserSolver(config),
	}
}

// CanSolve checks if this is a pure JS challenge (no CAPTCHA)
func (j *JSChallengeSolver) CanSolve(analysis *types.ResponseAnalysis) bool {
	if analysis == nil {
		return false
	}
	return analysis.JSChallenge && !analysis.CaptchaPresent
}

// SolverType returns the solver type
func (j *JSChallengeSolver) SolverType() string {
	return "js_challenge"
}

// DetectJSChallengeType analyzes response body for specific challenge types
func DetectJSChallengeType(body string) ChallengeType {
	lowerBody := strings.ToLower(body)

	// Cloudflare challenges
	if strings.Contains(lowerBody, "cf-ray") ||
		strings.Contains(lowerBody, "cloudflare") ||
		strings.Contains(lowerBody, "cf-browser-verification") ||
		strings.Contains(body, "__cf_chl_opt") {
		return ChallengeCloudflare
	}

	// Cloudflare Turnstile
	if strings.Contains(lowerBody, "cf-turnstile") ||
		strings.Contains(body, "challenges.cloudflare.com/turnstile") {
		return ChallengeCloudflareTurnstile
	}

	// DataDome
	if strings.Contains(lowerBody, "datadome") ||
		strings.Contains(body, "dd.js") {
		return ChallengeDataDome
	}

	// PerimeterX
	if strings.Contains(lowerBody, "perimeterx") ||
		strings.Contains(body, "_px") ||
		strings.Contains(body, "pxCaptcha") {
		return ChallengePerimeterX
	}

	// Generic JS challenge
	if strings.Contains(lowerBody, "please enable javascript") ||
		strings.Contains(lowerBody, "browser verification") ||
		strings.Contains(lowerBody, "checking your browser") {
		return ChallengeJavaScript
	}

	return ChallengeUnknown
}
