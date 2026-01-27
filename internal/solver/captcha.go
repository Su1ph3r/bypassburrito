package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// CaptchaSolver integrates with third-party CAPTCHA solving services
type CaptchaSolver struct {
	config  SolverConfig
	service CaptchaService
}

// CaptchaService represents a CAPTCHA solving service
type CaptchaService interface {
	// SolveCaptcha sends a CAPTCHA to be solved and returns the solution
	SolveCaptcha(ctx context.Context, captchaType string, siteKey string, pageURL string) (string, error)

	// Name returns the service name
	Name() string
}

// NewCaptchaSolver creates a new CAPTCHA solver
func NewCaptchaSolver(config SolverConfig) *CaptchaSolver {
	var service CaptchaService

	switch config.CaptchaService {
	case "2captcha":
		service = NewTwoCaptchaService(config.CaptchaAPIKey)
	case "anticaptcha":
		service = NewAntiCaptchaService(config.CaptchaAPIKey)
	default:
		// No service configured
		service = nil
	}

	return &CaptchaSolver{
		config:  config,
		service: service,
	}
}

// CanSolve checks if this solver can handle CAPTCHA challenges
func (c *CaptchaSolver) CanSolve(analysis *types.ResponseAnalysis) bool {
	if analysis == nil {
		return false
	}
	// Can solve if CAPTCHA is present and we have a service configured
	return analysis.CaptchaPresent && c.service != nil
}

// SolverType returns the solver type
func (c *CaptchaSolver) SolverType() string {
	if c.service != nil {
		return "captcha_" + c.service.Name()
	}
	return "captcha"
}

// Solve attempts to solve the CAPTCHA
func (c *CaptchaSolver) Solve(ctx context.Context, url string, opts SolveOptions) (*SolveResult, error) {
	start := time.Now()
	result := &SolveResult{
		Cookies:       make(map[string]string),
		ChallengeType: string(ChallengeRecaptcha),
		UserAgent:     opts.UserAgent,
	}

	if c.service == nil {
		result.Error = "no CAPTCHA service configured"
		result.Duration = time.Since(start)
		return result, nil
	}

	// Detect CAPTCHA type and extract site key
	// This would typically require fetching the page and parsing it
	// For now, return a placeholder
	result.Error = "CAPTCHA solving requires fetching page content to extract site key"
	result.Duration = time.Since(start)
	return result, nil
}

// TwoCaptchaService implements 2captcha.com integration
type TwoCaptchaService struct {
	apiKey  string
	baseURL string
}

// NewTwoCaptchaService creates a new 2captcha service
func NewTwoCaptchaService(apiKey string) *TwoCaptchaService {
	return &TwoCaptchaService{
		apiKey:  apiKey,
		baseURL: "https://2captcha.com",
	}
}

// Name returns the service name
func (t *TwoCaptchaService) Name() string {
	return "2captcha"
}

// SolveCaptcha sends a CAPTCHA to 2captcha and returns the solution
func (t *TwoCaptchaService) SolveCaptcha(ctx context.Context, captchaType string, siteKey string, pageURL string) (string, error) {
	if t.apiKey == "" {
		return "", fmt.Errorf("2captcha API key not configured")
	}

	// Step 1: Submit the CAPTCHA
	taskID, err := t.submitCaptcha(ctx, captchaType, siteKey, pageURL)
	if err != nil {
		return "", err
	}

	// Step 2: Poll for result
	return t.pollResult(ctx, taskID)
}

// submitCaptcha submits a CAPTCHA task to 2captcha
func (t *TwoCaptchaService) submitCaptcha(ctx context.Context, captchaType string, siteKey string, pageURL string) (string, error) {
	params := url.Values{}
	params.Set("key", t.apiKey)
	params.Set("method", "userrecaptcha")
	params.Set("googlekey", siteKey)
	params.Set("pageurl", pageURL)
	params.Set("json", "1")

	if captchaType == "hcaptcha" {
		params.Set("method", "hcaptcha")
		params.Set("sitekey", siteKey)
		params.Del("googlekey")
	}

	reqURL := t.baseURL + "/in.php?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Status  int    `json:"status"`
		Request string `json:"request"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %s", string(body))
	}

	if result.Status != 1 {
		return "", fmt.Errorf("2captcha error: %s", result.Request)
	}

	return result.Request, nil
}

// pollResult polls for CAPTCHA solution
func (t *TwoCaptchaService) pollResult(ctx context.Context, taskID string) (string, error) {
	params := url.Values{}
	params.Set("key", t.apiKey)
	params.Set("action", "get")
	params.Set("id", taskID)
	params.Set("json", "1")

	reqURL := t.baseURL + "/res.php?" + params.Encode()

	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < 60; i++ { // Max 2 minutes
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return "", err
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var result struct {
			Status  int    `json:"status"`
			Request string `json:"request"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		if result.Status == 1 {
			return result.Request, nil
		}

		if result.Request != "CAPCHA_NOT_READY" {
			return "", fmt.Errorf("2captcha error: %s", result.Request)
		}
	}

	return "", fmt.Errorf("timeout waiting for CAPTCHA solution")
}

// AntiCaptchaService implements anti-captcha.com integration
type AntiCaptchaService struct {
	apiKey  string
	baseURL string
}

// NewAntiCaptchaService creates a new AntiCaptcha service
func NewAntiCaptchaService(apiKey string) *AntiCaptchaService {
	return &AntiCaptchaService{
		apiKey:  apiKey,
		baseURL: "https://api.anti-captcha.com",
	}
}

// Name returns the service name
func (a *AntiCaptchaService) Name() string {
	return "anticaptcha"
}

// SolveCaptcha sends a CAPTCHA to AntiCaptcha and returns the solution
func (a *AntiCaptchaService) SolveCaptcha(ctx context.Context, captchaType string, siteKey string, pageURL string) (string, error) {
	if a.apiKey == "" {
		return "", fmt.Errorf("AntiCaptcha API key not configured")
	}

	// Step 1: Create task
	taskID, err := a.createTask(ctx, captchaType, siteKey, pageURL)
	if err != nil {
		return "", err
	}

	// Step 2: Get task result
	return a.getTaskResult(ctx, taskID)
}

// createTask creates a new CAPTCHA task
func (a *AntiCaptchaService) createTask(ctx context.Context, captchaType string, siteKey string, pageURL string) (int64, error) {
	taskType := "RecaptchaV2TaskProxyless"
	if strings.ToLower(captchaType) == "hcaptcha" {
		taskType = "HCaptchaTaskProxyless"
	}

	payload := map[string]interface{}{
		"clientKey": a.apiKey,
		"task": map[string]string{
			"type":       taskType,
			"websiteURL": pageURL,
			"websiteKey": siteKey,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/createTask", strings.NewReader(string(jsonData)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var result struct {
		ErrorID   int    `json:"errorId"`
		ErrorCode string `json:"errorCode"`
		TaskID    int64  `json:"taskId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}

	if result.ErrorID != 0 {
		return 0, fmt.Errorf("AntiCaptcha error: %s", result.ErrorCode)
	}

	return result.TaskID, nil
}

// getTaskResult polls for the task result
func (a *AntiCaptchaService) getTaskResult(ctx context.Context, taskID int64) (string, error) {
	payload := map[string]interface{}{
		"clientKey": a.apiKey,
		"taskId":    taskID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}

		req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/getTaskResult", strings.NewReader(string(jsonData)))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var result struct {
			ErrorID   int    `json:"errorId"`
			ErrorCode string `json:"errorCode"`
			Status    string `json:"status"`
			Solution  struct {
				GRecaptchaResponse string `json:"gRecaptchaResponse"`
			} `json:"solution"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		if result.ErrorID != 0 {
			return "", fmt.Errorf("AntiCaptcha error: %s", result.ErrorCode)
		}

		if result.Status == "ready" {
			return result.Solution.GRecaptchaResponse, nil
		}
	}

	return "", fmt.Errorf("timeout waiting for CAPTCHA solution")
}
