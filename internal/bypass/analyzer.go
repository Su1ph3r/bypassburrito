package bypass

import (
	"regexp"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ResponseAnalyzer analyzes HTTP responses to classify them
type ResponseAnalyzer struct {
	blockPatterns   []blockPattern
	successPatterns []successPattern
}

type blockPattern struct {
	pattern     *regexp.Regexp
	location    string
	description string
	confidence  float64
}

type successPattern struct {
	pattern     *regexp.Regexp
	location    string
	description string
}

// NewResponseAnalyzer creates a new response analyzer
func NewResponseAnalyzer() *ResponseAnalyzer {
	analyzer := &ResponseAnalyzer{
		blockPatterns:   defaultBlockPatterns(),
		successPatterns: defaultSuccessPatterns(),
	}
	return analyzer
}

// Analyze analyzes an HTTP response
func (a *ResponseAnalyzer) Analyze(resp *types.HTTPResponse) *types.ResponseAnalysis {
	analysis := &types.ResponseAnalysis{
		Classification:  types.ClassificationUnknown,
		Confidence:      0.5,
		BlockIndicators: []types.BlockIndicator{},
		ActualLatency:   resp.Latency,
	}

	// Check for error responses
	if resp.Error != "" {
		analysis.Classification = types.ClassificationError
		analysis.ErrorMessage = resp.Error
		return analysis
	}

	// Check status code
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 501 {
		analysis.Classification = types.ClassificationBlocked
		analysis.Confidence = 0.7
	} else if resp.StatusCode == 429 {
		analysis.Classification = types.ClassificationRateLimited
		analysis.Confidence = 0.9
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		analysis.Classification = types.ClassificationAllowed
		analysis.Confidence = 0.6
	}

	// Check for block patterns in body
	for _, pattern := range a.blockPatterns {
		if pattern.location == "body" || pattern.location == "any" {
			if pattern.pattern.MatchString(resp.Body) {
				analysis.Classification = types.ClassificationBlocked
				matched := pattern.pattern.FindString(resp.Body)
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}
				analysis.BlockIndicators = append(analysis.BlockIndicators, types.BlockIndicator{
					Type:        "body",
					Pattern:     pattern.pattern.String(),
					Matched:     matched,
					Confidence:  pattern.confidence,
					Description: pattern.description,
				})
				if pattern.confidence > analysis.Confidence {
					analysis.Confidence = pattern.confidence
				}
			}
		}
	}

	// Check for block patterns in headers
	headerStr := formatHeaders(resp.Headers)
	for _, pattern := range a.blockPatterns {
		if pattern.location == "header" || pattern.location == "any" {
			if pattern.pattern.MatchString(headerStr) {
				analysis.Classification = types.ClassificationBlocked
				matched := pattern.pattern.FindString(headerStr)
				analysis.BlockIndicators = append(analysis.BlockIndicators, types.BlockIndicator{
					Type:        "header",
					Pattern:     pattern.pattern.String(),
					Matched:     matched,
					Confidence:  pattern.confidence,
					Description: pattern.description,
				})
			}
		}
	}

	// Check for WAF headers
	wafHeaders := detectWAFHeaders(resp.Headers)
	analysis.WAFHeaders = wafHeaders

	// Check for block page characteristics
	analysis.BlockPage = isBlockPage(resp.Body)
	analysis.CaptchaPresent = hasCaptcha(resp.Body)
	analysis.JSChallenge = hasJSChallenge(resp.Body)

	if analysis.CaptchaPresent || analysis.JSChallenge {
		analysis.Classification = types.ClassificationChallenged
		analysis.Confidence = 0.9
	}

	// If we found block indicators, update error message
	if len(analysis.BlockIndicators) > 0 {
		analysis.ErrorMessage = analysis.BlockIndicators[0].Description
	}

	return analysis
}

// defaultBlockPatterns returns common WAF block patterns
func defaultBlockPatterns() []blockPattern {
	return []blockPattern{
		// Generic block messages
		{regexp.MustCompile(`(?i)access\s*denied`), "body", "Access denied message", 0.7},
		{regexp.MustCompile(`(?i)request\s*blocked`), "body", "Request blocked message", 0.8},
		{regexp.MustCompile(`(?i)forbidden`), "body", "Forbidden message", 0.6},
		{regexp.MustCompile(`(?i)not\s*allowed`), "body", "Not allowed message", 0.6},
		{regexp.MustCompile(`(?i)security\s*violation`), "body", "Security violation", 0.8},
		{regexp.MustCompile(`(?i)malicious\s*request`), "body", "Malicious request detected", 0.9},
		{regexp.MustCompile(`(?i)attack\s*detected`), "body", "Attack detected", 0.9},
		{regexp.MustCompile(`(?i)suspicious\s*activity`), "body", "Suspicious activity", 0.7},

		// Cloudflare
		{regexp.MustCompile(`(?i)ray\s*id`), "body", "Cloudflare Ray ID", 0.8},
		{regexp.MustCompile(`(?i)cloudflare`), "body", "Cloudflare mention", 0.6},
		{regexp.MustCompile(`(?i)error\s*1020`), "body", "Cloudflare error 1020", 0.9},
		{regexp.MustCompile(`(?i)cf-ray`), "header", "Cloudflare Ray header", 0.7},

		// ModSecurity
		{regexp.MustCompile(`(?i)mod_security`), "any", "ModSecurity", 0.9},
		{regexp.MustCompile(`(?i)modsecurity`), "any", "ModSecurity", 0.9},
		{regexp.MustCompile(`(?i)unique\s*id`), "body", "ModSecurity Unique ID", 0.7},

		// AWS WAF
		{regexp.MustCompile(`(?i)aws\s*waf`), "body", "AWS WAF", 0.9},
		{regexp.MustCompile(`(?i)x-amzn-requestid`), "header", "AWS request ID", 0.5},

		// Imperva/Incapsula
		{regexp.MustCompile(`(?i)incapsula`), "any", "Incapsula/Imperva", 0.9},
		{regexp.MustCompile(`(?i)imperva`), "any", "Imperva", 0.9},
		{regexp.MustCompile(`(?i)incident\s*id`), "body", "Imperva incident ID", 0.8},

		// F5 BIG-IP
		{regexp.MustCompile(`(?i)support\s*id`), "body", "F5 Support ID", 0.7},
		{regexp.MustCompile(`(?i)request\s*rejected`), "body", "F5 request rejected", 0.8},

		// Akamai
		{regexp.MustCompile(`(?i)reference\s*#`), "body", "Akamai reference", 0.7},
		{regexp.MustCompile(`(?i)akamai`), "any", "Akamai", 0.6},

		// Sucuri
		{regexp.MustCompile(`(?i)sucuri`), "any", "Sucuri WAF", 0.9},
		{regexp.MustCompile(`(?i)cloudproxy`), "body", "Sucuri CloudProxy", 0.8},

		// Wordfence
		{regexp.MustCompile(`(?i)wordfence`), "body", "Wordfence", 0.9},
		{regexp.MustCompile(`(?i)generated\s*by\s*wordfence`), "body", "Wordfence block page", 0.95},

		// Generic WAF
		{regexp.MustCompile(`(?i)web\s*application\s*firewall`), "body", "WAF mention", 0.8},
		{regexp.MustCompile(`(?i)waf`), "body", "WAF acronym", 0.4},
	}
}

// defaultSuccessPatterns returns patterns indicating successful bypass
func defaultSuccessPatterns() []successPattern {
	return []successPattern{
		// SQL error messages (indicate SQLi worked)
		{regexp.MustCompile(`(?i)sql\s*syntax`), "body", "SQL syntax error"},
		{regexp.MustCompile(`(?i)mysql`), "body", "MySQL error"},
		{regexp.MustCompile(`(?i)mariadb`), "body", "MariaDB error"},
		{regexp.MustCompile(`(?i)postgresql`), "body", "PostgreSQL error"},
		{regexp.MustCompile(`(?i)ora-\d+`), "body", "Oracle error"},
		{regexp.MustCompile(`(?i)sqlite`), "body", "SQLite error"},
		{regexp.MustCompile(`(?i)mssql`), "body", "MSSQL error"},

		// XSS indicators
		{regexp.MustCompile(`<script[^>]*>`), "body", "Script tag present"},
		{regexp.MustCompile(`javascript:`), "body", "JavaScript URI"},
		{regexp.MustCompile(`onerror\s*=`), "body", "Event handler present"},

		// Command injection
		{regexp.MustCompile(`(?i)root:.*:0:0`), "body", "passwd file content"},
		{regexp.MustCompile(`(?i)uid=\d+.*gid=\d+`), "body", "id command output"},

		// Path traversal
		{regexp.MustCompile(`\[boot\s*loader\]`), "body", "boot.ini content"},
		{regexp.MustCompile(`root:x:0:0`), "body", "passwd content"},
	}
}

// formatHeaders converts headers map to string for matching
func formatHeaders(headers map[string]string) string {
	var parts []string
	for k, v := range headers {
		parts = append(parts, k+": "+v)
	}
	return strings.Join(parts, "\n")
}

// detectWAFHeaders looks for WAF-related headers
func detectWAFHeaders(headers map[string]string) []string {
	wafHeaders := []string{}
	wafHeaderPatterns := []string{
		"cf-ray", "cf-cache", "x-sucuri", "x-waf", "x-iinfo",
		"x-amzn", "x-akamai", "server",
	}

	for k := range headers {
		lowerKey := strings.ToLower(k)
		for _, pattern := range wafHeaderPatterns {
			if strings.Contains(lowerKey, pattern) {
				wafHeaders = append(wafHeaders, k)
				break
			}
		}
	}

	return wafHeaders
}

// isBlockPage checks if the response looks like a WAF block page
func isBlockPage(body string) bool {
	blockIndicators := []string{
		"blocked", "denied", "forbidden", "not allowed",
		"security", "firewall", "protection", "violation",
	}

	lowerBody := strings.ToLower(body)
	matches := 0
	for _, indicator := range blockIndicators {
		if strings.Contains(lowerBody, indicator) {
			matches++
		}
	}

	return matches >= 2
}

// hasCaptcha checks if the response contains a CAPTCHA challenge
func hasCaptcha(body string) bool {
	captchaPatterns := []string{
		"captcha", "recaptcha", "hcaptcha", "challenge",
		"g-recaptcha", "h-captcha", "cf-turnstile",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range captchaPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	return false
}

// hasJSChallenge checks for JavaScript challenge
func hasJSChallenge(body string) bool {
	jsPatterns := []string{
		"javascript challenge", "browser check",
		"please wait", "checking your browser",
		"enable javascript", "ddos protection",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range jsPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	return false
}
