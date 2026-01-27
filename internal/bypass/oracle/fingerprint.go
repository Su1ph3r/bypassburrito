package oracle

import (
	"regexp"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ErrorFingerprint captures structured error information
type ErrorFingerprint struct {
	ErrorType         string   `json:"error_type"`
	ErrorCode         string   `json:"error_code,omitempty"`
	Framework         string   `json:"framework,omitempty"`
	Database          string   `json:"database,omitempty"`
	WAFType           string   `json:"waf_type,omitempty"`
	StackTracePresent bool     `json:"stack_trace_present"`
	LeakedPaths       []string `json:"leaked_paths,omitempty"`
	LeakedVersions    []string `json:"leaked_versions,omitempty"`
	KeyPhrases        []string `json:"key_phrases,omitempty"`
	Confidence        float64  `json:"confidence"`
}

// FingerprintAnalyzer extracts error fingerprints from responses
type FingerprintAnalyzer struct {
	errorPatterns    []errorPattern
	frameworkPatterns []frameworkPattern
	databasePatterns []databasePattern
	wafPatterns      []wafPattern
	pathPattern      *regexp.Regexp
	versionPattern   *regexp.Regexp
	stackTracePattern *regexp.Regexp
}

type errorPattern struct {
	pattern     *regexp.Regexp
	errorType   string
	codeGroup   int // Regex group for error code
	confidence  float64
}

type frameworkPattern struct {
	pattern    *regexp.Regexp
	framework  string
	confidence float64
}

type databasePattern struct {
	pattern    *regexp.Regexp
	database   string
	confidence float64
}

type wafPattern struct {
	pattern    *regexp.Regexp
	wafType    string
	confidence float64
}

// NewFingerprintAnalyzer creates a new fingerprint analyzer
func NewFingerprintAnalyzer() *FingerprintAnalyzer {
	return &FingerprintAnalyzer{
		errorPatterns:     defaultErrorPatterns(),
		frameworkPatterns: defaultFrameworkPatterns(),
		databasePatterns:  defaultDatabasePatterns(),
		wafPatterns:       defaultWAFPatterns(),
		pathPattern:       regexp.MustCompile(`(?:^|[\s"'<>])(/(?:var|usr|home|etc|opt|www|app|src|web|api)/[^\s"'<>]+)`),
		versionPattern:    regexp.MustCompile(`(?i)(?:version|v)[:\s]*(\d+\.\d+(?:\.\d+)?)`),
		stackTracePattern: regexp.MustCompile(`(?i)(?:at\s+[\w.$]+\(|Traceback|Stack trace|Exception in|Fatal error)`),
	}
}

// FingerprintError extracts error fingerprint from response
func (f *FingerprintAnalyzer) FingerprintError(resp *types.HTTPResponse) *ErrorFingerprint {
	fp := &ErrorFingerprint{
		Confidence: 0.0,
	}

	if resp == nil {
		return fp
	}

	body := resp.Body
	headers := formatHeadersForFingerprint(resp.Headers)
	combined := body + "\n" + headers

	// Detect error type
	f.detectErrorType(combined, fp)

	// Detect framework
	f.detectFramework(combined, fp)

	// Detect database
	f.detectDatabase(combined, fp)

	// Detect WAF
	f.detectWAF(combined, fp)

	// Extract leaked paths
	fp.LeakedPaths = f.extractPaths(body)

	// Extract versions
	fp.LeakedVersions = f.extractVersions(combined)

	// Check for stack trace
	fp.StackTracePresent = f.stackTracePattern.MatchString(body)

	// Extract key phrases
	fp.KeyPhrases = f.extractKeyPhrases(body)

	// Calculate overall confidence
	f.calculateConfidence(fp)

	return fp
}

// detectErrorType identifies the type of error
func (f *FingerprintAnalyzer) detectErrorType(content string, fp *ErrorFingerprint) {
	for _, p := range f.errorPatterns {
		if matches := p.pattern.FindStringSubmatch(content); matches != nil {
			if fp.ErrorType == "" || p.confidence > fp.Confidence {
				fp.ErrorType = p.errorType
				if p.codeGroup > 0 && p.codeGroup < len(matches) {
					fp.ErrorCode = matches[p.codeGroup]
				}
			}
		}
	}
}

// detectFramework identifies the framework
func (f *FingerprintAnalyzer) detectFramework(content string, fp *ErrorFingerprint) {
	for _, p := range f.frameworkPatterns {
		if p.pattern.MatchString(content) {
			if fp.Framework == "" || p.confidence > fp.Confidence {
				fp.Framework = p.framework
			}
		}
	}
}

// detectDatabase identifies the database
func (f *FingerprintAnalyzer) detectDatabase(content string, fp *ErrorFingerprint) {
	for _, p := range f.databasePatterns {
		if p.pattern.MatchString(content) {
			if fp.Database == "" || p.confidence > fp.Confidence {
				fp.Database = p.database
			}
		}
	}
}

// detectWAF identifies the WAF type
func (f *FingerprintAnalyzer) detectWAF(content string, fp *ErrorFingerprint) {
	for _, p := range f.wafPatterns {
		if p.pattern.MatchString(content) {
			if fp.WAFType == "" || p.confidence > fp.Confidence {
				fp.WAFType = p.wafType
			}
		}
	}
}

// extractPaths extracts file system paths from content
func (f *FingerprintAnalyzer) extractPaths(content string) []string {
	matches := f.pathPattern.FindAllStringSubmatch(content, -1)
	paths := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			paths[m[1]] = true
		}
	}

	result := make([]string, 0, len(paths))
	for p := range paths {
		result = append(result, p)
	}
	return result
}

// extractVersions extracts version numbers from content
func (f *FingerprintAnalyzer) extractVersions(content string) []string {
	matches := f.versionPattern.FindAllStringSubmatch(content, -1)
	versions := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			versions[m[1]] = true
		}
	}

	result := make([]string, 0, len(versions))
	for v := range versions {
		result = append(result, v)
	}
	return result
}

// extractKeyPhrases extracts security-relevant phrases
func (f *FingerprintAnalyzer) extractKeyPhrases(content string) []string {
	phrases := []string{
		"access denied", "permission denied", "unauthorized",
		"blocked", "rejected", "forbidden", "invalid",
		"attack detected", "malicious", "security violation",
		"rate limit", "throttled", "too many requests",
	}

	lower := strings.ToLower(content)
	var found []string
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			found = append(found, phrase)
		}
	}
	return found
}

// calculateConfidence computes overall fingerprint confidence
func (f *FingerprintAnalyzer) calculateConfidence(fp *ErrorFingerprint) {
	var score float64
	var factors int

	if fp.ErrorType != "" {
		score += 0.3
		factors++
	}
	if fp.ErrorCode != "" {
		score += 0.1
		factors++
	}
	if fp.Framework != "" {
		score += 0.2
		factors++
	}
	if fp.Database != "" {
		score += 0.2
		factors++
	}
	if fp.WAFType != "" {
		score += 0.3
		factors++
	}
	if fp.StackTracePresent {
		score += 0.1
		factors++
	}
	if len(fp.LeakedPaths) > 0 {
		score += 0.1
		factors++
	}
	if len(fp.KeyPhrases) > 0 {
		score += float64(len(fp.KeyPhrases)) * 0.05
		factors++
	}

	if factors > 0 {
		fp.Confidence = score
		if fp.Confidence > 1.0 {
			fp.Confidence = 1.0
		}
	}
}

func formatHeadersForFingerprint(headers map[string]string) string {
	var parts []string
	for k, v := range headers {
		parts = append(parts, k+": "+v)
	}
	return strings.Join(parts, "\n")
}

func defaultErrorPatterns() []errorPattern {
	return []errorPattern{
		// Generic errors
		{regexp.MustCompile(`(?i)error\s*(?:code)?[:\s]*(\d+)`), "generic_error", 1, 0.5},
		{regexp.MustCompile(`(?i)exception[:\s]+(.+)`), "exception", 1, 0.6},
		{regexp.MustCompile(`(?i)fatal\s+error`), "fatal_error", 0, 0.7},

		// HTTP errors
		{regexp.MustCompile(`(?i)403\s*forbidden`), "http_403", 0, 0.8},
		{regexp.MustCompile(`(?i)404\s*not\s*found`), "http_404", 0, 0.5},
		{regexp.MustCompile(`(?i)500\s*internal`), "http_500", 0, 0.6},

		// Security errors
		{regexp.MustCompile(`(?i)access\s*denied`), "access_denied", 0, 0.7},
		{regexp.MustCompile(`(?i)permission\s*denied`), "permission_denied", 0, 0.7},
		{regexp.MustCompile(`(?i)unauthorized`), "unauthorized", 0, 0.7},
		{regexp.MustCompile(`(?i)request\s*blocked`), "blocked", 0, 0.9},
		{regexp.MustCompile(`(?i)security\s*violation`), "security_violation", 0, 0.9},
	}
}

func defaultFrameworkPatterns() []frameworkPattern {
	return []frameworkPattern{
		// PHP
		{regexp.MustCompile(`(?i)PHP\s*(Fatal|Parse|Warning)`), "PHP", 0.8},
		{regexp.MustCompile(`(?i)Laravel`), "Laravel", 0.9},
		{regexp.MustCompile(`(?i)Symfony`), "Symfony", 0.9},
		{regexp.MustCompile(`(?i)WordPress`), "WordPress", 0.9},

		// Python
		{regexp.MustCompile(`(?i)Traceback\s*\(most\s*recent`), "Python", 0.9},
		{regexp.MustCompile(`(?i)Django`), "Django", 0.9},
		{regexp.MustCompile(`(?i)Flask`), "Flask", 0.9},

		// Java
		{regexp.MustCompile(`(?i)java\.lang\.\w+Exception`), "Java", 0.9},
		{regexp.MustCompile(`(?i)Spring\s*(?:Boot|Framework)`), "Spring", 0.9},

		// .NET
		{regexp.MustCompile(`(?i)System\.\w+Exception`), ".NET", 0.8},
		{regexp.MustCompile(`(?i)ASP\.NET`), "ASP.NET", 0.9},

		// Node.js
		{regexp.MustCompile(`(?i)TypeError:|ReferenceError:`), "Node.js", 0.7},
		{regexp.MustCompile(`(?i)Express`), "Express.js", 0.8},

		// Ruby
		{regexp.MustCompile(`(?i)Ruby\s*on\s*Rails`), "Rails", 0.9},
		{regexp.MustCompile(`(?i)Sinatra`), "Sinatra", 0.9},
	}
}

func defaultDatabasePatterns() []databasePattern {
	return []databasePattern{
		// MySQL/MariaDB
		{regexp.MustCompile(`(?i)mysql`), "MySQL", 0.8},
		{regexp.MustCompile(`(?i)mariadb`), "MariaDB", 0.9},
		{regexp.MustCompile(`(?i)You have an error in your SQL syntax`), "MySQL", 0.95},

		// PostgreSQL
		{regexp.MustCompile(`(?i)postgresql`), "PostgreSQL", 0.9},
		{regexp.MustCompile(`(?i)pg_`), "PostgreSQL", 0.7},

		// Oracle
		{regexp.MustCompile(`(?i)ORA-\d+`), "Oracle", 0.95},
		{regexp.MustCompile(`(?i)Oracle\s*error`), "Oracle", 0.9},

		// SQL Server
		{regexp.MustCompile(`(?i)Microsoft\s*SQL\s*Server`), "MSSQL", 0.95},
		{regexp.MustCompile(`(?i)ODBC\s*SQL\s*Server`), "MSSQL", 0.9},

		// SQLite
		{regexp.MustCompile(`(?i)sqlite`), "SQLite", 0.9},
		{regexp.MustCompile(`(?i)SQLITE_`), "SQLite", 0.9},

		// MongoDB
		{regexp.MustCompile(`(?i)mongodb`), "MongoDB", 0.9},
		{regexp.MustCompile(`(?i)MongoError`), "MongoDB", 0.95},
	}
}

func defaultWAFPatterns() []wafPattern {
	return []wafPattern{
		// Cloudflare
		{regexp.MustCompile(`(?i)cloudflare`), "Cloudflare", 0.9},
		{regexp.MustCompile(`(?i)cf-ray`), "Cloudflare", 0.95},
		{regexp.MustCompile(`(?i)error\s*1020`), "Cloudflare", 0.95},

		// ModSecurity
		{regexp.MustCompile(`(?i)mod_?security`), "ModSecurity", 0.95},
		{regexp.MustCompile(`(?i)OWASP.*CRS`), "ModSecurity", 0.9},

		// AWS WAF
		{regexp.MustCompile(`(?i)aws\s*waf`), "AWS WAF", 0.95},
		{regexp.MustCompile(`(?i)x-amzn-waf`), "AWS WAF", 0.95},

		// Akamai
		{regexp.MustCompile(`(?i)akamai`), "Akamai", 0.9},
		{regexp.MustCompile(`(?i)reference\s*#\s*\d+\.\w+`), "Akamai", 0.85},

		// Imperva/Incapsula
		{regexp.MustCompile(`(?i)incapsula`), "Imperva", 0.95},
		{regexp.MustCompile(`(?i)imperva`), "Imperva", 0.95},

		// F5 BIG-IP
		{regexp.MustCompile(`(?i)F5\s*BIG-?IP`), "F5 BIG-IP", 0.95},
		{regexp.MustCompile(`(?i)support\s*id.*\d+\.\d+`), "F5 BIG-IP", 0.8},

		// Sucuri
		{regexp.MustCompile(`(?i)sucuri`), "Sucuri", 0.95},
		{regexp.MustCompile(`(?i)cloudproxy`), "Sucuri", 0.85},

		// Wordfence
		{regexp.MustCompile(`(?i)wordfence`), "Wordfence", 0.95},

		// Fortinet
		{regexp.MustCompile(`(?i)fortigate|fortiweb`), "Fortinet", 0.95},

		// Barracuda
		{regexp.MustCompile(`(?i)barracuda`), "Barracuda", 0.95},
	}
}
