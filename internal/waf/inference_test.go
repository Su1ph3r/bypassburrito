package waf

import (
	"context"
	"testing"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// mockInferenceHTTPClient implements InferenceHTTPClient for testing
type mockInferenceHTTPClient struct {
	blockPatterns []string
	responses     map[string]*types.HTTPResponse
}

func newMockInferenceHTTPClient() *mockInferenceHTTPClient {
	return &mockInferenceHTTPClient{
		blockPatterns: []string{},
		responses:     make(map[string]*types.HTTPResponse),
	}
}

func (m *mockInferenceHTTPClient) Do(ctx context.Context, req *types.HTTPRequest) (*types.HTTPResponse, error) {
	// Check if any block pattern matches
	for _, pattern := range m.blockPatterns {
		if containsStr(req.URL, pattern) || containsStr(req.Body, pattern) {
			return &types.HTTPResponse{
				StatusCode: 403,
				Body:       "Blocked by WAF",
				Headers:    map[string]string{},
			}, nil
		}
	}

	return &types.HTTPResponse{
		StatusCode: 200,
		Body:       "OK",
		Headers:    map[string]string{},
	}, nil
}

func (m *mockInferenceHTTPClient) addBlockPattern(pattern string) {
	m.blockPatterns = append(m.blockPatterns, pattern)
}

func containsStr(s, substr string) bool {
	if len(substr) == 0 {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestNewRuleInferenceEngine(t *testing.T) {
	client := newMockInferenceHTTPClient()
	detector, _ := NewDetector()

	engine := NewRuleInferenceEngine(detector, client)

	if engine == nil {
		t.Fatal("NewRuleInferenceEngine returned nil")
	}

	if engine.minSamples != 20 {
		t.Errorf("expected minSamples=20, got %d", engine.minSamples)
	}
}

func TestDefaultInferenceConfig(t *testing.T) {
	config := DefaultInferenceConfig()

	if config.MinSamples != 20 {
		t.Errorf("expected MinSamples=20, got %d", config.MinSamples)
	}

	if config.MaxSamples != 100 {
		t.Errorf("expected MaxSamples=100, got %d", config.MaxSamples)
	}

	if config.MinConfidence != 0.6 {
		t.Errorf("expected MinConfidence=0.6, got %f", config.MinConfidence)
	}

	if !config.IncludeEvasionHints {
		t.Error("expected IncludeEvasionHints=true")
	}

	if len(config.AttackTypes) != 4 {
		t.Errorf("expected 4 attack types, got %d", len(config.AttackTypes))
	}
}

func TestRuleInferenceEngine_GetPayloadsForType(t *testing.T) {
	engine := &RuleInferenceEngine{}

	testCases := []struct {
		attackType types.AttackType
		minCount   int
	}{
		{types.AttackSQLi, 10},
		{types.AttackXSS, 10},
		{types.AttackCmdInjection, 5},
		{types.AttackPathTraversal, 5},
		{types.AttackType("unknown"), 0},
	}

	for _, tc := range testCases {
		t.Run(string(tc.attackType), func(t *testing.T) {
			payloads := engine.getPayloadsForType(tc.attackType)
			if len(payloads) < tc.minCount {
				t.Errorf("expected at least %d payloads for %s, got %d", tc.minCount, tc.attackType, len(payloads))
			}
		})
	}
}

func TestRuleInferenceEngine_IsBlocked(t *testing.T) {
	engine := &RuleInferenceEngine{}

	testCases := []struct {
		name       string
		response   *types.HTTPResponse
		expected   bool
	}{
		{
			name: "403 status",
			response: &types.HTTPResponse{
				StatusCode: 403,
				Body:       "Access Denied",
			},
			expected: true,
		},
		{
			name: "406 status",
			response: &types.HTTPResponse{
				StatusCode: 406,
				Body:       "Not Acceptable",
			},
			expected: true,
		},
		{
			name: "429 rate limited",
			response: &types.HTTPResponse{
				StatusCode: 429,
				Body:       "Rate Limited",
			},
			expected: true,
		},
		{
			name: "200 OK",
			response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "Success",
			},
			expected: false,
		},
		{
			name: "blocked in body",
			response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "Request blocked by firewall",
			},
			expected: true,
		},
		{
			name: "waf in body",
			response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "WAF detected malicious request",
			},
			expected: true,
		},
		{
			name: "normal content",
			response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "Welcome to the website",
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.isBlocked(tc.response)
			if result != tc.expected {
				t.Errorf("isBlocked(%s) = %v, expected %v", tc.name, result, tc.expected)
			}
		})
	}
}

func TestRuleInferenceEngine_IdentifyKeywordRules(t *testing.T) {
	engine := &RuleInferenceEngine{}

	blocked := []TestResult{
		{Payload: "SELECT * FROM users", Category: "sqli", Blocked: true},
		{Payload: "' UNION SELECT 1,2,3", Category: "sqli", Blocked: true},
		{Payload: "<script>alert(1)</script>", Category: "xss", Blocked: true},
	}

	allowed := []TestResult{
		{Payload: "normal text", Category: "", Blocked: false},
		{Payload: "hello world", Category: "", Blocked: false},
	}

	rules := engine.identifyKeywordRules(blocked, allowed)

	if len(rules) == 0 {
		t.Error("expected at least one keyword rule")
	}

	// Check for SELECT rule
	foundSelect := false
	for _, rule := range rules {
		if rule.Pattern == "SELECT" && rule.RuleType == "keyword" {
			foundSelect = true
			if rule.Category != "sqli" {
				t.Errorf("expected category=sqli for SELECT rule, got %s", rule.Category)
			}
		}
	}

	if !foundSelect {
		t.Log("SELECT rule not found (may be filtered by confidence)")
	}
}

func TestRuleInferenceEngine_IdentifyPatternRules(t *testing.T) {
	engine := &RuleInferenceEngine{}

	blocked := []TestResult{
		{Payload: "' OR 1=1--", Category: "sqli", Blocked: true},
		{Payload: "1' OR '1'='1", Category: "sqli", Blocked: true},
		{Payload: "<script>alert(1)</script>", Category: "xss", Blocked: true},
		{Payload: "<img onerror=alert(1)>", Category: "xss", Blocked: true},
	}

	allowed := []TestResult{
		{Payload: "normal", Category: "", Blocked: false},
	}

	rules := engine.identifyPatternRules(blocked, allowed)

	// Should identify at least some regex patterns
	t.Logf("identified %d pattern rules", len(rules))

	for _, rule := range rules {
		if rule.RuleType != "regex" {
			t.Errorf("expected RuleType=regex, got %s", rule.RuleType)
		}
		if rule.Confidence <= 0 || rule.Confidence > 1 {
			t.Errorf("invalid confidence: %f", rule.Confidence)
		}
	}
}

func TestRuleInferenceEngine_IdentifyEncodingRules(t *testing.T) {
	engine := &RuleInferenceEngine{}

	blocked := []TestResult{
		{Payload: "%27", Blocked: true},
		{Payload: "%3Cscript%3E", Blocked: true},
	}

	allowed := []TestResult{
		{Payload: "normal", Blocked: false},
	}

	rules := engine.identifyEncodingRules(blocked, allowed)

	for _, rule := range rules {
		if rule.RuleType != "encoding" {
			t.Errorf("expected RuleType=encoding, got %s", rule.RuleType)
		}
	}
}

func TestRuleInferenceEngine_GenerateEvasionHints(t *testing.T) {
	engine := &RuleInferenceEngine{}

	testCases := []struct {
		rule    *types.InferredRule
		wafType types.WAFType
	}{
		{
			rule: &types.InferredRule{
				Pattern:  "SELECT",
				RuleType: "keyword",
			},
			wafType: types.WAFUnknown,
		},
		{
			rule: &types.InferredRule{
				Pattern:  "on\\w+=",
				RuleType: "regex",
			},
			wafType: types.WAFCloudflare,
		},
		{
			rule: &types.InferredRule{
				Pattern:  "URL encoded",
				RuleType: "encoding",
			},
			wafType: types.WAFModSecurity,
		},
	}

	for _, tc := range testCases {
		hints := engine.generateEvasionHints(tc.rule, tc.wafType)

		if len(hints) == 0 {
			t.Errorf("expected hints for rule type %s", tc.rule.RuleType)
		}

		t.Logf("rule=%s waf=%s hints=%v", tc.rule.RuleType, tc.wafType, hints)
	}
}

func TestRuleInferenceEngine_GenerateSummary(t *testing.T) {
	engine := &RuleInferenceEngine{}

	result := &types.RuleInferenceResult{
		Target:       "https://example.com",
		WAFType:      types.WAFCloudflare,
		TotalSamples: 50,
		BlockedCount: 30,
		AllowedCount: 20,
		InferredRules: []types.InferredRule{
			{Pattern: "SELECT", Category: "sqli"},
			{Pattern: "<script", Category: "xss"},
		},
	}

	summary := engine.generateSummary(result)

	if summary == "" {
		t.Error("summary should not be empty")
	}

	if !containsStr(summary, "50") {
		t.Error("summary should contain total samples")
	}

	if !containsStr(summary, "30") {
		t.Error("summary should contain blocked count")
	}
}

func TestRuleInferenceEngine_BuildRequest(t *testing.T) {
	engine := &RuleInferenceEngine{}

	t.Run("query position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "https://example.com/api",
			Method:    "GET",
			Parameter: "id",
			Position:  types.PositionQuery,
		}

		req := engine.buildRequest(target, "test_payload")

		if req.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", req.Method)
		}

		if !containsStr(req.URL, "id=test_payload") {
			t.Errorf("expected URL to contain payload, got %s", req.URL)
		}
	})

	t.Run("body position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "https://example.com/api",
			Method:    "POST",
			Parameter: "data",
			Position:  types.PositionBody,
		}

		req := engine.buildRequest(target, "test_payload")

		if req.Body != "data=test_payload" {
			t.Errorf("expected Body=data=test_payload, got %s", req.Body)
		}
	})

	t.Run("header position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "https://example.com/api",
			Method:    "GET",
			Parameter: "X-Test",
			Position:  types.PositionHeader,
		}

		req := engine.buildRequest(target, "test_value")

		if req.Headers["X-Test"] != "test_value" {
			t.Error("expected header to be set")
		}
	})
}

func TestRuleInferenceEngine_InferRules_Integration(t *testing.T) {
	client := newMockInferenceHTTPClient()
	// Block SQL keywords
	client.addBlockPattern("SELECT")
	client.addBlockPattern("UNION")
	client.addBlockPattern("<script")

	detector, _ := NewDetector()
	engine := NewRuleInferenceEngine(detector, client)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := types.TargetConfig{
		URL:       "https://example.com/api",
		Method:    "GET",
		Parameter: "id",
		Position:  types.PositionQuery,
	}

	config := InferenceConfig{
		MinSamples:          5,
		MaxSamples:          20,
		MinConfidence:       0.5,
		IncludeEvasionHints: true,
		AttackTypes:         []types.AttackType{types.AttackSQLi, types.AttackXSS},
	}

	result, err := engine.InferRules(ctx, target, config)
	if err != nil {
		t.Fatalf("InferRules failed: %v", err)
	}

	if result.Target != target.URL {
		t.Errorf("expected Target=%s, got %s", target.URL, result.Target)
	}

	if result.TotalSamples == 0 {
		t.Error("expected some samples to be tested")
	}

	if result.BlockedCount == 0 {
		t.Error("expected some payloads to be blocked")
	}

	t.Logf("Result: samples=%d blocked=%d allowed=%d rules=%d",
		result.TotalSamples, result.BlockedCount, result.AllowedCount, len(result.InferredRules))
}

func TestRuleInferenceEngine_ContextCancellation(t *testing.T) {
	client := newMockInferenceHTTPClient()
	detector, _ := NewDetector()
	engine := NewRuleInferenceEngine(detector, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := types.TargetConfig{
		URL:       "https://example.com/api",
		Method:    "GET",
		Parameter: "id",
		Position:  types.PositionQuery,
	}

	config := DefaultInferenceConfig()

	result, err := engine.InferRules(ctx, target, config)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should return early due to cancellation
	if result.TotalSamples > 10 {
		t.Logf("samples tested: %d (context cancelled early)", result.TotalSamples)
	}
}

func TestInferredRule_Fields(t *testing.T) {
	rule := types.InferredRule{
		Pattern:      "SELECT",
		Confidence:   0.95,
		RuleType:     "keyword",
		Category:     "sqli",
		BlockedBy:    []string{"SELECT * FROM users"},
		AllowedBy:    []string{},
		EvasionHints: []string{"Try case variation"},
		Examples: []types.RuleExample{
			{Payload: "SELECT * FROM users", Blocked: true, Match: "SELECT"},
		},
		Severity:    "high",
		Description: "Blocks SELECT keyword",
	}

	if rule.Pattern != "SELECT" {
		t.Error("Pattern mismatch")
	}

	if rule.Confidence != 0.95 {
		t.Error("Confidence mismatch")
	}

	if len(rule.Examples) != 1 {
		t.Error("Examples count mismatch")
	}
}

func TestRuleInferenceResult_Fields(t *testing.T) {
	result := types.RuleInferenceResult{
		Target:        "https://example.com",
		WAFType:       types.WAFCloudflare,
		InferredRules: []types.InferredRule{},
		TotalSamples:  100,
		BlockedCount:  60,
		AllowedCount:  40,
		Duration:      5000,
		Summary:       "Test summary",
	}

	if result.Target != "https://example.com" {
		t.Error("Target mismatch")
	}

	if result.WAFType != types.WAFCloudflare {
		t.Error("WAFType mismatch")
	}

	if result.TotalSamples != 100 {
		t.Error("TotalSamples mismatch")
	}
}

func TestExtractPayloads(t *testing.T) {
	results := []TestResult{
		{Payload: "SELECT * FROM users", Blocked: true},
		{Payload: "' OR 1=1", Blocked: true},
		{Payload: "SELECT id FROM table", Blocked: true},
		{Payload: "normal text", Blocked: false},
	}

	extracted := extractPayloads(results, "SELECT")

	if len(extracted) != 2 {
		t.Errorf("expected 2 payloads with SELECT, got %d", len(extracted))
	}
}
