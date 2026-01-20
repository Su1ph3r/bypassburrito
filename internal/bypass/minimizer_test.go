package bypass

import (
	"context"
	"testing"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// mockHTTPClient implements HTTPClient for testing
type mockHTTPClient struct {
	responses map[string]*types.HTTPResponse
	blocked   map[string]bool
}

func newMockHTTPClient() *mockHTTPClient {
	return &mockHTTPClient{
		responses: make(map[string]*types.HTTPResponse),
		blocked:   make(map[string]bool),
	}
}

func (m *mockHTTPClient) Do(ctx context.Context, req *types.HTTPRequest) (*types.HTTPResponse, error) {
	// Check if the payload in the URL is blocked
	for pattern, blocked := range m.blocked {
		if blocked && containsPattern(req.URL, pattern) {
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

func (m *mockHTTPClient) setBlocked(pattern string, blocked bool) {
	m.blocked[pattern] = blocked
}

func containsPattern(url, pattern string) bool {
	return len(pattern) > 0 && len(url) >= len(pattern) &&
		(url == pattern || findSubstring(url, pattern))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestNewMinimizer(t *testing.T) {
	client := newMockHTTPClient()

	t.Run("default max attempts", func(t *testing.T) {
		m := NewMinimizer(client, 0)
		if m.maxAttempts != 50 {
			t.Errorf("expected default maxAttempts=50, got %d", m.maxAttempts)
		}
	})

	t.Run("custom max attempts", func(t *testing.T) {
		m := NewMinimizer(client, 100)
		if m.maxAttempts != 100 {
			t.Errorf("expected maxAttempts=100, got %d", m.maxAttempts)
		}
	})
}

func TestMinimizer_Minimize_WorkingPayload(t *testing.T) {
	client := newMockHTTPClient()
	// Block SELECT but not SELEC or other substrings
	client.setBlocked("SELECT", true)

	minimizer := NewMinimizer(client, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test with a payload that works (doesn't contain SELECT)
	req := MinimizeRequest{
		Target: types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "GET",
			Parameter: "id",
			Position:  types.PositionQuery,
		},
		WorkingPayload: "' OR '1'='1",
		AttackType:     types.AttackSQLi,
	}

	result, err := minimizer.Minimize(ctx, req)
	if err != nil {
		t.Fatalf("Minimize failed: %v", err)
	}

	if !result.StillWorks {
		t.Error("expected StillWorks=true for working payload")
	}

	if result.Original != req.WorkingPayload {
		t.Errorf("expected Original=%q, got %q", req.WorkingPayload, result.Original)
	}
}

func TestMinimizer_Minimize_NonWorkingPayload(t *testing.T) {
	client := newMockHTTPClient()
	// Block everything by blocking a common pattern that will match the payload
	client.setBlocked("blocked", true)

	minimizer := NewMinimizer(client, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := MinimizeRequest{
		Target: types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "GET",
			Parameter: "id",
			Position:  types.PositionQuery,
		},
		WorkingPayload: "blocked_payload",
		AttackType:     types.AttackSQLi,
	}

	result, err := minimizer.Minimize(ctx, req)
	if err != nil {
		t.Fatalf("Minimize failed: %v", err)
	}

	if result.StillWorks {
		t.Error("expected StillWorks=false for blocked payload")
	}
}

func TestMinimizer_BinarySearchMinimize(t *testing.T) {
	minimizer := &Minimizer{maxAttempts: 100}

	testCases := []struct {
		name     string
		payload  string
		testFunc func(string) bool
	}{
		{
			name:    "empty payload",
			payload: "",
			testFunc: func(s string) bool {
				return true
			},
		},
		{
			name:    "single char",
			payload: "x",
			testFunc: func(s string) bool {
				return true
			},
		},
		{
			name:    "all chars required",
			payload: "abc",
			testFunc: func(s string) bool {
				return s == "abc"
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result, iters := minimizer.binarySearchMinimize(tc.payload, tc.testFunc, ctx)

			// Result should still work
			if !tc.testFunc(result) {
				t.Errorf("minimized result %q doesn't pass test function", result)
			}

			t.Logf("payload=%q -> result=%q (iters=%d)", tc.payload, result, iters)
		})
	}
}

func TestMinimizer_DeltaDebugging(t *testing.T) {
	minimizer := &Minimizer{maxAttempts: 100}

	t.Run("reduce to minimum", func(t *testing.T) {
		ctx := context.Background()

		// Test function that only needs 'ab' from 'abcdef'
		testFunc := func(s string) bool {
			return findSubstring(s, "ab")
		}

		result, _ := minimizer.deltaDebugging("abcdef", testFunc, ctx)

		if !testFunc(result) {
			t.Errorf("result %q doesn't pass test", result)
		}

		// Should be shorter than or equal to original
		if len(result) > len("abcdef") {
			t.Errorf("result %q longer than original", result)
		}
	})
}

func TestMinimizer_CharacterRemoval(t *testing.T) {
	minimizer := &Minimizer{maxAttempts: 100}

	t.Run("remove unnecessary chars", func(t *testing.T) {
		ctx := context.Background()

		// Test that needs 'xyz' but input has extra chars
		testFunc := func(s string) bool {
			return findSubstring(s, "xyz")
		}

		result, _ := minimizer.characterRemoval("xxyzz", testFunc, ctx)

		if !testFunc(result) {
			t.Errorf("result %q doesn't pass test", result)
		}

		if len(result) > len("xxyzz") {
			t.Errorf("result should not be longer than input")
		}
	})
}

func TestMinimizer_TokenSimplification(t *testing.T) {
	minimizer := &Minimizer{maxAttempts: 100}

	t.Run("sqli simplification", func(t *testing.T) {
		ctx := context.Background()

		// Simple test that accepts any string
		testFunc := func(s string) bool {
			return true
		}

		result, iters := minimizer.tokenSimplification("' OR 1=1--", types.AttackSQLi, testFunc, ctx)

		t.Logf("input=%q -> result=%q (iters=%d)", "' OR 1=1--", result, iters)
	})
}

func TestMinimizer_IdentifyParts(t *testing.T) {
	minimizer := &Minimizer{}

	t.Run("identify essential parts", func(t *testing.T) {
		original := "' OR 1=1--"
		minimized := "' OR 1"

		essential := minimizer.identifyEssentialParts(original, minimized)

		if len(essential) == 0 {
			t.Error("expected some essential parts")
		}
	})

	t.Run("identify removed parts", func(t *testing.T) {
		original := "' OR 1=1--"
		minimized := "' OR 1"

		removed := minimizer.identifyRemovedParts(original, minimized)

		t.Logf("removed parts: %v", removed)
	})
}

func TestMinimizer_Tokenize(t *testing.T) {
	minimizer := &Minimizer{}

	testCases := []struct {
		input    string
		minCount int
	}{
		{"", 0},
		{"abc", 1},
		{"a b c", 5}, // a, space, b, space, c
		{"<script>alert(1)</script>", 8},
		{"' OR 1=1--", 5}, // ', space, OR, space, 1=1--
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			tokens := minimizer.tokenize(tc.input)
			if len(tokens) < tc.minCount {
				t.Errorf("expected at least %d tokens, got %d: %v", tc.minCount, len(tokens), tokens)
			}
		})
	}
}

func TestMinimizer_BuildRequest(t *testing.T) {
	minimizer := &Minimizer{}

	t.Run("query position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "GET",
			Parameter: "id",
			Position:  types.PositionQuery,
		}

		req := minimizer.buildRequest(target, "test_payload")

		if req.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", req.Method)
		}

		if !findSubstring(req.URL, "id=test_payload") {
			t.Errorf("expected URL to contain payload, got %s", req.URL)
		}
	})

	t.Run("body position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "POST",
			Parameter: "data",
			Position:  types.PositionBody,
		}

		req := minimizer.buildRequest(target, "test_payload")

		if req.Method != "POST" {
			t.Errorf("expected Method=POST, got %s", req.Method)
		}
	})

	t.Run("header position", func(t *testing.T) {
		target := types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "GET",
			Parameter: "X-Custom",
			Position:  types.PositionHeader,
		}

		req := minimizer.buildRequest(target, "test_value")

		if val, ok := req.Headers["X-Custom"]; !ok || val != "test_value" {
			t.Errorf("expected header X-Custom=test_value")
		}
	})
}

func TestMinimizer_ContextCancellation(t *testing.T) {
	client := newMockHTTPClient()
	minimizer := NewMinimizer(client, 1000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := MinimizeRequest{
		Target: types.TargetConfig{
			URL:       "http://example.com/api",
			Method:    "GET",
			Parameter: "id",
			Position:  types.PositionQuery,
		},
		WorkingPayload: "test_payload",
		AttackType:     types.AttackSQLi,
	}

	result, err := minimizer.Minimize(ctx, req)
	if err != nil {
		t.Fatalf("expected no error on cancellation, got %v", err)
	}

	// Should return early due to cancellation
	if result.Iterations > 10 {
		t.Errorf("expected few iterations due to cancellation, got %d", result.Iterations)
	}
}

func TestMinimizationResult_Fields(t *testing.T) {
	result := &types.MinimizationResult{
		Original:         "original_payload",
		Minimized:        "min",
		Reduction:        81.25,
		Iterations:       10,
		StillWorks:       true,
		EssentialParts:   []string{"min"},
		RemovedParts:     []string{"original_payload"},
		Duration:         100 * time.Millisecond,
		MinimizationPath: []string{"original_payload", "min"},
	}

	if result.Original != "original_payload" {
		t.Error("Original field mismatch")
	}

	if result.Reduction != 81.25 {
		t.Error("Reduction field mismatch")
	}

	if !result.StillWorks {
		t.Error("StillWorks should be true")
	}
}
