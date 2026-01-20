package bypass

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Minimizer reduces payloads to their minimum viable form
type Minimizer struct {
	httpClient  HTTPClient
	analyzer    *ResponseAnalyzer
	maxAttempts int
}

// MinimizeRequest holds the request for minimization
type MinimizeRequest struct {
	Target         types.TargetConfig
	WorkingPayload string
	AttackType     types.AttackType
}

// NewMinimizer creates a new payload minimizer
func NewMinimizer(client HTTPClient, maxAttempts int) *Minimizer {
	if maxAttempts <= 0 {
		maxAttempts = 50
	}
	return &Minimizer{
		httpClient:  client,
		analyzer:    NewResponseAnalyzer(),
		maxAttempts: maxAttempts,
	}
}

// Minimize reduces a working payload to its minimum form
func (m *Minimizer) Minimize(ctx context.Context, req MinimizeRequest) (*types.MinimizationResult, error) {
	start := time.Now()

	result := &types.MinimizationResult{
		Original:         req.WorkingPayload,
		Minimized:        req.WorkingPayload,
		Reduction:        0,
		Iterations:       0,
		StillWorks:       true,
		MinimizationPath: []string{req.WorkingPayload},
	}

	// Test function to verify payload still works
	testFn := func(payload string) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		httpReq := m.buildRequest(req.Target, payload)
		resp, err := m.httpClient.Do(ctx, httpReq)
		if err != nil {
			return false
		}

		analysis := m.analyzer.Analyze(resp)
		return analysis.Classification == types.ClassificationAllowed
	}

	// First verify the original works
	if !testFn(req.WorkingPayload) {
		result.StillWorks = false
		result.Duration = time.Since(start)
		return result, nil
	}

	// Apply multiple minimization techniques
	minimized := req.WorkingPayload
	iterations := 0

	// Phase 1: Binary search reduction
	minimized, iters := m.binarySearchMinimize(minimized, testFn, ctx)
	iterations += iters
	if minimized != result.Minimized {
		result.MinimizationPath = append(result.MinimizationPath, minimized)
	}

	// Phase 2: Delta debugging
	minimized, iters = m.deltaDebugging(minimized, testFn, ctx)
	iterations += iters
	if minimized != result.MinimizationPath[len(result.MinimizationPath)-1] {
		result.MinimizationPath = append(result.MinimizationPath, minimized)
	}

	// Phase 3: Character-by-character removal
	minimized, iters = m.characterRemoval(minimized, testFn, ctx)
	iterations += iters
	if minimized != result.MinimizationPath[len(result.MinimizationPath)-1] {
		result.MinimizationPath = append(result.MinimizationPath, minimized)
	}

	// Phase 4: Token simplification (for SQL, XSS, etc.)
	minimized, iters = m.tokenSimplification(minimized, req.AttackType, testFn, ctx)
	iterations += iters
	if minimized != result.MinimizationPath[len(result.MinimizationPath)-1] {
		result.MinimizationPath = append(result.MinimizationPath, minimized)
	}

	// Verify final result
	result.Minimized = minimized
	result.StillWorks = testFn(minimized)
	result.Iterations = iterations
	result.Duration = time.Since(start)

	// Calculate reduction
	if len(req.WorkingPayload) > 0 {
		result.Reduction = float64(len(req.WorkingPayload)-len(minimized)) / float64(len(req.WorkingPayload)) * 100
	}

	// Identify essential parts
	result.EssentialParts = m.identifyEssentialParts(req.WorkingPayload, minimized)
	result.RemovedParts = m.identifyRemovedParts(req.WorkingPayload, minimized)

	return result, nil
}

// binarySearchMinimize uses binary search to find minimum payload
func (m *Minimizer) binarySearchMinimize(payload string, testFn func(string) bool, ctx context.Context) (string, int) {
	if len(payload) <= 1 {
		return payload, 0
	}

	iterations := 0
	current := payload

	// Try removing larger chunks first
	for chunkSize := len(current) / 2; chunkSize >= 1 && iterations < m.maxAttempts; chunkSize /= 2 {
		select {
		case <-ctx.Done():
			return current, iterations
		default:
		}

		changed := true
		for changed && iterations < m.maxAttempts {
			changed = false
			for i := 0; i <= len(current)-chunkSize && iterations < m.maxAttempts; i++ {
				select {
				case <-ctx.Done():
					return current, iterations
				default:
				}

				// Try removing chunk at position i
				candidate := current[:i] + current[i+chunkSize:]
				iterations++

				if testFn(candidate) {
					current = candidate
					changed = true
					break // Start over with new string
				}
			}
		}
	}

	return current, iterations
}

// deltaDebugging implements the delta debugging algorithm
func (m *Minimizer) deltaDebugging(payload string, testFn func(string) bool, ctx context.Context) (string, int) {
	if len(payload) <= 1 {
		return payload, 0
	}

	iterations := 0
	n := 2 // Start with 2 partitions

	chars := []rune(payload)
	for n <= len(chars) && iterations < m.maxAttempts {
		select {
		case <-ctx.Done():
			return string(chars), iterations
		default:
		}

		chunkSize := len(chars) / n
		if chunkSize == 0 {
			break
		}

		foundReduction := false

		// Try removing each partition
		for i := 0; i < n && iterations < m.maxAttempts; i++ {
			select {
			case <-ctx.Done():
				return string(chars), iterations
			default:
			}

			start := i * chunkSize
			end := start + chunkSize
			if i == n-1 {
				end = len(chars)
			}

			// Create candidate without this partition
			candidate := make([]rune, 0, len(chars)-(end-start))
			candidate = append(candidate, chars[:start]...)
			candidate = append(candidate, chars[end:]...)

			iterations++

			if testFn(string(candidate)) {
				chars = candidate
				foundReduction = true
				n = max(n-1, 2) // Reduce partitions but keep at least 2
				break
			}
		}

		if !foundReduction {
			n *= 2 // Double partitions if no reduction found
		}
	}

	return string(chars), iterations
}

// characterRemoval tries removing individual characters
func (m *Minimizer) characterRemoval(payload string, testFn func(string) bool, ctx context.Context) (string, int) {
	if len(payload) <= 1 {
		return payload, 0
	}

	iterations := 0
	current := payload

	changed := true
	for changed && iterations < m.maxAttempts {
		changed = false
		chars := []rune(current)

		for i := 0; i < len(chars) && iterations < m.maxAttempts; i++ {
			select {
			case <-ctx.Done():
				return current, iterations
			default:
			}

			// Try removing character at position i
			candidate := string(chars[:i]) + string(chars[i+1:])
			iterations++

			if testFn(candidate) {
				current = candidate
				changed = true
				break
			}
		}
	}

	return current, iterations
}

// tokenSimplification simplifies based on attack type tokens
func (m *Minimizer) tokenSimplification(payload string, attackType types.AttackType, testFn func(string) bool, ctx context.Context) (string, int) {
	iterations := 0
	current := payload

	// Get simplification rules for attack type
	rules := m.getSimplificationRules(attackType)

	for _, rule := range rules {
		select {
		case <-ctx.Done():
			return current, iterations
		default:
		}

		if iterations >= m.maxAttempts {
			break
		}

		// Try each simplification
		for _, replacement := range rule.replacements {
			if !strings.Contains(current, rule.pattern) {
				continue
			}

			candidate := strings.Replace(current, rule.pattern, replacement, 1)
			iterations++

			if testFn(candidate) {
				current = candidate
				break
			}
		}
	}

	return current, iterations
}

type simplificationRule struct {
	pattern      string
	replacements []string
}

func (m *Minimizer) getSimplificationRules(attackType types.AttackType) []simplificationRule {
	var rules []simplificationRule

	switch attackType {
	case types.AttackSQLi:
		rules = []simplificationRule{
			// Remove unnecessary SQL keywords
			{" OR ", []string{" "}},
			{" AND ", []string{" "}},
			{" UNION ", []string{" "}},
			// Simplify conditions
			{"1=1", []string{"1"}},
			{"'1'='1'", []string{"1"}},
			// Remove comments
			{"/**/", []string{" ", ""}},
			{"--", []string{""}},
			{"#", []string{""}},
			// Simplify quotes
			{"''", []string{"'"}},
			{"\"\"", []string{"\""}},
		}

	case types.AttackXSS:
		rules = []simplificationRule{
			// Simplify tags
			{"<script>alert(1)</script>", []string{"<script>alert(1)"}},
			{"</script>", []string{""}},
			{"javascript:", []string{""}},
			// Simplify event handlers
			{"onclick=", []string{"on"}},
			{"onerror=", []string{"on"}},
			// Remove unnecessary attributes
			{" src=x", []string{""}},
			{" href=x", []string{""}},
		}

	case types.AttackCmdInjection:
		rules = []simplificationRule{
			// Simplify command separators
			{"; ", []string{";"}},
			{" | ", []string{"|"}},
			{" && ", []string{"&"}},
			// Remove unnecessary parts
			{"echo ", []string{""}},
			{"whoami", []string{"id"}},
		}

	case types.AttackPathTraversal:
		rules = []simplificationRule{
			// Simplify path traversal
			{"../../../", []string{"../"}},
			{"..\\..\\..\\", []string{"..\\"}},
			{"%2e%2e%2f", []string{"../"}},
		}
	}

	return rules
}

// identifyEssentialParts finds what parts of the payload are essential
func (m *Minimizer) identifyEssentialParts(original, minimized string) []string {
	var essential []string

	// Simple approach: split minimized into tokens
	tokens := m.tokenize(minimized)
	for _, token := range tokens {
		if len(token) > 0 {
			essential = append(essential, token)
		}
	}

	return essential
}

// identifyRemovedParts finds what was removed during minimization
func (m *Minimizer) identifyRemovedParts(original, minimized string) []string {
	var removed []string

	// Find characters that were removed
	origTokens := m.tokenize(original)
	minTokens := m.tokenize(minimized)

	minSet := make(map[string]bool)
	for _, t := range minTokens {
		minSet[t] = true
	}

	for _, t := range origTokens {
		if !minSet[t] {
			removed = append(removed, t)
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, r := range removed {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}

	return unique
}

// tokenize splits a payload into meaningful tokens
func (m *Minimizer) tokenize(payload string) []string {
	// Split on common delimiters while preserving them
	delimiters := []rune{' ', '<', '>', '/', '\\', '\'', '"', ';', '|', '&', '=', '(', ')', '{', '}', '[', ']'}
	delimSet := make(map[rune]bool)
	for _, d := range delimiters {
		delimSet[d] = true
	}

	var tokens []string
	var current strings.Builder

	for _, r := range payload {
		if delimSet[r] {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(r))
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// buildRequest builds an HTTP request with the payload
func (m *Minimizer) buildRequest(target types.TargetConfig, payload string) *types.HTTPRequest {
	req := &types.HTTPRequest{
		Method:      target.Method,
		URL:         target.URL,
		Headers:     make(map[string]string),
		Cookies:     target.Cookies,
		ContentType: target.ContentType,
		Timestamp:   time.Now(),
	}

	// Copy headers
	for k, v := range target.Headers {
		req.Headers[k] = v
	}

	if target.AuthHeader != "" {
		req.Headers["Authorization"] = target.AuthHeader
	}

	// Insert payload based on position
	switch target.Position {
	case types.PositionQuery:
		if req.Method == "GET" || req.Method == "" {
			if target.Parameter != "" {
				separator := "?"
				if strings.Contains(req.URL, "?") {
					separator = "&"
				}
				req.URL = req.URL + separator + target.Parameter + "=" + payload
			}
		}
	case types.PositionBody:
		req.Body = injectIntoBody(target.Body, target.Parameter, payload, target.ContentType)
	case types.PositionHeader:
		req.Headers[target.Parameter] = payload
	case types.PositionCookie:
		if req.Cookies == nil {
			req.Cookies = make(map[string]string)
		}
		req.Cookies[target.Parameter] = payload
	case types.PositionPath:
		req.URL = replacePathParam(req.URL, target.Parameter, payload)
	}

	return req
}

// MinimizeMultiple minimizes multiple payloads and returns the best results
func (m *Minimizer) MinimizeMultiple(ctx context.Context, target types.TargetConfig, payloads []string, attackType types.AttackType) ([]*types.MinimizationResult, error) {
	var results []*types.MinimizationResult

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		req := MinimizeRequest{
			Target:         target,
			WorkingPayload: payload,
			AttackType:     attackType,
		}

		result, err := m.Minimize(ctx, req)
		if err != nil {
			continue
		}

		if result.StillWorks {
			results = append(results, result)
		}
	}

	// Sort by reduction percentage (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Reduction > results[j].Reduction
	})

	return results, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
