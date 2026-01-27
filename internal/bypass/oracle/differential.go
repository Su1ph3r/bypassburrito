package oracle

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// DifferentialAnalyzer performs body diffing and comparison
type DifferentialAnalyzer struct {
	significantPatterns []string
}

// NewDifferentialAnalyzer creates a new differential analyzer
func NewDifferentialAnalyzer() *DifferentialAnalyzer {
	return &DifferentialAnalyzer{
		significantPatterns: []string{
			"blocked", "denied", "forbidden", "error",
			"rejected", "invalid", "malicious", "attack",
			"firewall", "waf", "security", "violation",
		},
	}
}

// DiffResponses performs semantic body comparison
func (d *DifferentialAnalyzer) DiffResponses(baseline, test *types.HTTPResponse) *types.DifferentialAnalysis {
	analysis := &types.DifferentialAnalysis{
		BaselineResponse: baseline,
		TestResponse:     test,
	}

	if baseline == nil || test == nil {
		return analysis
	}

	// Status code difference
	analysis.StatusDiff = baseline.StatusCode != test.StatusCode

	// Header differences
	analysis.HeaderDiff = d.diffHeaders(baseline.Headers, test.Headers)

	// Body differences
	analysis.BodyDiff = d.diffBodies(baseline.Body, test.Body)

	// Latency difference
	analysis.LatencyDiff = test.Latency - baseline.Latency

	// Determine if significant
	analysis.Significant = d.isSignificant(analysis)

	// Build interpretation
	analysis.Interpretation = d.interpret(analysis)

	return analysis
}

// diffHeaders finds differences between header maps
func (d *DifferentialAnalyzer) diffHeaders(baseline, test map[string]string) []string {
	var diffs []string

	// Check for added or changed headers in test
	for k, v := range test {
		if baseVal, ok := baseline[k]; !ok {
			diffs = append(diffs, "+"+k+": "+v)
		} else if baseVal != v {
			diffs = append(diffs, "~"+k+": "+baseVal+" -> "+v)
		}
	}

	// Check for removed headers
	for k, v := range baseline {
		if _, ok := test[k]; !ok {
			diffs = append(diffs, "-"+k+": "+v)
		}
	}

	return diffs
}

// diffBodies performs content-level body comparison
func (d *DifferentialAnalyzer) diffBodies(baseline, test string) types.BodyDiff {
	diff := types.BodyDiff{
		LengthDiff: len(test) - len(baseline),
	}

	// Calculate similarity ratio using Levenshtein-based similarity
	diff.SimilarityRatio = d.calculateSimilarity(baseline, test)

	// Find added and removed patterns
	diff.AddedPatterns = d.findPatterns(test, baseline)
	diff.RemovedPatterns = d.findPatterns(baseline, test)

	// Check for structural differences (basic HTML structure check)
	diff.StructureDiff = d.checkStructuralDiff(baseline, test)

	return diff
}

// calculateSimilarity computes similarity ratio between two strings
func (d *DifferentialAnalyzer) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Use a simplified approach for large strings
	if len(s1) > 10000 || len(s2) > 10000 {
		return d.calculateHashSimilarity(s1, s2)
	}

	// Calculate Levenshtein distance
	distance := d.levenshteinDistance(s1, s2)
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	return 1.0 - float64(distance)/float64(maxLen)
}

// levenshteinDistance calculates edit distance between two strings
func (d *DifferentialAnalyzer) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Use only two rows to reduce memory usage
	prev := make([]int, len(s2)+1)
	curr := make([]int, len(s2)+1)

	for j := 0; j <= len(s2); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(s1); i++ {
		curr[0] = i
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			curr[j] = min(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}

	return prev[len(s2)]
}

// calculateHashSimilarity uses chunking for large strings
func (d *DifferentialAnalyzer) calculateHashSimilarity(s1, s2 string) float64 {
	chunkSize := 1000
	chunks1 := d.chunkString(s1, chunkSize)
	chunks2 := d.chunkString(s2, chunkSize)

	// Create hash sets
	set1 := make(map[string]bool)
	for _, chunk := range chunks1 {
		hash := sha256.Sum256([]byte(chunk))
		set1[hex.EncodeToString(hash[:])] = true
	}

	// Count matches
	matches := 0
	for _, chunk := range chunks2 {
		hash := sha256.Sum256([]byte(chunk))
		if set1[hex.EncodeToString(hash[:])] {
			matches++
		}
	}

	maxChunks := len(chunks1)
	if len(chunks2) > maxChunks {
		maxChunks = len(chunks2)
	}

	if maxChunks == 0 {
		return 0.0
	}

	return float64(matches) / float64(maxChunks)
}

// chunkString splits a string into chunks
func (d *DifferentialAnalyzer) chunkString(s string, size int) []string {
	var chunks []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// findPatterns finds significant patterns in s1 that are not in s2
func (d *DifferentialAnalyzer) findPatterns(s1, s2 string) []string {
	var found []string
	lower1 := strings.ToLower(s1)
	lower2 := strings.ToLower(s2)

	for _, pattern := range d.significantPatterns {
		if strings.Contains(lower1, pattern) && !strings.Contains(lower2, pattern) {
			found = append(found, pattern)
		}
	}

	return found
}

// checkStructuralDiff checks for HTML structure differences
func (d *DifferentialAnalyzer) checkStructuralDiff(s1, s2 string) bool {
	// Extract HTML tags for structural comparison
	tagPattern := regexp.MustCompile(`</?[a-zA-Z][^>]*>`)

	tags1 := tagPattern.FindAllString(s1, -1)
	tags2 := tagPattern.FindAllString(s2, -1)

	if len(tags1) != len(tags2) {
		return true
	}

	// Simple tag sequence comparison
	for i := range tags1 {
		// Normalize tags (lowercase, remove attributes)
		t1 := strings.ToLower(strings.Split(tags1[i], " ")[0])
		t2 := strings.ToLower(strings.Split(tags2[i], " ")[0])
		if t1 != t2 {
			return true
		}
	}

	return false
}

// isSignificant determines if the differences are significant
func (d *DifferentialAnalyzer) isSignificant(analysis *types.DifferentialAnalysis) bool {
	// Status code change is always significant
	if analysis.StatusDiff {
		return true
	}

	// Significant header changes
	for _, h := range analysis.HeaderDiff {
		// Look for security-related headers
		lower := strings.ToLower(h)
		if strings.Contains(lower, "waf") ||
			strings.Contains(lower, "security") ||
			strings.Contains(lower, "blocked") ||
			strings.Contains(lower, "cf-ray") {
			return true
		}
	}

	// Large body difference
	if analysis.BodyDiff.SimilarityRatio < 0.5 {
		return true
	}

	// New security patterns appeared
	if len(analysis.BodyDiff.AddedPatterns) > 0 {
		return true
	}

	// Structural change
	if analysis.BodyDiff.StructureDiff {
		return true
	}

	return false
}

// interpret builds a human-readable interpretation
func (d *DifferentialAnalyzer) interpret(analysis *types.DifferentialAnalysis) string {
	var parts []string

	if analysis.StatusDiff {
		parts = append(parts, "Status code changed")
	}

	if len(analysis.HeaderDiff) > 0 {
		parts = append(parts, "Headers modified")
	}

	if analysis.BodyDiff.SimilarityRatio < 0.5 {
		parts = append(parts, "Body significantly different")
	} else if analysis.BodyDiff.SimilarityRatio < 0.9 {
		parts = append(parts, "Body moderately different")
	}

	if len(analysis.BodyDiff.AddedPatterns) > 0 {
		parts = append(parts, "Security patterns detected: "+strings.Join(analysis.BodyDiff.AddedPatterns, ", "))
	}

	if analysis.BodyDiff.StructureDiff {
		parts = append(parts, "HTML structure changed")
	}

	if len(parts) == 0 {
		return "Responses are similar"
	}

	return strings.Join(parts, "; ")
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
