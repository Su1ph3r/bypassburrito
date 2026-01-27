package oracle

import (
	"math"
)

// ContentLengthAnalysis holds content-length anomaly detection results
type ContentLengthAnalysis struct {
	ExpectedLength int     `json:"expected_length"`
	ActualLength   int     `json:"actual_length"`
	Deviation      float64 `json:"deviation_percent"`
	IsAnomaly      bool    `json:"is_anomaly"`
	Pattern        string  `json:"pattern"` // "truncated", "padded", "normal"
}

// ContentLengthAnalyzer detects content-length anomalies
type ContentLengthAnalyzer struct {
	threshold float64 // Deviation threshold (e.g., 0.1 = 10%)
	history   []int   // Historical content lengths for baseline
}

// NewContentLengthAnalyzer creates a new content length analyzer
func NewContentLengthAnalyzer(threshold float64) *ContentLengthAnalyzer {
	if threshold <= 0 {
		threshold = 0.1 // Default 10%
	}
	return &ContentLengthAnalyzer{
		threshold: threshold,
		history:   make([]int, 0, 100),
	}
}

// AnalyzeContentLength compares expected and actual content lengths
func (c *ContentLengthAnalyzer) AnalyzeContentLength(expected, actual int) *ContentLengthAnalysis {
	analysis := &ContentLengthAnalysis{
		ExpectedLength: expected,
		ActualLength:   actual,
		Pattern:        "normal",
	}

	if expected == 0 {
		return analysis
	}

	// Calculate deviation
	diff := float64(actual - expected)
	analysis.Deviation = diff / float64(expected)

	// Determine pattern
	if math.Abs(analysis.Deviation) > c.threshold {
		analysis.IsAnomaly = true
		if analysis.Deviation < 0 {
			analysis.Pattern = "truncated"
		} else {
			analysis.Pattern = "padded"
		}
	}

	return analysis
}

// RecordLength records a content length for historical analysis
func (c *ContentLengthAnalyzer) RecordLength(length int) {
	c.history = append(c.history, length)
	// Keep last 100 samples
	if len(c.history) > 100 {
		c.history = c.history[1:]
	}
}

// AnalyzeAgainstHistory compares a length against historical baseline
func (c *ContentLengthAnalyzer) AnalyzeAgainstHistory(length int) *ContentLengthAnalysis {
	if len(c.history) == 0 {
		return c.AnalyzeContentLength(length, length)
	}

	// Calculate historical average
	var sum int
	for _, l := range c.history {
		sum += l
	}
	avg := sum / len(c.history)

	return c.AnalyzeContentLength(avg, length)
}

// GetHistoricalStats returns statistics about recorded lengths
func (c *ContentLengthAnalyzer) GetHistoricalStats() (avg int, min int, max int, stdDev float64) {
	if len(c.history) == 0 {
		return 0, 0, 0, 0
	}

	sum := 0
	minVal := c.history[0]
	maxVal := c.history[0]

	for _, l := range c.history {
		sum += l
		if l < minVal {
			minVal = l
		}
		if l > maxVal {
			maxVal = l
		}
	}

	avg = sum / len(c.history)

	// Calculate standard deviation
	var variance float64
	for _, l := range c.history {
		diff := float64(l - avg)
		variance += diff * diff
	}
	variance /= float64(len(c.history))
	stdDev = math.Sqrt(variance)

	return avg, minVal, maxVal, stdDev
}

// DetectConsistentLength checks if lengths are consistent (low variance)
func (c *ContentLengthAnalyzer) DetectConsistentLength() bool {
	if len(c.history) < 3 {
		return true
	}

	avg, _, _, stdDev := c.GetHistoricalStats()
	if avg == 0 {
		return true
	}

	// Coefficient of variation should be low for consistent lengths
	cv := stdDev / float64(avg)
	return cv < 0.1 // Less than 10% variation
}

// ClassifyLengthPattern analyzes the pattern of content lengths
func (c *ContentLengthAnalyzer) ClassifyLengthPattern() string {
	if len(c.history) < 5 {
		return "insufficient_data"
	}

	avg, minVal, maxVal, stdDev := c.GetHistoricalStats()

	// Check for bimodal distribution (blocked vs allowed responses)
	if float64(maxVal-minVal) > float64(avg)*0.5 {
		// Large range suggests different response types
		return "bimodal"
	}

	// Check for high variance
	if stdDev > float64(avg)*0.2 {
		return "high_variance"
	}

	// Check for consistent lengths
	if stdDev < float64(avg)*0.05 {
		return "consistent"
	}

	return "moderate_variance"
}
