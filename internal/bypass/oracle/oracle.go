// Package oracle provides advanced response analysis capabilities for WAF bypass detection
package oracle

import (
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ResponseOracle provides advanced response analysis capabilities
type ResponseOracle interface {
	// AnalyzeWithBaseline compares a response against baseline for anomalies
	AnalyzeWithBaseline(resp *types.HTTPResponse, baseline *types.HTTPResponse) *OracleAnalysis

	// DetectTimingAnomaly checks for timing-based detection
	DetectTimingAnomaly(responses []*types.HTTPResponse) *TimingAnalysis

	// FingerprintError extracts structured error information
	FingerprintError(resp *types.HTTPResponse) *ErrorFingerprint

	// DiffBodies performs semantic body comparison
	DiffBodies(baseline, test *types.HTTPResponse) *types.DifferentialAnalysis

	// RecordBaseline stores a baseline response for future comparisons
	RecordBaseline(resp *types.HTTPResponse)

	// GetBaselineStats returns statistics about recorded baselines
	GetBaselineStats() *BaselineStats
}

// OracleAnalysis represents comprehensive oracle analysis results
type OracleAnalysis struct {
	Timing            *TimingAnalysis            `json:"timing"`
	Differential      *types.DifferentialAnalysis `json:"differential"`
	Error             *ErrorFingerprint          `json:"error"`
	ContentLen        *ContentLengthAnalysis     `json:"content_length"`
	OverallConfidence float64                    `json:"overall_confidence"`
	Classification    types.ResponseClassification `json:"classification"`
	Reasoning         string                     `json:"reasoning"`
}

// BaselineStats holds statistics about recorded baseline responses
type BaselineStats struct {
	SampleCount       int           `json:"sample_count"`
	AverageLatency    time.Duration `json:"average_latency"`
	LatencyStdDev     float64       `json:"latency_std_dev"`
	AverageBodyLength int           `json:"average_body_length"`
	BodyLengthStdDev  float64       `json:"body_length_std_dev"`
}

// DefaultOracle implements ResponseOracle with configurable thresholds
type DefaultOracle struct {
	config           OracleConfig
	baselines        []*types.HTTPResponse
	timingAnalyzer   *TimingAnalyzer
	diffAnalyzer     *DifferentialAnalyzer
	fingerprintAnalyzer *FingerprintAnalyzer
	contentAnalyzer  *ContentLengthAnalyzer
}

// OracleConfig holds configuration for the response oracle
type OracleConfig struct {
	Enabled                bool    `yaml:"enabled" mapstructure:"enabled"`
	TimingThreshold        float64 `yaml:"timing_threshold" mapstructure:"timing_threshold"`
	ContentLengthThreshold float64 `yaml:"content_length_threshold" mapstructure:"content_length_threshold"`
	BaselineSamples        int     `yaml:"baseline_samples" mapstructure:"baseline_samples"`
	ErrorFingerprinting    bool    `yaml:"error_fingerprinting" mapstructure:"error_fingerprinting"`
}

// DefaultOracleConfig returns sensible defaults
func DefaultOracleConfig() OracleConfig {
	return OracleConfig{
		Enabled:                true,
		TimingThreshold:        0.3,  // 30% deviation
		ContentLengthThreshold: 0.1,  // 10% deviation
		BaselineSamples:        5,
		ErrorFingerprinting:    true,
	}
}

// NewDefaultOracle creates a new oracle with the given configuration
func NewDefaultOracle(config OracleConfig) *DefaultOracle {
	return &DefaultOracle{
		config:              config,
		baselines:          make([]*types.HTTPResponse, 0, config.BaselineSamples),
		timingAnalyzer:     NewTimingAnalyzer(config.TimingThreshold),
		diffAnalyzer:       NewDifferentialAnalyzer(),
		fingerprintAnalyzer: NewFingerprintAnalyzer(),
		contentAnalyzer:    NewContentLengthAnalyzer(config.ContentLengthThreshold),
	}
}

// RecordBaseline stores a baseline response
func (o *DefaultOracle) RecordBaseline(resp *types.HTTPResponse) {
	if len(o.baselines) < o.config.BaselineSamples {
		o.baselines = append(o.baselines, resp)
	}
}

// GetBaselineStats returns statistics about recorded baselines
func (o *DefaultOracle) GetBaselineStats() *BaselineStats {
	if len(o.baselines) == 0 {
		return &BaselineStats{}
	}

	var totalLatency time.Duration
	var totalLength int

	for _, b := range o.baselines {
		totalLatency += b.Latency
		totalLength += b.ContentLength
	}

	avgLatency := totalLatency / time.Duration(len(o.baselines))
	avgLength := totalLength / len(o.baselines)

	// Calculate standard deviations
	var latencyVariance, lengthVariance float64
	for _, b := range o.baselines {
		latDiff := float64(b.Latency - avgLatency)
		latencyVariance += latDiff * latDiff
		lenDiff := float64(b.ContentLength - avgLength)
		lengthVariance += lenDiff * lenDiff
	}

	n := float64(len(o.baselines))
	latencyStdDev := sqrt(latencyVariance / n)
	lengthStdDev := sqrt(lengthVariance / n)

	return &BaselineStats{
		SampleCount:       len(o.baselines),
		AverageLatency:    avgLatency,
		LatencyStdDev:     latencyStdDev,
		AverageBodyLength: avgLength,
		BodyLengthStdDev:  lengthStdDev,
	}
}

// AnalyzeWithBaseline compares a response against baseline for anomalies
func (o *DefaultOracle) AnalyzeWithBaseline(resp *types.HTTPResponse, baseline *types.HTTPResponse) *OracleAnalysis {
	analysis := &OracleAnalysis{
		OverallConfidence: 0.5,
		Classification:    types.ClassificationUnknown,
	}

	// Use provided baseline or first recorded baseline
	baselineResp := baseline
	if baselineResp == nil && len(o.baselines) > 0 {
		baselineResp = o.baselines[0]
	}

	if baselineResp == nil {
		analysis.Reasoning = "No baseline available for comparison"
		return analysis
	}

	// Timing analysis
	analysis.Timing = o.timingAnalyzer.AnalyzeTiming(baselineResp.Latency, resp.Latency)

	// Differential analysis
	analysis.Differential = o.diffAnalyzer.DiffResponses(baselineResp, resp)

	// Error fingerprinting
	if o.config.ErrorFingerprinting {
		analysis.Error = o.fingerprintAnalyzer.FingerprintError(resp)
	}

	// Content length analysis
	analysis.ContentLen = o.contentAnalyzer.AnalyzeContentLength(baselineResp.ContentLength, resp.ContentLength)

	// Calculate overall confidence and classification
	o.computeOverallClassification(analysis)

	return analysis
}

// DetectTimingAnomaly checks for timing-based detection across multiple responses
func (o *DefaultOracle) DetectTimingAnomaly(responses []*types.HTTPResponse) *TimingAnalysis {
	if len(responses) == 0 {
		return &TimingAnalysis{}
	}

	latencies := make([]time.Duration, len(responses))
	for i, r := range responses {
		latencies[i] = r.Latency
	}

	return o.timingAnalyzer.AnalyzeMultiple(latencies)
}

// FingerprintError extracts structured error information
func (o *DefaultOracle) FingerprintError(resp *types.HTTPResponse) *ErrorFingerprint {
	return o.fingerprintAnalyzer.FingerprintError(resp)
}

// DiffBodies performs semantic body comparison
func (o *DefaultOracle) DiffBodies(baseline, test *types.HTTPResponse) *types.DifferentialAnalysis {
	return o.diffAnalyzer.DiffResponses(baseline, test)
}

// computeOverallClassification determines the final classification
func (o *DefaultOracle) computeOverallClassification(analysis *OracleAnalysis) {
	var signals []float64
	var reasons []string

	// Timing signal
	if analysis.Timing != nil && analysis.Timing.IsAnomaly {
		if analysis.Timing.AnomalyType == "slower" {
			signals = append(signals, 0.7) // Slower often indicates more processing (blocked)
			reasons = append(reasons, "Response significantly slower than baseline")
		} else if analysis.Timing.AnomalyType == "faster" {
			signals = append(signals, 0.3) // Faster might indicate short-circuit (blocked)
			reasons = append(reasons, "Response significantly faster than baseline")
		}
	}

	// Content length signal
	if analysis.ContentLen != nil && analysis.ContentLen.IsAnomaly {
		if analysis.ContentLen.Pattern == "truncated" {
			signals = append(signals, 0.8) // Truncated often means blocked
			reasons = append(reasons, "Response body truncated")
		} else if analysis.ContentLen.Pattern == "padded" {
			signals = append(signals, 0.4) // Padded might indicate error page
			reasons = append(reasons, "Response body larger than expected")
		}
	}

	// Differential signal
	if analysis.Differential != nil && analysis.Differential.Significant {
		signals = append(signals, 0.7)
		reasons = append(reasons, "Significant difference from baseline")
	}

	// Error fingerprint signal
	if analysis.Error != nil && analysis.Error.Confidence > 0.5 {
		signals = append(signals, analysis.Error.Confidence)
		reasons = append(reasons, "Error fingerprint detected: "+analysis.Error.ErrorType)
	}

	// Calculate overall confidence
	if len(signals) > 0 {
		var sum float64
		for _, s := range signals {
			sum += s
		}
		analysis.OverallConfidence = sum / float64(len(signals))
	}

	// Determine classification based on confidence
	if analysis.OverallConfidence >= 0.7 {
		analysis.Classification = types.ClassificationBlocked
	} else if analysis.OverallConfidence <= 0.3 {
		analysis.Classification = types.ClassificationAllowed
	} else {
		analysis.Classification = types.ClassificationUnknown
	}

	// Build reasoning
	if len(reasons) > 0 {
		analysis.Reasoning = joinStrings(reasons, "; ")
	} else {
		analysis.Reasoning = "No significant anomalies detected"
	}
}

// sqrt is a simple square root implementation
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

// joinStrings joins strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
