package oracle

import (
	"math"
	"sort"
	"time"
)

// TimingAnalysis holds timing side-channel analysis results
type TimingAnalysis struct {
	BaselineLatency time.Duration `json:"baseline_latency"`
	TestLatency     time.Duration `json:"test_latency"`
	Deviation       float64       `json:"deviation_percent"`
	IsAnomaly       bool          `json:"is_anomaly"`
	AnomalyType     string        `json:"anomaly_type"` // "faster", "slower", "inconsistent"
	StatisticalZ    float64       `json:"statistical_z_score"`
	Samples         int           `json:"samples"`
	Mean            time.Duration `json:"mean,omitempty"`
	StdDev          float64       `json:"std_dev,omitempty"`
	Percentile95    time.Duration `json:"percentile_95,omitempty"`
}

// TimingAnalyzer analyzes response timing for side-channel detection
type TimingAnalyzer struct {
	threshold float64 // Deviation threshold (e.g., 0.3 = 30%)
}

// NewTimingAnalyzer creates a new timing analyzer
func NewTimingAnalyzer(threshold float64) *TimingAnalyzer {
	if threshold <= 0 {
		threshold = 0.3 // Default 30%
	}
	return &TimingAnalyzer{
		threshold: threshold,
	}
}

// AnalyzeTiming compares baseline and test latencies
func (t *TimingAnalyzer) AnalyzeTiming(baseline, test time.Duration) *TimingAnalysis {
	analysis := &TimingAnalysis{
		BaselineLatency: baseline,
		TestLatency:     test,
		Samples:         1,
	}

	if baseline == 0 {
		return analysis
	}

	// Calculate deviation
	diff := float64(test - baseline)
	analysis.Deviation = diff / float64(baseline)

	// Determine if anomaly
	if math.Abs(analysis.Deviation) > t.threshold {
		analysis.IsAnomaly = true
		if analysis.Deviation > 0 {
			analysis.AnomalyType = "slower"
		} else {
			analysis.AnomalyType = "faster"
		}
	}

	// Simple z-score (assuming baseline is the expected value)
	// This is a simplified calculation for single sample comparison
	analysis.StatisticalZ = analysis.Deviation / t.threshold

	return analysis
}

// AnalyzeMultiple analyzes multiple latency samples for statistical significance
func (t *TimingAnalyzer) AnalyzeMultiple(latencies []time.Duration) *TimingAnalysis {
	analysis := &TimingAnalysis{
		Samples: len(latencies),
	}

	if len(latencies) == 0 {
		return analysis
	}

	// Convert to float64 milliseconds for calculations
	samples := make([]float64, len(latencies))
	for i, l := range latencies {
		samples[i] = float64(l.Milliseconds())
	}

	// Calculate mean
	var sum float64
	for _, s := range samples {
		sum += s
	}
	mean := sum / float64(len(samples))
	analysis.Mean = time.Duration(mean) * time.Millisecond

	// Calculate standard deviation
	var variance float64
	for _, s := range samples {
		diff := s - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))
	stdDev := math.Sqrt(variance)
	analysis.StdDev = stdDev

	// Calculate 95th percentile
	sortedSamples := make([]float64, len(samples))
	copy(sortedSamples, samples)
	sort.Float64s(sortedSamples)
	p95Index := int(float64(len(sortedSamples)) * 0.95)
	if p95Index >= len(sortedSamples) {
		p95Index = len(sortedSamples) - 1
	}
	analysis.Percentile95 = time.Duration(sortedSamples[p95Index]) * time.Millisecond

	// Detect inconsistency (high variance indicates WAF processing)
	coefficientOfVariation := stdDev / mean
	if coefficientOfVariation > t.threshold {
		analysis.IsAnomaly = true
		analysis.AnomalyType = "inconsistent"
	}

	// Set baseline and test latency for reporting
	if len(latencies) > 0 {
		analysis.BaselineLatency = analysis.Mean
		analysis.TestLatency = latencies[len(latencies)-1]
	}

	return analysis
}

// DetectBimodal checks if latencies show bimodal distribution (blocked vs allowed)
func (t *TimingAnalyzer) DetectBimodal(latencies []time.Duration) (bool, time.Duration, time.Duration) {
	if len(latencies) < 10 {
		return false, 0, 0
	}

	// Convert and sort
	samples := make([]float64, len(latencies))
	for i, l := range latencies {
		samples[i] = float64(l.Milliseconds())
	}
	sort.Float64s(samples)

	// Simple bimodal detection: check if there's a significant gap in the middle
	midIndex := len(samples) / 2
	lowerMean := mean(samples[:midIndex])
	upperMean := mean(samples[midIndex:])

	// If the gap between means is significant, likely bimodal
	gap := upperMean - lowerMean
	overallMean := mean(samples)
	if gap > overallMean*t.threshold*2 {
		return true,
			time.Duration(lowerMean) * time.Millisecond,
			time.Duration(upperMean) * time.Millisecond
	}

	return false, 0, 0
}

// CompareTimingProfiles compares two sets of latencies
func (t *TimingAnalyzer) CompareTimingProfiles(baseline, test []time.Duration) *TimingAnalysis {
	baselineAnalysis := t.AnalyzeMultiple(baseline)
	testAnalysis := t.AnalyzeMultiple(test)

	analysis := &TimingAnalysis{
		BaselineLatency: baselineAnalysis.Mean,
		TestLatency:     testAnalysis.Mean,
		Samples:         len(test),
		Mean:            testAnalysis.Mean,
		StdDev:          testAnalysis.StdDev,
		Percentile95:    testAnalysis.Percentile95,
	}

	if baselineAnalysis.Mean == 0 {
		return analysis
	}

	// Calculate deviation between means
	diff := float64(testAnalysis.Mean - baselineAnalysis.Mean)
	analysis.Deviation = diff / float64(baselineAnalysis.Mean)

	// Calculate z-score using pooled standard deviation
	pooledStdDev := math.Sqrt((baselineAnalysis.StdDev*baselineAnalysis.StdDev +
		testAnalysis.StdDev*testAnalysis.StdDev) / 2)
	if pooledStdDev > 0 {
		analysis.StatisticalZ = diff / pooledStdDev
	}

	// Determine if anomaly (using z-score threshold of 1.96 for 95% confidence)
	if math.Abs(analysis.StatisticalZ) > 1.96 {
		analysis.IsAnomaly = true
		if analysis.Deviation > 0 {
			analysis.AnomalyType = "slower"
		} else {
			analysis.AnomalyType = "faster"
		}
	}

	return analysis
}

// mean calculates the mean of a float64 slice
func mean(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	return sum / float64(len(samples))
}
