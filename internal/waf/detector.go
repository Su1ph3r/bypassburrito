package waf

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Detector handles WAF detection and fingerprinting
type Detector struct {
	signatures *SignatureDatabase
	behavioral *BehavioralAnalyzer
}

// NewDetector creates a new WAF detector
func NewDetector() (*Detector, error) {
	sigs, err := LoadEmbeddedSignatures()
	if err != nil {
		return nil, err
	}

	return &Detector{
		signatures: sigs,
		behavioral: NewBehavioralAnalyzer(),
	}, nil
}

// NewDetectorWithSignatures creates a detector with custom signatures
func NewDetectorWithSignatures(sigPath string) (*Detector, error) {
	sigs, err := LoadSignatures(sigPath)
	if err != nil {
		return nil, err
	}

	return &Detector{
		signatures: sigs,
		behavioral: NewBehavioralAnalyzer(),
	}, nil
}

// Detect performs WAF detection on a response
func (d *Detector) Detect(resp *types.HTTPResponse) *types.WAFDetectionResult {
	result := &types.WAFDetectionResult{
		Detected:   false,
		AllMatches: []types.WAFFingerprint{},
	}

	// Check each signature
	var allMatches []types.WAFFingerprint
	for wafType, sig := range d.signatures.Signatures {
		fingerprint := d.matchSignature(resp, wafType, sig)
		if fingerprint != nil && fingerprint.Confidence > 0.3 {
			allMatches = append(allMatches, *fingerprint)
		}
	}

	if len(allMatches) == 0 {
		return result
	}

	// Sort by confidence
	sort.Slice(allMatches, func(i, j int) bool {
		return allMatches[i].Confidence > allMatches[j].Confidence
	})

	result.Detected = true
	result.AllMatches = allMatches
	result.Fingerprint = &allMatches[0]

	return result
}

// DetectWithBehavior performs WAF detection with behavioral analysis
func (d *Detector) DetectWithBehavior(ctx context.Context, client HTTPClient, targetURL string) (*types.WAFDetectionResult, error) {
	// First, get a baseline response
	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	// Initial detection from baseline
	result := d.Detect(baselineResp)

	// If behavioral analysis is desired, probe the target
	if result.Detected || true { // Always do behavioral for thoroughness
		profile, err := d.behavioral.Profile(ctx, client, targetURL)
		if err == nil {
			result.BehavioralProfile = profile

			// If we detected a WAF, update the fingerprint with behavioral data
			if result.Fingerprint != nil {
				result.Fingerprint.BehavioralProfile = profile
			}
		}
	}

	return result, nil
}

// matchSignature matches a response against a WAF signature
func (d *Detector) matchSignature(resp *types.HTTPResponse, wafType string, sig types.WAFSignature) *types.WAFFingerprint {
	var totalWeight float64
	var matchedWeight float64
	var matches []types.SignatureMatch

	// Check headers
	for _, pattern := range sig.Detection.Headers {
		totalWeight += pattern.Weight
		for header, value := range resp.Headers {
			combined := header + ": " + value
			if matched, _ := regexp.MatchString(pattern.Pattern, combined); matched {
				matchedWeight += pattern.Weight
				matches = append(matches, types.SignatureMatch{
					Pattern:     pattern.Pattern,
					Location:    "header",
					Matched:     combined,
					Weight:      pattern.Weight,
					Description: pattern.Description,
				})
				break
			}
		}
	}

	// Check body
	for _, pattern := range sig.Detection.Body {
		totalWeight += pattern.Weight
		if matched, _ := regexp.MatchString(pattern.Pattern, resp.Body); matched {
			matchedWeight += pattern.Weight
			// Extract a snippet of what matched
			re := regexp.MustCompile(pattern.Pattern)
			matchedText := re.FindString(resp.Body)
			if len(matchedText) > 100 {
				matchedText = matchedText[:100] + "..."
			}
			matches = append(matches, types.SignatureMatch{
				Pattern:     pattern.Pattern,
				Location:    "body",
				Matched:     matchedText,
				Weight:      pattern.Weight,
				Description: pattern.Description,
			})
		}
	}

	// Check cookies
	for _, pattern := range sig.Detection.Cookies {
		totalWeight += pattern.Weight
		cookieHeader := resp.Headers["Set-Cookie"]
		if matched, _ := regexp.MatchString(pattern.Pattern, cookieHeader); matched {
			matchedWeight += pattern.Weight
			matches = append(matches, types.SignatureMatch{
				Pattern:  pattern.Pattern,
				Location: "cookie",
				Matched:  cookieHeader,
				Weight:   pattern.Weight,
			})
		}
	}

	// Check status codes
	for _, code := range sig.Detection.StatusCodes {
		if resp.StatusCode == code {
			matchedWeight += 0.2 // Small bonus for status code match
			break
		}
	}

	if matchedWeight == 0 {
		return nil
	}

	// Calculate confidence
	confidence := matchedWeight / totalWeight
	if confidence > 1.0 {
		confidence = 1.0
	}

	return &types.WAFFingerprint{
		Type:             types.WAFType(wafType),
		Name:             sig.Name,
		Vendor:           sig.Vendor,
		Confidence:       confidence,
		KnownBypasses:    sig.KnownBypasses,
		SignatureMatches: matches,
	}
}

// IdentifyBlockReason attempts to identify why a request was blocked
func (d *Detector) IdentifyBlockReason(resp *types.HTTPResponse) *types.BlockAnalysis {
	analysis := &types.BlockAnalysis{
		DetectionType: "unknown",
		Confidence:    0.5,
	}

	// Look for common block patterns
	body := strings.ToLower(resp.Body)

	// SQLi detection
	if strings.Contains(body, "sql") || strings.Contains(body, "injection") ||
		strings.Contains(body, "query") {
		analysis.RuleCategory = "sqli"
		analysis.DetectionType = "regex"
	}

	// XSS detection
	if strings.Contains(body, "xss") || strings.Contains(body, "script") ||
		strings.Contains(body, "cross-site") {
		analysis.RuleCategory = "xss"
		analysis.DetectionType = "regex"
	}

	// Command injection
	if strings.Contains(body, "command") || strings.Contains(body, "shell") ||
		strings.Contains(body, "execution") {
		analysis.RuleCategory = "cmdi"
		analysis.DetectionType = "regex"
	}

	// Path traversal
	if strings.Contains(body, "traversal") || strings.Contains(body, "directory") ||
		strings.Contains(body, "path") {
		analysis.RuleCategory = "path_traversal"
		analysis.DetectionType = "regex"
	}

	// Look for specific trigger patterns
	if strings.Contains(body, "blocked") || strings.Contains(body, "denied") ||
		strings.Contains(body, "forbidden") {
		analysis.Confidence = 0.8
	}

	return analysis
}

// GetEvasionProfile returns the evasion profile for a WAF type
func (d *Detector) GetEvasionProfile(wafType types.WAFType) *types.EvasionProfile {
	// Return known evasion techniques for the WAF
	// This would typically load from a file, but we'll return defaults
	profiles := map[types.WAFType]*types.EvasionProfile{
		types.WAFCloudflare: {
			Name:    "Cloudflare",
			Version: "2025.01",
			RecommendedChain: []string{
				"unicode_normalization",
				"double_url_encoding",
				"comment_injection",
				"case_variation",
				"whitespace_substitution",
			},
			Quirks: []string{
				"Processes requests in multiple phases",
				"Has ML-based detection in addition to rules",
				"Caches blocked requests",
				"Rate limits more aggressive after blocks",
			},
		},
		types.WAFModSecurity: {
			Name:    "ModSecurity",
			Version: "2025.01",
			RecommendedChain: []string{
				"comment_injection",
				"case_randomization",
				"url_encoding",
				"whitespace_substitution",
				"null_byte_injection",
			},
			Quirks: []string{
				"Paranoia level affects detection strictness",
				"CRS rules are signature-based",
				"Order of rules matters",
			},
		},
	}

	if profile, ok := profiles[wafType]; ok {
		return profile
	}

	// Default profile
	return &types.EvasionProfile{
		Name:    "Generic",
		Version: "1.0",
		RecommendedChain: []string{
			"url_encoding",
			"case_randomization",
			"comment_injection",
		},
	}
}

// HTTPClient interface for behavioral analysis
type HTTPClient interface {
	Get(ctx context.Context, url string) (*types.HTTPResponse, error)
	Post(ctx context.Context, url, contentType, body string) (*types.HTTPResponse, error)
}

// BehavioralAnalyzer performs behavioral analysis of WAFs
type BehavioralAnalyzer struct {
	mu sync.Mutex
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	return &BehavioralAnalyzer{}
}

// Profile builds a behavioral profile of the WAF
func (b *BehavioralAnalyzer) Profile(ctx context.Context, client HTTPClient, targetURL string) (*types.BehavioralProfile, error) {
	profile := &types.BehavioralProfile{}

	// Measure baseline latency
	baselineLatency, err := b.measureBaseline(ctx, client, targetURL)
	if err != nil {
		return nil, err
	}
	profile.BaselineLatency = baselineLatency

	// Probe with known-bad payload to measure block latency
	blockLatency, blockStatus, err := b.probeBlock(ctx, client, targetURL)
	if err == nil {
		profile.BlockLatency = blockLatency
		profile.BlockStatusCodes = []int{blockStatus}
	}

	// Probe for rate limiting
	rateLimit := b.probeRateLimit(ctx, client, targetURL)
	profile.RateLimitThreshold = rateLimit

	return profile, nil
}

// measureBaseline measures normal response latency
func (b *BehavioralAnalyzer) measureBaseline(ctx context.Context, client HTTPClient, url string) (int64, error) {
	var totalLatency int64
	samples := 3

	for i := 0; i < samples; i++ {
		resp, err := client.Get(ctx, url)
		if err != nil {
			return 0, err
		}
		totalLatency += resp.Latency.Milliseconds()
	}

	return totalLatency / int64(samples), nil
}

// probeBlock probes with a malicious payload
func (b *BehavioralAnalyzer) probeBlock(ctx context.Context, client HTTPClient, url string) (int64, int, error) {
	// Try a simple XSS payload
	testURL := url
	if strings.Contains(url, "?") {
		testURL += "&test=<script>alert(1)</script>"
	} else {
		testURL += "?test=<script>alert(1)</script>"
	}

	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return 0, 0, err
	}

	return resp.Latency.Milliseconds(), resp.StatusCode, nil
}

// probeRateLimit probes for rate limiting threshold
func (b *BehavioralAnalyzer) probeRateLimit(ctx context.Context, client HTTPClient, url string) int {
	// This is a simplified probe - in practice, this would be more sophisticated
	// We just return a sensible default
	return 100 // requests per minute estimate
}
