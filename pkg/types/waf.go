package types

// WAFType represents a known WAF vendor
type WAFType string

const (
	WAFCloudflare   WAFType = "cloudflare"
	WAFModSecurity  WAFType = "modsecurity"
	WAFAWSWaf       WAFType = "aws_waf"
	WAFAkamai       WAFType = "akamai"
	WAFImperva      WAFType = "imperva"
	WAFBIGIP        WAFType = "f5_bigip"
	WAFSucuri       WAFType = "sucuri"
	WAFWordfence    WAFType = "wordfence"
	WAFFortinet     WAFType = "fortinet"
	WAFBarracuda    WAFType = "barracuda"
	WAFCitrix       WAFType = "citrix"
	WAFPaloAlto     WAFType = "palo_alto"
	WAFRadware      WAFType = "radware"
	WAFUnknown      WAFType = "unknown"
)

// WAFFingerprint represents detected WAF information
type WAFFingerprint struct {
	Type              WAFType            `json:"type" yaml:"type"`
	Name              string             `json:"name" yaml:"name"`
	Vendor            string             `json:"vendor" yaml:"vendor"`
	Version           string             `json:"version,omitempty" yaml:"version,omitempty"`
	Confidence        float64            `json:"confidence" yaml:"confidence"`
	DetectedRuleset   string             `json:"detected_ruleset,omitempty" yaml:"detected_ruleset,omitempty"`
	ParanoiaLevel     int                `json:"paranoia_level,omitempty" yaml:"paranoia_level,omitempty"`
	Features          []string           `json:"features,omitempty" yaml:"features,omitempty"`
	KnownBypasses     []string           `json:"known_bypasses,omitempty" yaml:"known_bypasses,omitempty"`
	Headers           map[string]string  `json:"headers,omitempty" yaml:"headers,omitempty"`
	BehavioralProfile *BehavioralProfile `json:"behavioral_profile,omitempty" yaml:"behavioral_profile,omitempty"`
	SignatureMatches  []SignatureMatch   `json:"signature_matches,omitempty" yaml:"signature_matches,omitempty"`
}

// BehavioralProfile represents behavioral analysis of a WAF
type BehavioralProfile struct {
	// Timing characteristics
	BaselineLatency   int64   `json:"baseline_latency_ms" yaml:"baseline_latency_ms"`
	BlockLatency      int64   `json:"block_latency_ms" yaml:"block_latency_ms"`
	LatencyVariance   float64 `json:"latency_variance" yaml:"latency_variance"`

	// Response characteristics
	BlockContentLength int      `json:"block_content_length" yaml:"block_content_length"`
	BlockStatusCodes   []int    `json:"block_status_codes" yaml:"block_status_codes"`
	BlockBodyPatterns  []string `json:"block_body_patterns" yaml:"block_body_patterns"`

	// Threshold detection
	RateLimitThreshold int `json:"rate_limit_threshold" yaml:"rate_limit_threshold"`
	PayloadSizeLimit   int `json:"payload_size_limit" yaml:"payload_size_limit"`
	ParamCountLimit    int `json:"param_count_limit" yaml:"param_count_limit"`

	// Behavioral signatures
	ConnectionReset  bool `json:"connection_reset" yaml:"connection_reset"`
	DelayedResponse  bool `json:"delayed_response" yaml:"delayed_response"`
	CaptchaTriggered bool `json:"captcha_triggered" yaml:"captcha_triggered"`
	JSChallenge      bool `json:"js_challenge" yaml:"js_challenge"`
}

// SignatureMatch represents a matched WAF signature
type SignatureMatch struct {
	Pattern     string  `json:"pattern" yaml:"pattern"`
	Location    string  `json:"location" yaml:"location"` // header, body, cookie, status
	Matched     string  `json:"matched" yaml:"matched"`
	Weight      float64 `json:"weight" yaml:"weight"`
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
}

// WAFSignature represents a WAF detection signature
type WAFSignature struct {
	WAFType       WAFType             `yaml:"waf_type"`
	Name          string              `yaml:"name"`
	Vendor        string              `yaml:"vendor"`
	Detection     DetectionSignatures `yaml:"detection"`
	BlockIndicators []string          `yaml:"block_indicators"`
	KnownBypasses []string            `yaml:"known_bypasses"`
	Rulesets      map[string]RulesetInfo `yaml:"rulesets,omitempty"`
}

// DetectionSignatures holds patterns for WAF detection
type DetectionSignatures struct {
	Headers     []PatternWeight `yaml:"headers,omitempty"`
	Body        []PatternWeight `yaml:"body,omitempty"`
	Cookies     []PatternWeight `yaml:"cookies,omitempty"`
	StatusCodes []int           `yaml:"status_codes,omitempty"`
}

// PatternWeight represents a detection pattern with its weight
type PatternWeight struct {
	Pattern     string  `yaml:"pattern"`
	Weight      float64 `yaml:"weight"`
	Description string  `yaml:"description,omitempty"`
}

// RulesetInfo holds information about a specific ruleset
type RulesetInfo struct {
	DetectionPatterns []PatternWeight   `yaml:"detection_patterns"`
	ParanoiaLevels    map[int]string    `yaml:"paranoia_levels,omitempty"`
	Description       string            `yaml:"description,omitempty"`
}

// WAFSignatureDatabase represents the complete signature database
type WAFSignatureDatabase struct {
	Version     string                  `yaml:"version"`
	LastUpdated string                  `yaml:"last_updated"`
	Signatures  map[string]WAFSignature `yaml:"signatures"`
}

// EvasionProfile represents WAF-specific evasion techniques
type EvasionProfile struct {
	Name                string              `yaml:"name"`
	Version             string              `yaml:"version"`
	EffectiveTechniques TechniquesBySuccess `yaml:"effective_techniques"`
	Quirks              []string            `yaml:"quirks"`
	RecommendedChain    []string            `yaml:"recommended_chain"`
}

// TechniquesBySuccess categorizes techniques by success rate
type TechniquesBySuccess struct {
	HighSuccess   []EvasionTechnique `yaml:"high_success"`
	MediumSuccess []EvasionTechnique `yaml:"medium_success"`
	LowSuccess    []EvasionTechnique `yaml:"low_success"`
}

// EvasionTechnique represents a specific evasion technique
type EvasionTechnique struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Examples    []TechniqueExample `yaml:"examples,omitempty"`
}

// TechniqueExample shows before/after for a technique
type TechniqueExample struct {
	Original string `yaml:"original"`
	Bypass   string `yaml:"bypass"`
}

// BlockAnalysis represents analysis of why a request was blocked
type BlockAnalysis struct {
	TriggerPattern     string   `json:"trigger_pattern"`
	RuleCategory       string   `json:"rule_category"`
	DetectionType      string   `json:"detection_type"` // regex, ml, behavioral
	TokensToObfuscate  []string `json:"tokens_to_obfuscate"`
	RecommendedEvasion string   `json:"recommended_evasion"`
	Confidence         float64  `json:"confidence"`
}

// WAFDetectionResult represents the result of WAF detection
type WAFDetectionResult struct {
	Detected          bool               `json:"detected"`
	Type              WAFType            `json:"type,omitempty"`
	Confidence        float64            `json:"confidence,omitempty"`
	Evidence          []string           `json:"evidence,omitempty"`
	Fingerprint       *WAFFingerprint    `json:"fingerprint,omitempty"`
	AllMatches        []WAFFingerprint   `json:"all_matches,omitempty"`
	BehavioralProfile *BehavioralProfile `json:"behavioral_profile,omitempty"`
	ProbeResults      []ProbeResult      `json:"probe_results,omitempty"`
}

// ProbeResult represents the result of a detection probe
type ProbeResult struct {
	ProbeType string `json:"probe_type"`
	Payload   string `json:"payload"`
	Blocked   bool   `json:"blocked"`
	StatusCode int   `json:"status_code"`
	Latency   int64  `json:"latency_ms"`
}
