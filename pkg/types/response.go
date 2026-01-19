package types

import "time"

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Cookies     map[string]string `json:"cookies,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode    int               `json:"status_code"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	ContentLength int               `json:"content_length"`
	Latency       time.Duration     `json:"latency"`
	Timestamp     time.Time         `json:"timestamp"`
	TLSVersion    string            `json:"tls_version,omitempty"`
	Error         string            `json:"error,omitempty"`
}

// ResponseClassification represents how a response is classified
type ResponseClassification string

const (
	ClassificationBlocked     ResponseClassification = "blocked"
	ClassificationAllowed     ResponseClassification = "allowed"
	ClassificationChallenged  ResponseClassification = "challenged"
	ClassificationRateLimited ResponseClassification = "rate_limited"
	ClassificationError       ResponseClassification = "error"
	ClassificationUnknown     ResponseClassification = "unknown"
)

// ResponseAnalysis represents detailed analysis of a response
type ResponseAnalysis struct {
	Classification   ResponseClassification `json:"classification"`
	Confidence       float64                `json:"confidence"`
	BlockIndicators  []BlockIndicator       `json:"block_indicators,omitempty"`
	WAFHeaders       []string               `json:"waf_headers,omitempty"`
	BlockPage        bool                   `json:"block_page"`
	CaptchaPresent   bool                   `json:"captcha_present"`
	JSChallenge      bool                   `json:"js_challenge"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	SensitiveData    []SensitiveDataMatch   `json:"sensitive_data,omitempty"`
	TimingAnomaly    bool                   `json:"timing_anomaly"`
	ExpectedLatency  time.Duration          `json:"expected_latency"`
	ActualLatency    time.Duration          `json:"actual_latency"`
}

// BlockIndicator represents evidence of blocking
type BlockIndicator struct {
	Type        string  `json:"type"` // header, body, status, timing
	Pattern     string  `json:"pattern"`
	Matched     string  `json:"matched"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description,omitempty"`
}

// SensitiveDataMatch represents detected sensitive data in response
type SensitiveDataMatch struct {
	Type     string `json:"type"` // error, stack_trace, db_info, credentials
	Pattern  string `json:"pattern"`
	Location string `json:"location"`
	Excerpt  string `json:"excerpt"`
}

// DifferentialAnalysis compares two responses for differences
type DifferentialAnalysis struct {
	BaselineResponse *HTTPResponse `json:"baseline_response"`
	TestResponse     *HTTPResponse `json:"test_response"`
	StatusDiff       bool          `json:"status_diff"`
	HeaderDiff       []string      `json:"header_diff"`
	BodyDiff         BodyDiff      `json:"body_diff"`
	LatencyDiff      time.Duration `json:"latency_diff"`
	Significant      bool          `json:"significant"`
	Interpretation   string        `json:"interpretation"`
}

// BodyDiff represents differences in response bodies
type BodyDiff struct {
	LengthDiff     int      `json:"length_diff"`
	SimilarityRatio float64 `json:"similarity_ratio"`
	AddedPatterns  []string `json:"added_patterns"`
	RemovedPatterns []string `json:"removed_patterns"`
	StructureDiff  bool     `json:"structure_diff"`
}

// ResponseFingerprint represents a unique fingerprint of a response pattern
type ResponseFingerprint struct {
	StatusCode      int               `json:"status_code"`
	ContentLength   int               `json:"content_length"`
	HeaderHash      string            `json:"header_hash"`
	BodyHash        string            `json:"body_hash"`
	SignificantHeaders map[string]string `json:"significant_headers"`
	KeyPatterns     []string          `json:"key_patterns"`
}

// SemanticAnalysis represents LLM-powered semantic analysis of response
type SemanticAnalysis struct {
	Intent          string   `json:"intent"` // block, allow, challenge, error
	Reasoning       string   `json:"reasoning"`
	BlockReason     string   `json:"block_reason,omitempty"`
	SecurityContext string   `json:"security_context,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
	Confidence      float64  `json:"confidence"`
}

// CurlCommand represents a reproducible curl command
type CurlCommand struct {
	Command      string `json:"command"`
	Description  string `json:"description,omitempty"`
	WithProxy    string `json:"with_proxy,omitempty"`
	WithInsecure string `json:"with_insecure,omitempty"`
}

// GenerateCurlCommand creates a curl command from request
func GenerateCurlCommand(req *HTTPRequest) *CurlCommand {
	cmd := "curl -X " + req.Method

	// Add headers
	for key, value := range req.Headers {
		cmd += " -H '" + key + ": " + value + "'"
	}

	// Add cookies
	if len(req.Cookies) > 0 {
		cookieStr := ""
		for key, value := range req.Cookies {
			if cookieStr != "" {
				cookieStr += "; "
			}
			cookieStr += key + "=" + value
		}
		cmd += " -H 'Cookie: " + cookieStr + "'"
	}

	// Add body
	if req.Body != "" {
		cmd += " -d '" + req.Body + "'"
	}

	cmd += " '" + req.URL + "'"

	return &CurlCommand{
		Command:      cmd,
		WithProxy:    cmd + " -x http://127.0.0.1:8080",
		WithInsecure: cmd + " -k",
	}
}
