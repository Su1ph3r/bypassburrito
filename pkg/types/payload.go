package types

import "time"

// AttackType represents the type of attack
type AttackType string

const (
	AttackXSS           AttackType = "xss"
	AttackSQLi          AttackType = "sqli"
	AttackCmdInjection  AttackType = "cmdi"
	AttackPathTraversal AttackType = "path_traversal"
	AttackSSTI          AttackType = "ssti"
	AttackXXE           AttackType = "xxe"
	AttackAll           AttackType = "all"
)

// ParameterPosition represents where a parameter is located
type ParameterPosition string

const (
	PositionQuery  ParameterPosition = "query"
	PositionBody   ParameterPosition = "body"
	PositionHeader ParameterPosition = "header"
	PositionPath   ParameterPosition = "path"
	PositionCookie ParameterPosition = "cookie"
)

// Payload represents a test payload
type Payload struct {
	Value       string     `json:"value" yaml:"value"`
	Type        AttackType `json:"type" yaml:"type"`
	Description string     `json:"description" yaml:"description"`
	Original    string     `json:"original,omitempty" yaml:"original,omitempty"`
	Mutations   []string   `json:"mutations,omitempty" yaml:"mutations,omitempty"`
	Source      string     `json:"source" yaml:"source"` // "base", "llm", "learned", "mutated"
	Category    string     `json:"category,omitempty" yaml:"category,omitempty"`
	Tags        []string   `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// TargetConfig holds target endpoint configuration
type TargetConfig struct {
	URL         string            `json:"url" yaml:"url"`
	Method      string            `json:"method" yaml:"method"`
	Headers     map[string]string `json:"headers" yaml:"headers"`
	Cookies     map[string]string `json:"cookies" yaml:"cookies"`
	Parameter   string            `json:"parameter" yaml:"parameter"`
	Position    ParameterPosition `json:"position" yaml:"position"`
	Body        string            `json:"body" yaml:"body"`
	ContentType string            `json:"content_type" yaml:"content_type"`
	AuthHeader  string            `json:"auth_header" yaml:"auth_header"`
}

// BypassRequest represents a request to generate bypasses
type BypassRequest struct {
	ID          string       `json:"id"`
	Target      TargetConfig `json:"target"`
	AttackType  AttackType   `json:"attack_type"`
	Payloads    []Payload    `json:"payloads,omitempty"`
	Options     BypassOptions `json:"options"`
	CreatedAt   time.Time    `json:"created_at"`
}

// BypassOptions holds options for bypass generation
type BypassOptions struct {
	MaxIterations  int      `json:"max_iterations"`
	MaxPayloads    int      `json:"max_payloads"`
	MutationDepth  int      `json:"mutation_depth"`
	UseLearned     bool     `json:"use_learned"`
	DetectWAF      bool     `json:"detect_waf"`
	WAFType        string   `json:"waf_type,omitempty"`
	Strategies     []string `json:"strategies,omitempty"`
	Aggressive     bool     `json:"aggressive"`
	Stealth        bool     `json:"stealth"`
}

// AttemptResult represents the result of a bypass attempt
type AttemptResult string

const (
	ResultBlocked  AttemptResult = "blocked"
	ResultBypassed AttemptResult = "bypassed"
	ResultError    AttemptResult = "error"
	ResultUnknown  AttemptResult = "unknown"
)

// BypassAttempt represents a single bypass attempt
type BypassAttempt struct {
	Iteration     int             `json:"iteration"`
	Payload       Payload         `json:"payload"`
	Request       *HTTPRequest    `json:"request"`
	Response      *HTTPResponse   `json:"response"`
	Result        AttemptResult   `json:"result"`
	BlockReason   string          `json:"block_reason,omitempty"`
	TriggerPattern string         `json:"trigger_pattern,omitempty"`
	Mutations     []string        `json:"mutations_applied"`
	LLMReasoning  string          `json:"llm_reasoning,omitempty"`
	Duration      time.Duration   `json:"duration"`
	Timestamp     time.Time       `json:"timestamp"`
}

// BypassResult represents the final result of bypass attempts
type BypassResult struct {
	ID               string              `json:"id"`
	OriginalPayload  Payload             `json:"original_payload"`
	SuccessfulBypass *BypassAttempt      `json:"successful_bypass,omitempty"`
	AllAttempts      []BypassAttempt     `json:"all_attempts"`
	WAFDetected      *WAFFingerprint     `json:"waf_detected,omitempty"`
	TotalIterations  int                 `json:"total_iterations"`
	Success          bool                `json:"success"`
	Duration         time.Duration       `json:"duration"`
	CurlCommand      string              `json:"curl_command,omitempty"`
	MinimizedPayload *MinimizationResult `json:"minimized_payload,omitempty"`
}

// MinimizationResult holds the result of payload minimization
type MinimizationResult struct {
	Original         string        `json:"original"`
	Minimized        string        `json:"minimized"`
	Reduction        float64       `json:"reduction_percent"`
	Iterations       int           `json:"iterations"`
	StillWorks       bool          `json:"still_works"`
	EssentialParts   []string      `json:"essential_parts,omitempty"`
	RemovedParts     []string      `json:"removed_parts,omitempty"`
	Duration         time.Duration `json:"duration"`
	MinimizationPath []string      `json:"minimization_path,omitempty"`
}

// BypassSuggestion represents LLM-generated bypass suggestion
type BypassSuggestion struct {
	Payload              Payload  `json:"payload"`
	Mutations            []string `json:"mutations"`
	Reasoning            string   `json:"reasoning"`
	Confidence           float64  `json:"confidence"`
	AlternativeApproaches []string `json:"alternative_approaches,omitempty"`
}

// MutationType represents a type of mutation
type MutationType string

const (
	MutationURLEncode         MutationType = "url_encode"
	MutationDoubleURLEncode   MutationType = "double_url_encode"
	MutationUnicode           MutationType = "unicode"
	MutationOverlongUnicode   MutationType = "overlong_unicode"
	MutationHTMLEntity        MutationType = "html_entity"
	MutationCommentInjection  MutationType = "comment_injection"
	MutationCaseRandomization MutationType = "case_randomization"
	MutationWhitespace        MutationType = "whitespace"
	MutationNullByte          MutationType = "null_byte"
	MutationHomoglyph         MutationType = "homoglyph"
	MutationInvisibleChar     MutationType = "invisible_char"
	MutationFragmentation     MutationType = "fragmentation"
	MutationAlternativeSyntax MutationType = "alternative_syntax"
)

// Mutation represents a mutation operation
type Mutation struct {
	Type        MutationType   `json:"type" yaml:"type"`
	Name        string         `json:"name" yaml:"name"`
	Description string         `json:"description" yaml:"description"`
	Transform   func(string) string `json:"-" yaml:"-"`
	Priority    int            `json:"priority" yaml:"priority"`
}

// MutationChain represents a sequence of mutations
type MutationChain struct {
	Name        string           `json:"name" yaml:"name"`
	Description string           `json:"description" yaml:"description"`
	Stages      []MutationStage  `json:"stages" yaml:"stages"`
}

// MutationStage represents a stage in mutation chain
type MutationStage struct {
	Name       string         `json:"name" yaml:"name"`
	Mutations  []MutationType `json:"mutations" yaml:"mutations"`
	Conditions []string       `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Priority   int            `json:"priority" yaml:"priority"`
}

// PayloadLibrary represents a collection of payloads
type PayloadLibrary struct {
	Version     string     `yaml:"version"`
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	AttackType  AttackType `yaml:"attack_type"`
	Category    string     `yaml:"category"`
	Payloads    []Payload  `yaml:"payloads"`
}
