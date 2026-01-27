// Package types provides shared type definitions for BypassBurrito
package types

import (
	"time"
)

// Config represents the complete application configuration
type Config struct {
	Provider     ProviderConfig     `yaml:"provider" mapstructure:"provider"`
	HTTP         HTTPConfig         `yaml:"http" mapstructure:"http"`
	Bypass       BypassConfig       `yaml:"bypass" mapstructure:"bypass"`
	Learning     LearningConfig     `yaml:"learning" mapstructure:"learning"`
	WAF          WAFConfig          `yaml:"waf" mapstructure:"waf"`
	Output       OutputConfig       `yaml:"output" mapstructure:"output"`
	Advanced     AdvancedConfig     `yaml:"advanced" mapstructure:"advanced"`
	Solver       SolverConfig       `yaml:"solver" mapstructure:"solver"`
	Sequence     SequenceConfig     `yaml:"sequence" mapstructure:"sequence"`
}

// SolverConfig holds challenge solver settings
type SolverConfig struct {
	Enabled        bool   `yaml:"enabled" mapstructure:"enabled"`
	BrowserPath    string `yaml:"browser_path" mapstructure:"browser_path"`
	Headless       bool   `yaml:"headless" mapstructure:"headless"`
	CaptchaService string `yaml:"captcha_service" mapstructure:"captcha_service"`
	CaptchaAPIKey  string `yaml:"captcha_api_key" mapstructure:"captcha_api_key"`
	MaxAttempts    int    `yaml:"max_attempts" mapstructure:"max_attempts"`
	TimeoutSeconds int    `yaml:"timeout_seconds" mapstructure:"timeout_seconds"`
}

// SequenceConfig holds multi-request sequence settings
type SequenceConfig struct {
	Enabled         bool   `yaml:"enabled" mapstructure:"enabled"`
	SequenceDir     string `yaml:"sequence_dir" mapstructure:"sequence_dir"`
	MaxSteps        int    `yaml:"max_steps" mapstructure:"max_steps"`
	DefaultTimeout  int    `yaml:"default_timeout" mapstructure:"default_timeout"`
	PreserveSession bool   `yaml:"preserve_session" mapstructure:"preserve_session"`
}

// ProviderConfig holds LLM provider configuration
type ProviderConfig struct {
	Name        string          `yaml:"name" mapstructure:"name"`
	APIKey      string          `yaml:"api_key" mapstructure:"api_key"`
	BaseURL     string          `yaml:"base_url" mapstructure:"base_url"`
	Model       string          `yaml:"model" mapstructure:"model"`
	MaxTokens   int             `yaml:"max_tokens" mapstructure:"max_tokens"`
	Temperature float64         `yaml:"temperature" mapstructure:"temperature"`
	Ensemble    EnsembleConfig  `yaml:"ensemble" mapstructure:"ensemble"`
}

// EnsembleConfig holds multi-model ensemble configuration
type EnsembleConfig struct {
	Enabled   bool              `yaml:"enabled" mapstructure:"enabled"`
	Providers []ProviderWeight  `yaml:"providers" mapstructure:"providers"`
	Strategy  string            `yaml:"strategy" mapstructure:"strategy"` // majority_vote, weighted_average, best_confidence
}

// ProviderWeight represents a provider with its weight in ensemble
type ProviderWeight struct {
	Name   string  `yaml:"name" mapstructure:"name"`
	Model  string  `yaml:"model" mapstructure:"model"`
	Weight float64 `yaml:"weight" mapstructure:"weight"`
}

// HTTPConfig holds HTTP client configuration
type HTTPConfig struct {
	ProxyURL       string            `yaml:"proxy_url" mapstructure:"proxy_url"`
	Timeout        time.Duration     `yaml:"timeout" mapstructure:"timeout"`
	RateLimit      float64           `yaml:"rate_limit" mapstructure:"rate_limit"`
	AdaptiveRate   bool              `yaml:"adaptive_rate" mapstructure:"adaptive_rate"`
	UserAgent      string            `yaml:"user_agent" mapstructure:"user_agent"`
	Headers        map[string]string `yaml:"headers" mapstructure:"headers"`
	Cookies        map[string]string `yaml:"cookies" mapstructure:"cookies"`
	TLSFingerprint TLSFingerprintConfig `yaml:"tls_fingerprint" mapstructure:"tls_fingerprint"`
	Session        SessionConfig     `yaml:"session" mapstructure:"session"`
	Retry          RetryConfig       `yaml:"retry" mapstructure:"retry"`
	VerifySSL      bool              `yaml:"verify_ssl" mapstructure:"verify_ssl"`
	Protocol       ProtocolConfig    `yaml:"protocol" mapstructure:"protocol"`
}

// ProtocolConfig holds protocol-level evasion settings
type ProtocolConfig struct {
	PreferHTTP2      bool `yaml:"prefer_http2" mapstructure:"prefer_http2"`
	EnableWebSocket  bool `yaml:"enable_websocket" mapstructure:"enable_websocket"`
	ChunkedEvasion   bool `yaml:"chunked_evasion" mapstructure:"chunked_evasion"`
	ConnectionReuse  bool `yaml:"connection_reuse" mapstructure:"connection_reuse"`
	PipelineRequests bool `yaml:"pipeline_requests" mapstructure:"pipeline_requests"`
}

// TLSFingerprintConfig holds TLS fingerprint rotation settings
type TLSFingerprintConfig struct {
	Enabled  bool     `yaml:"enabled" mapstructure:"enabled"`
	Rotate   bool     `yaml:"rotate" mapstructure:"rotate"`
	Profiles []string `yaml:"profiles" mapstructure:"profiles"`
}

// SessionConfig holds session management settings
type SessionConfig struct {
	PersistCookies bool `yaml:"persist_cookies" mapstructure:"persist_cookies"`
	AutoCSRF       bool `yaml:"auto_csrf" mapstructure:"auto_csrf"`
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries int    `yaml:"max_retries" mapstructure:"max_retries"`
	Backoff    string `yaml:"backoff" mapstructure:"backoff"` // linear, exponential
	RetryOn    []int  `yaml:"retry_on" mapstructure:"retry_on"`
}

// BypassConfig holds bypass generation settings
type BypassConfig struct {
	MaxIterations  int             `yaml:"max_iterations" mapstructure:"max_iterations"`
	MaxPayloads    int             `yaml:"max_payloads" mapstructure:"max_payloads"`
	MutationDepth  int             `yaml:"mutation_depth" mapstructure:"mutation_depth"`
	DetectWAF      bool            `yaml:"detect_waf" mapstructure:"detect_waf"`
	UseLearned     bool            `yaml:"use_learned" mapstructure:"use_learned"`
	Strategies     StrategyConfig  `yaml:"strategies" mapstructure:"strategies"`
	Attacks        AttackConfig    `yaml:"attacks" mapstructure:"attacks"`
	Deduplication  DedupConfig     `yaml:"deduplication" mapstructure:"deduplication"`
	Oracle         OracleConfig    `yaml:"oracle" mapstructure:"oracle"`
}

// OracleConfig holds response oracle analysis settings
type OracleConfig struct {
	Enabled                bool    `yaml:"enabled" mapstructure:"enabled"`
	TimingThreshold        float64 `yaml:"timing_threshold" mapstructure:"timing_threshold"`
	ContentLengthThreshold float64 `yaml:"content_length_threshold" mapstructure:"content_length_threshold"`
	BaselineSamples        int     `yaml:"baseline_samples" mapstructure:"baseline_samples"`
	ErrorFingerprinting    bool    `yaml:"error_fingerprinting" mapstructure:"error_fingerprinting"`
}

// StrategyConfig holds mutation strategy settings
type StrategyConfig struct {
	Enabled     []string          `yaml:"enabled" mapstructure:"enabled"`
	Encoding    EncodingConfig    `yaml:"encoding" mapstructure:"encoding"`
	Obfuscation ObfuscationConfig `yaml:"obfuscation" mapstructure:"obfuscation"`
	Adversarial AdversarialConfig `yaml:"adversarial" mapstructure:"adversarial"`
}

// EncodingConfig holds encoding strategy settings
type EncodingConfig struct {
	URL            bool `yaml:"url" mapstructure:"url"`
	DoubleURL      bool `yaml:"double_url" mapstructure:"double_url"`
	Unicode        bool `yaml:"unicode" mapstructure:"unicode"`
	OverlongUnicode bool `yaml:"overlong_unicode" mapstructure:"overlong_unicode"`
	HTMLEntity     bool `yaml:"html_entity" mapstructure:"html_entity"`
	Mixed          bool `yaml:"mixed" mapstructure:"mixed"`
}

// ObfuscationConfig holds obfuscation strategy settings
type ObfuscationConfig struct {
	CommentInjection      bool `yaml:"comment_injection" mapstructure:"comment_injection"`
	CaseRandomization     bool `yaml:"case_randomization" mapstructure:"case_randomization"`
	WhitespaceSubstitution bool `yaml:"whitespace_substitution" mapstructure:"whitespace_substitution"`
	NullBytes             bool `yaml:"null_bytes" mapstructure:"null_bytes"`
}

// AdversarialConfig holds adversarial ML evasion settings
type AdversarialConfig struct {
	Homoglyphs      bool `yaml:"homoglyphs" mapstructure:"homoglyphs"`
	InvisibleChars  bool `yaml:"invisible_chars" mapstructure:"invisible_chars"`
	BiDiOverride    bool `yaml:"bidi_override" mapstructure:"bidi_override"`
}

// AttackConfig holds attack-specific settings
type AttackConfig struct {
	XSS    XSSConfig    `yaml:"xss" mapstructure:"xss"`
	SQLi   SQLiConfig   `yaml:"sqli" mapstructure:"sqli"`
	CMDi   CMDiConfig   `yaml:"cmdi" mapstructure:"cmdi"`
	SSTI   SSTIConfig   `yaml:"ssti" mapstructure:"ssti"`
	NoSQLi NoSQLiConfig `yaml:"nosqli" mapstructure:"nosqli"`
}

// SSTIConfig holds SSTI attack settings
type SSTIConfig struct {
	TargetEngines  []string `yaml:"target_engines" mapstructure:"target_engines"`
	DetectionFirst bool     `yaml:"detection_first" mapstructure:"detection_first"`
}

// NoSQLiConfig holds NoSQL injection attack settings
type NoSQLiConfig struct {
	Databases  []string `yaml:"databases" mapstructure:"databases"`
	Techniques []string `yaml:"techniques" mapstructure:"techniques"`
}

// XSSConfig holds XSS attack settings
type XSSConfig struct {
	IncludeDOM      bool `yaml:"include_dom" mapstructure:"include_dom"`
	IncludePolyglot bool `yaml:"include_polyglot" mapstructure:"include_polyglot"`
	EventHandlers   bool `yaml:"event_handlers" mapstructure:"event_handlers"`
}

// SQLiConfig holds SQLi attack settings
type SQLiConfig struct {
	Databases  []string `yaml:"databases" mapstructure:"databases"`
	Techniques []string `yaml:"techniques" mapstructure:"techniques"`
}

// CMDiConfig holds command injection settings
type CMDiConfig struct {
	Platforms      []string `yaml:"platforms" mapstructure:"platforms"`
	BlindDetection bool     `yaml:"blind_detection" mapstructure:"blind_detection"`
}

// DedupConfig holds deduplication settings
type DedupConfig struct {
	Enabled             bool    `yaml:"enabled" mapstructure:"enabled"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" mapstructure:"similarity_threshold"`
}

// LearningConfig holds learning system settings
type LearningConfig struct {
	Enabled        bool            `yaml:"enabled" mapstructure:"enabled"`
	StorePath      string          `yaml:"store_path" mapstructure:"store_path"`
	AutoSave       bool            `yaml:"auto_save" mapstructure:"auto_save"`
	MinSuccessCount int            `yaml:"min_success_count" mapstructure:"min_success_count"`
	Evolution      EvolutionConfig `yaml:"evolution" mapstructure:"evolution"`
	Sharing        SharingConfig   `yaml:"sharing" mapstructure:"sharing"`
}

// EvolutionConfig holds genetic algorithm settings
type EvolutionConfig struct {
	Enabled        bool    `yaml:"enabled" mapstructure:"enabled"`
	Generations    int     `yaml:"generations" mapstructure:"generations"`
	PopulationSize int     `yaml:"population_size" mapstructure:"population_size"`
	MutationRate   float64 `yaml:"mutation_rate" mapstructure:"mutation_rate"`
	CrossoverRate  float64 `yaml:"crossover_rate" mapstructure:"crossover_rate"`
}

// SharingConfig holds pattern sharing settings
type SharingConfig struct {
	ExportSuccessful bool `yaml:"export_successful" mapstructure:"export_successful"`
	Anonymize        bool `yaml:"anonymize" mapstructure:"anonymize"`
}

// WAFConfig holds WAF detection settings
type WAFConfig struct {
	AutoDetect           bool   `yaml:"auto_detect" mapstructure:"auto_detect"`
	BehavioralAnalysis   bool   `yaml:"behavioral_analysis" mapstructure:"behavioral_analysis"`
	RulesetIdentification bool  `yaml:"ruleset_identification" mapstructure:"ruleset_identification"`
	SignaturesFile       string `yaml:"signatures_file" mapstructure:"signatures_file"`
	ProfilesDir          string `yaml:"profiles_dir" mapstructure:"profiles_dir"`
}

// OutputConfig holds output settings
type OutputConfig struct {
	Format          string        `yaml:"format" mapstructure:"format"`
	File            string        `yaml:"file" mapstructure:"file"`
	Verbose         bool          `yaml:"verbose" mapstructure:"verbose"`
	Color           bool          `yaml:"color" mapstructure:"color"`
	ShowAllAttempts bool          `yaml:"show_all_attempts" mapstructure:"show_all_attempts"`
	Include         IncludeConfig `yaml:"include" mapstructure:"include"`
}

// IncludeConfig holds output inclusion settings
type IncludeConfig struct {
	CurlCommands    bool `yaml:"curl_commands" mapstructure:"curl_commands"`
	RequestResponse bool `yaml:"request_response" mapstructure:"request_response"`
	LLMReasoning    bool `yaml:"llm_reasoning" mapstructure:"llm_reasoning"`
	TimingInfo      bool `yaml:"timing_info" mapstructure:"timing_info"`
}

// AdvancedConfig holds advanced settings
type AdvancedConfig struct {
	SaveRequests bool         `yaml:"save_requests" mapstructure:"save_requests"`
	RequestsDir  string       `yaml:"requests_dir" mapstructure:"requests_dir"`
	Cache        CacheConfig  `yaml:"cache" mapstructure:"cache"`
	Concurrency  ConcurrencyConfig `yaml:"concurrency" mapstructure:"concurrency"`
}

// CacheConfig holds response caching settings
type CacheConfig struct {
	Enabled bool          `yaml:"enabled" mapstructure:"enabled"`
	TTL     time.Duration `yaml:"ttl" mapstructure:"ttl"`
}

// ConcurrencyConfig holds parallel processing settings
type ConcurrencyConfig struct {
	Payloads  int `yaml:"payloads" mapstructure:"payloads"`
	Mutations int `yaml:"mutations" mapstructure:"mutations"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Provider: ProviderConfig{
			Name:        "anthropic",
			Model:       "claude-sonnet-4-20250514",
			MaxTokens:   8192,
			Temperature: 0.3,
			Ensemble: EnsembleConfig{
				Enabled:  false,
				Strategy: "weighted_average",
			},
		},
		HTTP: HTTPConfig{
			Timeout:      30 * time.Second,
			RateLimit:    5.0,
			AdaptiveRate: true,
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Headers:      make(map[string]string),
			Cookies:      make(map[string]string),
			VerifySSL:    true,
			TLSFingerprint: TLSFingerprintConfig{
				Enabled:  false,
				Rotate:   true,
				Profiles: []string{"chrome", "firefox", "safari"},
			},
			Session: SessionConfig{
				PersistCookies: true,
				AutoCSRF:       true,
			},
			Retry: RetryConfig{
				MaxRetries: 3,
				Backoff:    "exponential",
				RetryOn:    []int{429, 502, 503},
			},
			Protocol: ProtocolConfig{
				PreferHTTP2:      false,
				EnableWebSocket:  false,
				ChunkedEvasion:   false,
				ConnectionReuse:  true,
				PipelineRequests: false,
			},
		},
		Bypass: BypassConfig{
			MaxIterations: 15,
			MaxPayloads:   30,
			MutationDepth: 5,
			DetectWAF:     true,
			UseLearned:    true,
			Strategies: StrategyConfig{
				Enabled: []string{"encoding", "obfuscation", "fragmentation", "polymorphic", "contextual", "adversarial"},
				Encoding: EncodingConfig{
					URL:            true,
					DoubleURL:      true,
					Unicode:        true,
					OverlongUnicode: true,
					HTMLEntity:     true,
					Mixed:          true,
				},
				Obfuscation: ObfuscationConfig{
					CommentInjection:      true,
					CaseRandomization:     true,
					WhitespaceSubstitution: true,
					NullBytes:             true,
				},
				Adversarial: AdversarialConfig{
					Homoglyphs:     true,
					InvisibleChars: true,
					BiDiOverride:   false,
				},
			},
			Attacks: AttackConfig{
				XSS: XSSConfig{
					IncludeDOM:      true,
					IncludePolyglot: true,
					EventHandlers:   true,
				},
				SQLi: SQLiConfig{
					Databases:  []string{"mysql", "postgresql", "mssql", "oracle", "sqlite"},
					Techniques: []string{"union", "boolean_blind", "time_blind", "error_based"},
				},
				CMDi: CMDiConfig{
					Platforms:      []string{"unix", "windows"},
					BlindDetection: true,
				},
				SSTI: SSTIConfig{
					TargetEngines:  []string{"jinja2", "twig", "freemarker", "velocity"},
					DetectionFirst: true,
				},
				NoSQLi: NoSQLiConfig{
					Databases:  []string{"mongodb", "couchdb"},
					Techniques: []string{"operator_injection", "js_injection", "regex"},
				},
			},
			Deduplication: DedupConfig{
				Enabled:             true,
				SimilarityThreshold: 0.85,
			},
			Oracle: OracleConfig{
				Enabled:                true,
				TimingThreshold:        0.3,
				ContentLengthThreshold: 0.1,
				BaselineSamples:        5,
				ErrorFingerprinting:    true,
			},
		},
		Learning: LearningConfig{
			Enabled:        true,
			StorePath:      "~/.bypassburrito/learned-patterns.yaml",
			AutoSave:       true,
			MinSuccessCount: 2,
			Evolution: EvolutionConfig{
				Enabled:        false,
				Generations:    10,
				PopulationSize: 50,
				MutationRate:   0.1,
				CrossoverRate:  0.7,
			},
			Sharing: SharingConfig{
				ExportSuccessful: true,
				Anonymize:        true,
			},
		},
		WAF: WAFConfig{
			AutoDetect:           true,
			BehavioralAnalysis:   true,
			RulesetIdentification: true,
		},
		Output: OutputConfig{
			Format:          "text",
			Verbose:         false,
			Color:           true,
			ShowAllAttempts: false,
			Include: IncludeConfig{
				CurlCommands:    true,
				RequestResponse: false,
				LLMReasoning:    true,
				TimingInfo:      true,
			},
		},
		Advanced: AdvancedConfig{
			SaveRequests: false,
			RequestsDir:  "~/.bypassburrito/requests",
			Cache: CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
			},
			Concurrency: ConcurrencyConfig{
				Payloads:  5,
				Mutations: 10,
			},
		},
	}
}
