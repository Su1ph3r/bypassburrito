package types

import "time"

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	StatusPending    ScanStatus = "pending"
	StatusRunning    ScanStatus = "running"
	StatusCompleted  ScanStatus = "completed"
	StatusFailed     ScanStatus = "failed"
	StatusCancelled  ScanStatus = "cancelled"
)

// ScanResult represents the complete result of a bypass scan
type ScanResult struct {
	ID               string            `json:"id"`
	Status           ScanStatus        `json:"status"`
	Target           TargetConfig      `json:"target"`
	AttackType       AttackType        `json:"attack_type"`
	WAFDetected      *WAFFingerprint   `json:"waf_detected,omitempty"`
	TotalPayloads    int               `json:"total_payloads"`
	TotalAttempts    int               `json:"total_attempts"`
	SuccessfulBypasses []BypassResult  `json:"successful_bypasses"`
	FailedAttempts   int               `json:"failed_attempts"`
	StartTime        time.Time         `json:"start_time"`
	EndTime          time.Time         `json:"end_time"`
	Duration         time.Duration     `json:"duration"`
	Options          BypassOptions     `json:"options"`
	Statistics       ScanStatistics    `json:"statistics"`
	Errors           []ScanError       `json:"errors,omitempty"`
}

// ScanStatistics holds detailed scan statistics
type ScanStatistics struct {
	PayloadsProcessed  int               `json:"payloads_processed"`
	MutationsApplied   int               `json:"mutations_applied"`
	RequestsSent       int               `json:"requests_sent"`
	RequestsBlocked    int               `json:"requests_blocked"`
	RequestsBypassed   int               `json:"requests_bypassed"`
	RequestsError      int               `json:"requests_error"`
	BypassRate         float64           `json:"bypass_rate"`
	AvgLatency         time.Duration     `json:"avg_latency"`
	MaxLatency         time.Duration     `json:"max_latency"`
	MinLatency         time.Duration     `json:"min_latency"`
	LLMCalls           int               `json:"llm_calls"`
	LLMTokensUsed      int               `json:"llm_tokens_used,omitempty"`
	ByMutation         map[string]int    `json:"by_mutation"`
	ByIteration        []IterationStat   `json:"by_iteration"`
}

// IterationStat holds statistics for a single iteration
type IterationStat struct {
	Iteration      int     `json:"iteration"`
	AttemptsCount  int     `json:"attempts_count"`
	SuccessCount   int     `json:"success_count"`
	SuccessRate    float64 `json:"success_rate"`
}

// ScanError represents an error during scan
type ScanError struct {
	Timestamp time.Time `json:"timestamp"`
	Phase     string    `json:"phase"`
	Message   string    `json:"message"`
	Payload   string    `json:"payload,omitempty"`
	Fatal     bool      `json:"fatal"`
}

// ScanProgress represents real-time scan progress
type ScanProgress struct {
	ScanID           string        `json:"scan_id"`
	Phase            string        `json:"phase"` // detection, generation, testing, analysis
	Progress         float64       `json:"progress"` // 0-100
	CurrentPayload   string        `json:"current_payload,omitempty"`
	CurrentIteration int           `json:"current_iteration"`
	TotalIterations  int           `json:"total_iterations"`
	SuccessCount     int           `json:"success_count"`
	FailureCount     int           `json:"failure_count"`
	ElapsedTime      time.Duration `json:"elapsed_time"`
	EstimatedRemaining time.Duration `json:"estimated_remaining,omitempty"`
	LastUpdate       time.Time     `json:"last_update"`
}

// ScanEvent represents an event during scan (for streaming)
type ScanEvent struct {
	Type      ScanEventType `json:"type"`
	Timestamp time.Time     `json:"timestamp"`
	Data      interface{}   `json:"data"`
}

// ScanEventType represents types of scan events
type ScanEventType string

const (
	EventScanStarted     ScanEventType = "scan_started"
	EventScanCompleted   ScanEventType = "scan_completed"
	EventScanFailed      ScanEventType = "scan_failed"
	EventWAFDetected     ScanEventType = "waf_detected"
	EventAttemptStarted  ScanEventType = "attempt_started"
	EventAttemptCompleted ScanEventType = "attempt_completed"
	EventBypassFound     ScanEventType = "bypass_found"
	EventIterationComplete ScanEventType = "iteration_complete"
	EventPatternLearned  ScanEventType = "pattern_learned"
	EventRateLimited     ScanEventType = "rate_limited"
	EventError           ScanEventType = "error"
)

// QueueItem represents an item in the scan queue
type QueueItem struct {
	ID         string       `json:"id"`
	Request    BypassRequest `json:"request"`
	Status     ScanStatus   `json:"status"`
	Priority   int          `json:"priority"`
	CreatedAt  time.Time    `json:"created_at"`
	StartedAt  *time.Time   `json:"started_at,omitempty"`
}

// QueueStatus represents the status of the scan queue
type QueueStatus struct {
	Pending    int          `json:"pending"`
	Running    int          `json:"running"`
	Completed  int          `json:"completed"`
	Failed     int          `json:"failed"`
	Items      []QueueItem  `json:"items"`
}

// Report represents a generated report
type Report struct {
	Format      ReportFormat  `json:"format"`
	Content     []byte        `json:"content"`
	Filename    string        `json:"filename"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// ReportFormat represents supported report formats
type ReportFormat string

const (
	FormatJSON     ReportFormat = "json"
	FormatMarkdown ReportFormat = "markdown"
	FormatHTML     ReportFormat = "html"
	FormatText     ReportFormat = "text"
	FormatBurp     ReportFormat = "burp"
	FormatNuclei   ReportFormat = "nuclei"
	FormatSARIF    ReportFormat = "sarif"
)

// NucleiTemplate represents a generated Nuclei template
type NucleiTemplate struct {
	ID            string   `yaml:"id"`
	Info          NucleiInfo `yaml:"info"`
	HTTP          []NucleiHTTP `yaml:"http"`
}

// NucleiInfo holds Nuclei template metadata
type NucleiInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

// NucleiHTTP holds Nuclei HTTP request configuration
type NucleiHTTP struct {
	Method      string            `yaml:"method"`
	Path        []string          `yaml:"path"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	Matchers    []NucleiMatcher   `yaml:"matchers"`
}

// NucleiMatcher holds Nuclei matcher configuration
type NucleiMatcher struct {
	Type      string   `yaml:"type"`
	Status    []int    `yaml:"status,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
}

// BurpExport represents Burp Suite XML export format
type BurpExport struct {
	Items []BurpItem `xml:"item"`
}

// BurpItem represents a single item in Burp export
type BurpItem struct {
	Time          string `xml:"time"`
	URL           string `xml:"url"`
	Host          string `xml:"host"`
	Port          int    `xml:"port"`
	Protocol      string `xml:"protocol"`
	Method        string `xml:"method"`
	Path          string `xml:"path"`
	Extension     string `xml:"extension"`
	Request       string `xml:"request"` // Base64 encoded
	Response      string `xml:"response"` // Base64 encoded
	Status        int    `xml:"status"`
	ResponseLength int   `xml:"responselength"`
	MimeType      string `xml:"mimetype"`
	Comment       string `xml:"comment"`
}

// HealthStatus represents server health status
type HealthStatus struct {
	Status       string    `json:"status"`
	Version      string    `json:"version"`
	Uptime       time.Duration `json:"uptime"`
	QueueStatus  QueueStatus `json:"queue_status"`
	LLMProvider  string    `json:"llm_provider"`
	LLMAvailable bool      `json:"llm_available"`
}
