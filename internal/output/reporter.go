package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
	"gopkg.in/yaml.v3"
)

// Reporter handles output formatting
type Reporter struct {
	format string
}

// DetectionReport wraps WAF detection results
type DetectionReport struct {
	Target     string                    `json:"target" yaml:"target"`
	Result     *types.WAFDetectionResult `json:"result" yaml:"result"`
	Behavioral *types.BehavioralProfile  `json:"behavioral,omitempty" yaml:"behavioral,omitempty"`
	Timestamp  time.Time                 `json:"timestamp" yaml:"timestamp"`
}

// NewReporter creates a new reporter
func NewReporter(format string) *Reporter {
	return &Reporter{format: format}
}

// WriteToFile writes bypass results to a file
func (r *Reporter) WriteToFile(result *types.BypassResult, path string) error {
	var data []byte
	var err error

	switch r.format {
	case "json":
		data, err = r.formatJSON(result)
	case "markdown", "md":
		data, err = r.formatMarkdown(result)
	case "html":
		data, err = r.formatHTML(result)
	case "burp":
		data, err = r.formatBurp(result)
	case "nuclei":
		data, err = r.formatNuclei(result)
	case "yaml":
		data, err = r.formatYAML(result)
	default:
		data, err = r.formatText(result)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// WriteDetectionReport writes WAF detection results to a file
func (r *Reporter) WriteDetectionReport(report *DetectionReport, path string) error {
	var data []byte
	var err error

	switch r.format {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(report)
	default:
		data, err = r.formatDetectionText(report)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (r *Reporter) formatJSON(result *types.BypassResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func (r *Reporter) formatYAML(result *types.BypassResult) ([]byte, error) {
	return yaml.Marshal(result)
}

func (r *Reporter) formatText(result *types.BypassResult) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("=== BypassBurrito Report ===\n\n")

	sb.WriteString(fmt.Sprintf("Original Payload: %s\n", result.OriginalPayload.Value))
	sb.WriteString(fmt.Sprintf("Attack Type: %s\n", result.OriginalPayload.Type))
	sb.WriteString(fmt.Sprintf("Total Iterations: %d\n", result.TotalIterations))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration))

	if result.WAFDetected != nil {
		sb.WriteString(fmt.Sprintf("\nWAF Detected: %s (%.0f%% confidence)\n",
			result.WAFDetected.Type, result.WAFDetected.Confidence*100))
	}

	if result.Success && result.SuccessfulBypass != nil {
		sb.WriteString("\n=== BYPASS SUCCESSFUL ===\n")
		sb.WriteString(fmt.Sprintf("Bypass Payload: %s\n", result.SuccessfulBypass.Payload.Value))
		sb.WriteString(fmt.Sprintf("Mutations: %s\n", strings.Join(result.SuccessfulBypass.Mutations, ", ")))
		sb.WriteString(fmt.Sprintf("Iteration: %d\n", result.SuccessfulBypass.Iteration))

		if result.CurlCommand != "" {
			sb.WriteString(fmt.Sprintf("\nCurl Command:\n%s\n", result.CurlCommand))
		}
	} else {
		sb.WriteString("\n=== NO BYPASS FOUND ===\n")
	}

	return []byte(sb.String()), nil
}

func (r *Reporter) formatMarkdown(result *types.BypassResult) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("# BypassBurrito Report 🌯\n\n")

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Original Payload:** `%s`\n", result.OriginalPayload.Value))
	sb.WriteString(fmt.Sprintf("- **Attack Type:** %s\n", result.OriginalPayload.Type))
	sb.WriteString(fmt.Sprintf("- **Total Iterations:** %d\n", result.TotalIterations))
	sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", result.Duration))

	if result.WAFDetected != nil {
		sb.WriteString(fmt.Sprintf("- **WAF Detected:** %s (%.0f%% confidence)\n",
			result.WAFDetected.Type, result.WAFDetected.Confidence*100))
	}

	if result.Success && result.SuccessfulBypass != nil {
		sb.WriteString("\n## ✅ Bypass Successful\n\n")
		sb.WriteString(fmt.Sprintf("**Bypass Payload:**\n```\n%s\n```\n\n", result.SuccessfulBypass.Payload.Value))
		sb.WriteString(fmt.Sprintf("**Mutations Applied:** %s\n\n", strings.Join(result.SuccessfulBypass.Mutations, ", ")))

		if result.CurlCommand != "" {
			sb.WriteString("**Curl Command:**\n```bash\n")
			sb.WriteString(result.CurlCommand)
			sb.WriteString("\n```\n")
		}
	} else {
		sb.WriteString("\n## ❌ No Bypass Found\n\n")
	}

	if len(result.AllAttempts) > 0 {
		sb.WriteString("\n## Attempt Log\n\n")
		sb.WriteString("| # | Payload | Result | Mutations |\n")
		sb.WriteString("|---|---------|--------|----------|\n")

		for i, attempt := range result.AllAttempts {
			payload := attempt.Payload.Value
			if len(payload) > 40 {
				payload = payload[:37] + "..."
			}
			mutations := strings.Join(attempt.Mutations, ", ")
			if len(mutations) > 30 {
				mutations = mutations[:27] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s |\n",
				i+1, payload, attempt.Result, mutations))
		}
	}

	return []byte(sb.String()), nil
}

func (r *Reporter) formatHTML(result *types.BypassResult) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
    <title>BypassBurrito Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; border: 1px solid #c3e6cb; }
        .failure { background: #f8d7da; padding: 15px; border-radius: 5px; border: 1px solid #f5c6cb; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f4f4f4; }
        .blocked { color: #dc3545; }
        .bypassed { color: #28a745; }
    </style>
</head>
<body>
`)

	sb.WriteString("<h1>BypassBurrito Report 🌯</h1>\n")

	sb.WriteString("<h2>Summary</h2>\n<ul>\n")
	sb.WriteString(fmt.Sprintf("<li><strong>Original Payload:</strong> <code>%s</code></li>\n", escapeHTML(result.OriginalPayload.Value)))
	sb.WriteString(fmt.Sprintf("<li><strong>Attack Type:</strong> %s</li>\n", result.OriginalPayload.Type))
	sb.WriteString(fmt.Sprintf("<li><strong>Total Iterations:</strong> %d</li>\n", result.TotalIterations))
	sb.WriteString(fmt.Sprintf("<li><strong>Duration:</strong> %s</li>\n", result.Duration))
	if result.WAFDetected != nil {
		sb.WriteString(fmt.Sprintf("<li><strong>WAF Detected:</strong> %s (%.0f%% confidence)</li>\n",
			result.WAFDetected.Type, result.WAFDetected.Confidence*100))
	}
	sb.WriteString("</ul>\n")

	if result.Success && result.SuccessfulBypass != nil {
		sb.WriteString(`<div class="success">`)
		sb.WriteString("<h2>✅ Bypass Successful</h2>\n")
		sb.WriteString(fmt.Sprintf("<p><strong>Bypass Payload:</strong></p>\n<pre class=\"code\">%s</pre>\n",
			escapeHTML(result.SuccessfulBypass.Payload.Value)))
		sb.WriteString(fmt.Sprintf("<p><strong>Mutations:</strong> %s</p>\n",
			strings.Join(result.SuccessfulBypass.Mutations, ", ")))
		if result.CurlCommand != "" {
			sb.WriteString(fmt.Sprintf("<p><strong>Curl Command:</strong></p>\n<pre class=\"code\">%s</pre>\n",
				escapeHTML(result.CurlCommand)))
		}
		sb.WriteString("</div>\n")
	} else {
		sb.WriteString(`<div class="failure">`)
		sb.WriteString("<h2>❌ No Bypass Found</h2>\n")
		sb.WriteString("</div>\n")
	}

	if len(result.AllAttempts) > 0 {
		sb.WriteString("<h2>Attempt Log</h2>\n")
		sb.WriteString("<table>\n<tr><th>#</th><th>Payload</th><th>Result</th><th>Mutations</th></tr>\n")
		for i, attempt := range result.AllAttempts {
			resultClass := ""
			if attempt.Result == types.ResultBypassed {
				resultClass = "bypassed"
			} else if attempt.Result == types.ResultBlocked {
				resultClass = "blocked"
			}
			payload := attempt.Payload.Value
			if len(payload) > 50 {
				payload = payload[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td><code>%s</code></td><td class=\"%s\">%s</td><td>%s</td></tr>\n",
				i+1, escapeHTML(payload), resultClass, attempt.Result, strings.Join(attempt.Mutations, ", ")))
		}
		sb.WriteString("</table>\n")
	}

	sb.WriteString("</body>\n</html>")

	return []byte(sb.String()), nil
}

func (r *Reporter) formatBurp(result *types.BypassResult) ([]byte, error) {
	// Burp Suite XML format
	var sb strings.Builder

	sb.WriteString(`<?xml version="1.0"?>
<issues>
`)

	if result.Success && result.SuccessfulBypass != nil {
		sb.WriteString("  <issue>\n")
		sb.WriteString(fmt.Sprintf("    <serialNumber>%s</serialNumber>\n", result.ID))
		sb.WriteString(fmt.Sprintf("    <type>WAF Bypass - %s</type>\n", result.OriginalPayload.Type))
		sb.WriteString("    <severity>High</severity>\n")
		sb.WriteString("    <confidence>Certain</confidence>\n")
		sb.WriteString(fmt.Sprintf("    <issueBackground>A WAF bypass was discovered for %s attack type.</issueBackground>\n",
			result.OriginalPayload.Type))
		sb.WriteString(fmt.Sprintf("    <issueDetail>Original payload: %s\nBypass payload: %s\nMutations: %s</issueDetail>\n",
			escapeXML(result.OriginalPayload.Value),
			escapeXML(result.SuccessfulBypass.Payload.Value),
			strings.Join(result.SuccessfulBypass.Mutations, ", ")))
		sb.WriteString("    <remediationBackground>Review WAF rules and add detection for the bypass payload pattern.</remediationBackground>\n")
		sb.WriteString("  </issue>\n")
	}

	sb.WriteString("</issues>")

	return []byte(sb.String()), nil
}

func (r *Reporter) formatNuclei(result *types.BypassResult) ([]byte, error) {
	if !result.Success || result.SuccessfulBypass == nil {
		return []byte("# No bypass found - no template generated"), nil
	}

	template := map[string]interface{}{
		"id":   fmt.Sprintf("burrito-bypass-%s", result.ID[:8]),
		"info": map[string]interface{}{
			"name":        fmt.Sprintf("WAF Bypass - %s", result.OriginalPayload.Type),
			"author":      "bypassburrito",
			"severity":    "high",
			"description": fmt.Sprintf("WAF bypass for %s discovered by BypassBurrito", result.OriginalPayload.Type),
			"tags":        []string{"waf", "bypass", string(result.OriginalPayload.Type)},
		},
		"requests": []map[string]interface{}{
			{
				"method": "GET",
				"path":   []string{"{{BaseURL}}?param={{payload}}"},
				"payloads": map[string][]string{
					"payload": {result.SuccessfulBypass.Payload.Value},
				},
				"matchers": []map[string]interface{}{
					{
						"type":   "status",
						"status": []int{200},
					},
				},
			},
		},
	}

	return yaml.Marshal(template)
}

func (r *Reporter) formatDetectionText(report *DetectionReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("=== WAF Detection Report ===\n\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", report.Timestamp.Format(time.RFC3339)))

	if report.Result != nil && report.Result.Detected {
		sb.WriteString(fmt.Sprintf("WAF Type: %s\n", report.Result.Fingerprint.Type))
		confidence := report.Result.Confidence
		if confidence == 0 && report.Result.Fingerprint != nil {
			confidence = report.Result.Fingerprint.Confidence
		}
		sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", confidence*100))

		if len(report.Result.Evidence) > 0 {
			sb.WriteString("\nEvidence:\n")
			for _, e := range report.Result.Evidence {
				sb.WriteString(fmt.Sprintf("  - %s\n", e))
			}
		}
	} else {
		sb.WriteString("WAF: Not detected\n")
	}

	if report.Behavioral != nil {
		sb.WriteString(fmt.Sprintf("\nBaseline Latency: %dms\n", report.Behavioral.BaselineLatency))
		if report.Behavioral.RateLimitThreshold > 0 {
			sb.WriteString(fmt.Sprintf("Rate Limit: %d requests\n", report.Behavioral.RateLimitThreshold))
		}
	}

	return []byte(sb.String()), nil
}

func escapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func escapeXML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

// InferenceReport wraps WAF rule inference results
type InferenceReport struct {
	Target    string                     `json:"target" yaml:"target"`
	Result    *types.RuleInferenceResult `json:"result" yaml:"result"`
	Timestamp time.Time                  `json:"timestamp" yaml:"timestamp"`
}

// WriteInferenceReport writes rule inference results to a file
func (r *Reporter) WriteInferenceReport(report *InferenceReport, path string) error {
	var data []byte
	var err error

	switch r.format {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(report)
	case "markdown", "md":
		data, err = r.formatInferenceMarkdown(report)
	default:
		data, err = r.formatInferenceText(report)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (r *Reporter) formatInferenceText(report *InferenceReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("=== WAF Rule Inference Report ===\n\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", report.Timestamp.Format(time.RFC3339)))

	if report.Result != nil {
		sb.WriteString(fmt.Sprintf("WAF Type: %s\n", report.Result.WAFType))
		sb.WriteString(fmt.Sprintf("Total Samples: %d\n", report.Result.TotalSamples))
		sb.WriteString(fmt.Sprintf("Blocked: %d\n", report.Result.BlockedCount))
		sb.WriteString(fmt.Sprintf("Allowed: %d\n", report.Result.AllowedCount))
		sb.WriteString(fmt.Sprintf("Duration: %dms\n\n", report.Result.Duration))

		if len(report.Result.InferredRules) > 0 {
			sb.WriteString("=== Inferred Rules ===\n\n")
			for i, rule := range report.Result.InferredRules {
				sb.WriteString(fmt.Sprintf("%d. [%s] %s (%.0f%% confidence)\n",
					i+1, rule.Category, rule.Pattern, rule.Confidence*100))
				sb.WriteString(fmt.Sprintf("   Type: %s\n", rule.RuleType))
				if rule.Description != "" {
					sb.WriteString(fmt.Sprintf("   Description: %s\n", rule.Description))
				}
				if len(rule.EvasionHints) > 0 {
					sb.WriteString("   Evasion hints:\n")
					for _, hint := range rule.EvasionHints {
						sb.WriteString(fmt.Sprintf("     - %s\n", hint))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	return []byte(sb.String()), nil
}

func (r *Reporter) formatInferenceMarkdown(report *InferenceReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("# WAF Rule Inference Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Target:** %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("- **Timestamp:** %s\n\n", report.Timestamp.Format(time.RFC3339)))

	if report.Result != nil {
		sb.WriteString("## Summary\n\n")
		sb.WriteString(fmt.Sprintf("- **WAF Type:** %s\n", report.Result.WAFType))
		sb.WriteString(fmt.Sprintf("- **Total Samples:** %d\n", report.Result.TotalSamples))
		if report.Result.TotalSamples > 0 {
			sb.WriteString(fmt.Sprintf("- **Blocked:** %d (%.1f%%)\n", report.Result.BlockedCount,
				float64(report.Result.BlockedCount)/float64(report.Result.TotalSamples)*100))
			sb.WriteString(fmt.Sprintf("- **Allowed:** %d (%.1f%%)\n", report.Result.AllowedCount,
				float64(report.Result.AllowedCount)/float64(report.Result.TotalSamples)*100))
		} else {
			sb.WriteString(fmt.Sprintf("- **Blocked:** %d\n", report.Result.BlockedCount))
			sb.WriteString(fmt.Sprintf("- **Allowed:** %d\n", report.Result.AllowedCount))
		}
		sb.WriteString(fmt.Sprintf("- **Duration:** %dms\n\n", report.Result.Duration))

		if len(report.Result.InferredRules) > 0 {
			sb.WriteString("## Inferred Rules\n\n")
			sb.WriteString("| # | Category | Pattern | Type | Confidence |\n")
			sb.WriteString("|---|----------|---------|------|------------|\n")

			for i, rule := range report.Result.InferredRules {
				pattern := rule.Pattern
				if len(pattern) > 30 {
					pattern = pattern[:27] + "..."
				}
				sb.WriteString(fmt.Sprintf("| %d | %s | `%s` | %s | %.0f%% |\n",
					i+1, rule.Category, pattern, rule.RuleType, rule.Confidence*100))
			}

			sb.WriteString("\n### Rule Details\n\n")
			for i, rule := range report.Result.InferredRules {
				sb.WriteString(fmt.Sprintf("#### %d. %s\n\n", i+1, rule.Pattern))
				sb.WriteString(fmt.Sprintf("- **Category:** %s\n", rule.Category))
				sb.WriteString(fmt.Sprintf("- **Type:** %s\n", rule.RuleType))
				sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", rule.Confidence*100))

				if rule.Description != "" {
					sb.WriteString(fmt.Sprintf("- **Description:** %s\n", rule.Description))
				}

				if len(rule.EvasionHints) > 0 {
					sb.WriteString("\n**Evasion Hints:**\n")
					for _, hint := range rule.EvasionHints {
						sb.WriteString(fmt.Sprintf("- %s\n", hint))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	return []byte(sb.String()), nil
}
