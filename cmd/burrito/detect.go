package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/su1ph3r/bypassburrito/internal/http"
	"github.com/su1ph3r/bypassburrito/internal/output"
	"github.com/su1ph3r/bypassburrito/internal/waf"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect and fingerprint WAF",
	Long: `Detect and fingerprint the Web Application Firewall protecting a target.

The detect command sends various probes to identify the WAF type, version,
ruleset, and behavioral characteristics.

Examples:
  # Basic detection
  burrito detect -u "https://target.com"

  # Deep analysis with behavioral profiling
  burrito detect -u "https://target.com" --deep

  # Output to file
  burrito detect -u "https://target.com" -o waf-report.json -f json`,
	RunE: runDetect,
}

func init() {
	rootCmd.AddCommand(detectCmd)

	detectCmd.Flags().StringP("url", "u", "", "Target URL (required)")
	detectCmd.Flags().Bool("deep", false, "Deep WAF analysis (behavioral profiling)")
	detectCmd.Flags().Bool("probe-payloads", true, "Use payloads to trigger WAF")
	detectCmd.Flags().Bool("identify-ruleset", false, "Attempt to identify WAF ruleset")
	detectCmd.Flags().StringP("output", "o", "", "Output file")
	detectCmd.Flags().StringP("format", "f", "text", "Output format: json, text, markdown")
	detectCmd.Flags().String("proxy", "", "HTTP proxy URL")
	detectCmd.Flags().Duration("timeout", 30*time.Second, "Request timeout")
	detectCmd.Flags().Bool("no-color", false, "Disable colored output")

	detectCmd.MarkFlagRequired("url")
}

func runDetect(cmd *cobra.Command, args []string) error {
	targetURL, _ := cmd.Flags().GetString("url")
	deep, _ := cmd.Flags().GetBool("deep")
	probePayloads, _ := cmd.Flags().GetBool("probe-payloads")
	identifyRuleset, _ := cmd.Flags().GetBool("identify-ruleset")
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	noColor, _ := cmd.Flags().GetBool("no-color")

	if noColor {
		color.NoColor = true
	}

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted...")
		cancel()
	}()

	// Print header
	fmt.Println()
	color.Cyan("=== WAF Detection ===")
	fmt.Printf("Target: %s\n\n", targetURL)

	// Create HTTP client
	httpConfig := types.HTTPConfig{
		Timeout:   timeout,
		ProxyURL:  proxyURL,
		RateLimit: 5.0,
	}
	httpClient, err := http.NewClient(httpConfig)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create WAF detector
	detector, err := waf.NewDetector()
	if err != nil {
		return fmt.Errorf("failed to create WAF detector: %w", err)
	}

	// Phase 1: Baseline request
	fmt.Println("Phase 1: Making baseline request...")
	baselineReq := &types.HTTPRequest{
		Method:    "GET",
		URL:       targetURL,
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	baselineResp, err := httpClient.Do(ctx, baselineReq)
	if err != nil {
		return fmt.Errorf("baseline request failed: %w", err)
	}

	fmt.Printf("  Status: %d\n", baselineResp.StatusCode)
	fmt.Printf("  Latency: %s\n", baselineResp.Latency)

	// Phase 2: WAF detection
	fmt.Println("\nPhase 2: Analyzing response for WAF signatures...")
	result := detector.Detect(baselineResp)

	// Phase 3: Probe with payloads
	if probePayloads {
		fmt.Println("\nPhase 3: Probing with test payloads...")
		probeResult := probeWAF(ctx, httpClient, targetURL, detector)
		if probeResult != nil && probeResult.Confidence > result.Confidence {
			result = probeResult
		}
	}

	// Phase 4: Deep analysis
	var behavioral *types.BehavioralProfile
	if deep {
		fmt.Println("\nPhase 4: Behavioral analysis...")
		behavioral = analyzeBehavior(ctx, httpClient, targetURL)
	}

	// Phase 5: Ruleset identification
	if identifyRuleset && result.Detected {
		fmt.Println("\nPhase 5: Identifying ruleset...")
		ruleset := identifyWAFRuleset(ctx, httpClient, targetURL)
		if ruleset != "" {
			fmt.Printf("  Detected ruleset: %s\n", ruleset)
		}
	}

	// Print results
	printDetectionResults(result, behavioral)

	// Output to file
	if outputFile != "" {
		reporter := output.NewReporter(outputFormat)
		detectionReport := &output.DetectionReport{
			Target:     targetURL,
			Result:     result,
			Behavioral: behavioral,
			Timestamp:  time.Now(),
		}
		if err := reporter.WriteDetectionReport(detectionReport, outputFile); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("\nReport written to: %s\n", outputFile)
	}

	return nil
}

func probeWAF(ctx context.Context, client *http.Client, targetURL string, detector *waf.Detector) *types.WAFDetectionResult {
	// Test payloads to trigger WAF
	testPayloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"../../../etc/passwd",
		"; cat /etc/passwd",
		"{{7*7}}",
	}

	var bestResult *types.WAFDetectionResult

	for _, payload := range testPayloads {
		select {
		case <-ctx.Done():
			return bestResult
		default:
		}

		req := &types.HTTPRequest{
			Method:    "GET",
			URL:       targetURL + "?test=" + payload,
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}

		result := detector.Detect(resp)
		if result.Detected {
			if bestResult == nil || result.Confidence > bestResult.Confidence {
				bestResult = result
			}
		}

		// Small delay between probes
		time.Sleep(200 * time.Millisecond)
	}

	return bestResult
}

func analyzeBehavior(ctx context.Context, client *http.Client, targetURL string) *types.BehavioralProfile {
	profile := &types.BehavioralProfile{}

	// Measure baseline latency
	var latencies []time.Duration
	for i := 0; i < 5; i++ {
		req := &types.HTTPRequest{
			Method:    "GET",
			URL:       targetURL,
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		latencies = append(latencies, resp.Latency)
		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) > 0 {
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		avgLatency := total / time.Duration(len(latencies))
		profile.BaselineLatency = avgLatency.Milliseconds()
	}

	// Test rate limiting
	fmt.Print("  Testing rate limits")
	requestCount := 0
	for i := 0; i < 50; i++ {
		req := &types.HTTPRequest{
			Method:    "GET",
			URL:       targetURL,
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			break
		}

		if resp.StatusCode == 429 {
			profile.RateLimitThreshold = requestCount
			break
		}
		requestCount++
		fmt.Print(".")
	}
	fmt.Println()

	if profile.RateLimitThreshold == 0 && requestCount >= 50 {
		fmt.Println("  Rate limit not detected (50+ requests)")
	} else if profile.RateLimitThreshold > 0 {
		fmt.Printf("  Rate limit threshold: %d requests\n", profile.RateLimitThreshold)
	}

	return profile
}

func identifyWAFRuleset(ctx context.Context, client *http.Client, targetURL string) string {
	// OWASP CRS detection payloads
	owaspProbes := map[string]string{
		"SQL injection 942100": "' OR 1=1--",
		"XSS 941100":           "<script>alert(1)</script>",
		"LFI 930100":           "../../../etc/passwd",
	}

	for ruleName, payload := range owaspProbes {
		req := &types.HTTPRequest{
			Method:    "GET",
			URL:       targetURL + "?test=" + payload,
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}

		// Check for OWASP CRS error format
		if resp.StatusCode == 403 {
			if containsAny(resp.Body, "ModSecurity", "OWASP", "CRS") {
				return "OWASP ModSecurity Core Rule Set"
			}
		}

		time.Sleep(200 * time.Millisecond)
		_ = ruleName // Suppress unused warning
	}

	return ""
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func printDetectionResults(result *types.WAFDetectionResult, behavioral *types.BehavioralProfile) {
	fmt.Println()

	// Create table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Property", "Value"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	if result.Detected {
		color.Green("WAF Detected!")
		fmt.Println()

		table.Append([]string{"WAF Type", string(result.Fingerprint.Type)})
		table.Append([]string{"Confidence", fmt.Sprintf("%.0f%%", result.Confidence*100)})

		if result.Fingerprint.Version != "" {
			table.Append([]string{"Version", result.Fingerprint.Version})
		}

		if len(result.Fingerprint.Headers) > 0 {
			headers := ""
			for k, v := range result.Fingerprint.Headers {
				headers += fmt.Sprintf("%s: %s\n", k, v)
			}
			table.Append([]string{"WAF Headers", headers})
		}

		if len(result.Evidence) > 0 {
			evidence := ""
			for _, e := range result.Evidence {
				evidence += fmt.Sprintf("- %s\n", e)
			}
			table.Append([]string{"Evidence", evidence})
		}
	} else {
		color.Yellow("No WAF detected (or WAF is not blocking)")
		fmt.Println()
		table.Append([]string{"Status", "No WAF detected"})
	}

	if behavioral != nil {
		table.Append([]string{"Baseline Latency", fmt.Sprintf("%dms", behavioral.BaselineLatency)})
		if behavioral.RateLimitThreshold > 0 {
			table.Append([]string{"Rate Limit", fmt.Sprintf("%d requests", behavioral.RateLimitThreshold)})
		}
	}

	table.Render()

	// Recommendations
	if result.Detected {
		fmt.Println()
		color.Cyan("Recommended Evasion Techniques:")
		recommendations := getRecommendations(result.Fingerprint.Type)
		for i, rec := range recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}
}

func getRecommendations(wafType types.WAFType) []string {
	recommendations := map[types.WAFType][]string{
		types.WAFCloudflare: {
			"Double URL encoding",
			"Unicode normalization exploits",
			"HTTP parameter pollution",
			"Chunked transfer encoding",
		},
		types.WAFModSecurity: {
			"Comment injection (/**/)",
			"Case variation",
			"Null byte injection",
			"HTTP verb tampering",
		},
		types.WAFAWSWaf: {
			"Unicode encoding",
			"Parameter pollution",
			"Content-Type manipulation",
			"JSON/XML encoding",
		},
		types.WAFAkamai: {
			"Alternative syntax",
			"Whitespace manipulation",
			"Encoding combinations",
			"Protocol-level evasion",
		},
		types.WAFImperva: {
			"Polymorphic payloads",
			"Multi-encoding",
			"Fragmented requests",
			"Header manipulation",
		},
	}

	if recs, ok := recommendations[wafType]; ok {
		return recs
	}

	return []string{
		"Try various encoding techniques",
		"Use alternative syntax",
		"Test with different HTTP methods",
		"Apply case variation",
	}
}
