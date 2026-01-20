package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/su1ph3r/bypassburrito/internal/http"
	"github.com/su1ph3r/bypassburrito/internal/waf"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

var inferCmd = &cobra.Command{
	Use:   "infer",
	Short: "Infer WAF rules from responses",
	Long: `Analyze WAF behavior to infer the rules and patterns being used.

This command sends a variety of test payloads to discover what patterns
the WAF blocks, allowing you to understand its rule configuration and
find potential bypass opportunities.

Examples:
  # Basic rule inference
  burrito infer -u "https://target.com/api" --param id

  # With more samples
  burrito infer -u "https://target.com/api" --param id --samples 100

  # Focus on specific attack types
  burrito infer -u "https://target.com/api" --param id --type sqli,xss

  # Output to JSON
  burrito infer -u "https://target.com/api" --param id -o rules.json -f json`,
	RunE: runInfer,
}

func init() {
	rootCmd.AddCommand(inferCmd)

	// Target flags
	inferCmd.Flags().StringP("url", "u", "", "Target URL (required)")
	inferCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	inferCmd.Flags().String("param", "", "Target parameter name (required)")
	inferCmd.Flags().String("position", "query", "Parameter position: query, body, header")
	inferCmd.Flags().StringArrayP("header", "H", nil, "Custom headers")

	// Inference settings
	inferCmd.Flags().Int("samples", 50, "Number of test samples to send")
	inferCmd.Flags().Float64("min-confidence", 0.6, "Minimum confidence threshold for rules")
	inferCmd.Flags().StringP("type", "t", "sqli,xss,cmdi,path_traversal", "Attack types to test (comma-separated)")
	inferCmd.Flags().Bool("hints", true, "Include evasion hints for each rule")

	// HTTP settings
	inferCmd.Flags().String("proxy", "", "HTTP proxy URL")
	inferCmd.Flags().Float64("rate-limit", 5.0, "Requests per second")
	inferCmd.Flags().Duration("timeout", 30*time.Second, "Request timeout")
	inferCmd.Flags().String("auth", "", "Authorization header")
	inferCmd.Flags().Bool("no-ssl-verify", false, "Skip SSL verification")

	// Output settings
	inferCmd.Flags().StringP("output", "o", "", "Output file")
	inferCmd.Flags().StringP("format", "f", "text", "Output format: json, yaml, text")

	// Required flags
	inferCmd.MarkFlagRequired("url")
	inferCmd.MarkFlagRequired("param")

	// Bind to viper
	viper.BindPFlags(inferCmd.Flags())
}

func runInfer(cmd *cobra.Command, args []string) error {
	// Get flags
	targetURL, _ := cmd.Flags().GetString("url")
	method, _ := cmd.Flags().GetString("method")
	param, _ := cmd.Flags().GetString("param")
	position, _ := cmd.Flags().GetString("position")
	samples, _ := cmd.Flags().GetInt("samples")
	minConfidence, _ := cmd.Flags().GetFloat64("min-confidence")
	attackTypesStr, _ := cmd.Flags().GetString("type")
	includeHints, _ := cmd.Flags().GetBool("hints")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	// Disable color if requested
	if noColor {
		color.NoColor = true
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			fmt.Println("\nInterrupted, cleaning up...")
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	// Print banner
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n=== WAF Rule Inference ===")

	// Initialize HTTP client
	httpConfig := types.HTTPConfig{
		Timeout:   timeout,
		ProxyURL:  proxyURL,
		RateLimit: rateLimit,
		VerifySSL: !viper.GetBool("no-ssl-verify"),
		Retry: types.RetryConfig{
			MaxRetries: 3,
		},
	}
	httpClient, err := http.NewClient(httpConfig)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Initialize WAF detector
	wafDetector, err := waf.NewDetector()
	if err != nil {
		return fmt.Errorf("failed to create WAF detector: %w", err)
	}

	// Build target config
	target := types.TargetConfig{
		URL:       targetURL,
		Method:    method,
		Parameter: param,
		Position:  parsePosition(position),
	}

	// Parse attack types
	var attackTypes []types.AttackType
	for _, t := range strings.Split(attackTypesStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			attackTypes = append(attackTypes, types.AttackType(t))
		}
	}

	// Build inference config
	inferConfig := waf.InferenceConfig{
		MinSamples:          samples / 2,
		MaxSamples:          samples,
		MinConfidence:       minConfidence,
		IncludeEvasionHints: includeHints,
		AttackTypes:         attackTypes,
	}

	// Create inference engine
	engine := waf.NewRuleInferenceEngine(wafDetector, httpClient)

	fmt.Printf("\nTarget: %s\n", targetURL)
	fmt.Printf("Parameter: %s (%s)\n", param, position)
	fmt.Printf("Testing attack types: %s\n", attackTypesStr)
	fmt.Printf("Max samples: %d\n\n", samples)

	fmt.Println("Running inference...")
	startTime := time.Now()

	// Run inference
	result, err := engine.InferRules(ctx, target, inferConfig)
	if err != nil {
		return fmt.Errorf("inference failed: %w", err)
	}

	// Print results
	printInferenceResults(result, outputFormat == "text")

	// Write output file if specified
	if outputFile != "" {
		if err := writeInferenceOutput(result, outputFile, outputFormat); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("\nResults written to: %s\n", outputFile)
	}

	fmt.Printf("\nCompleted in %s\n", time.Since(startTime).Round(time.Millisecond))

	return nil
}

func printInferenceResults(result *types.RuleInferenceResult, verbose bool) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)

	fmt.Println()

	// Summary
	cyan.Println("=== Summary ===")
	fmt.Printf("Total samples tested: %d\n", result.TotalSamples)
	if result.TotalSamples > 0 {
		fmt.Printf("Blocked: %d (%.1f%%)\n", result.BlockedCount,
			float64(result.BlockedCount)/float64(result.TotalSamples)*100)
		fmt.Printf("Allowed: %d (%.1f%%)\n", result.AllowedCount,
			float64(result.AllowedCount)/float64(result.TotalSamples)*100)
	} else {
		fmt.Printf("Blocked: %d\n", result.BlockedCount)
		fmt.Printf("Allowed: %d\n", result.AllowedCount)
	}

	if result.WAFType != types.WAFUnknown {
		fmt.Printf("Detected WAF: %s\n", green.Sprint(result.WAFType))
	}

	fmt.Println()

	// Inferred rules
	if len(result.InferredRules) == 0 {
		yellow.Println("No rules inferred with sufficient confidence.")
		return
	}

	cyan.Printf("=== Inferred Rules (%d found) ===\n\n", len(result.InferredRules))

	for i, rule := range result.InferredRules {
		// Rule header
		confidenceColor := color.FgYellow
		if rule.Confidence >= 0.9 {
			confidenceColor = color.FgGreen
		} else if rule.Confidence < 0.7 {
			confidenceColor = color.FgRed
		}

		fmt.Printf("%d. ", i+1)
		color.New(color.Bold).Printf("[%s] ", rule.Category)
		fmt.Printf("%s ", rule.Pattern)
		color.New(confidenceColor).Printf("(%.0f%% confidence)\n", rule.Confidence*100)

		// Rule details
		fmt.Printf("   Type: %s\n", rule.RuleType)
		if rule.Description != "" {
			fmt.Printf("   Description: %s\n", rule.Description)
		}

		// Examples
		if verbose && len(rule.Examples) > 0 {
			fmt.Println("   Examples:")
			for _, ex := range rule.Examples {
				if ex.Blocked {
					fmt.Printf("     %s %s", color.RedString("[BLOCKED]"), truncate(ex.Payload, 50))
				} else {
					fmt.Printf("     %s %s", color.GreenString("[ALLOWED]"), truncate(ex.Payload, 50))
				}
				if ex.Match != "" {
					fmt.Printf(" (matched: %s)", ex.Match)
				}
				fmt.Println()
			}
		}

		// Evasion hints
		if len(rule.EvasionHints) > 0 {
			yellow.Println("   Evasion hints:")
			for _, hint := range rule.EvasionHints {
				fmt.Printf("     - %s\n", hint)
			}
		}

		fmt.Println()
	}
}

func writeInferenceOutput(result *types.RuleInferenceResult, path, format string) error {
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(result, "", "  ")
	case "yaml", "yml":
		data, err = yaml.Marshal(result)
	default:
		// Text format
		var sb strings.Builder
		sb.WriteString("WAF Rule Inference Results\n")
		sb.WriteString(strings.Repeat("=", 50) + "\n\n")
		sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
		sb.WriteString(fmt.Sprintf("WAF Type: %s\n", result.WAFType))
		sb.WriteString(fmt.Sprintf("Samples: %d (blocked: %d, allowed: %d)\n\n",
			result.TotalSamples, result.BlockedCount, result.AllowedCount))

		sb.WriteString("Inferred Rules\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n\n")

		for i, rule := range result.InferredRules {
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

		data = []byte(sb.String())
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
