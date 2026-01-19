package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/su1ph3r/bypassburrito/internal/bypass"
	"github.com/su1ph3r/bypassburrito/internal/bypass/strategies"
	"github.com/su1ph3r/bypassburrito/internal/http"
	"github.com/su1ph3r/bypassburrito/internal/learning"
	"github.com/su1ph3r/bypassburrito/internal/llm"
	"github.com/su1ph3r/bypassburrito/internal/output"
	"github.com/su1ph3r/bypassburrito/internal/payloads"
	"github.com/su1ph3r/bypassburrito/internal/waf"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

var bypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "Generate WAF bypass payloads",
	Long: `Generate WAF bypass payloads using LLM-powered mutation strategies.

The bypass command iteratively tests payloads against a target URL,
analyzing WAF responses and generating mutations to evade detection.

Examples:
  # Basic SQLi bypass
  burrito bypass -u "https://target.com/api" --param id --type sqli

  # XSS with proxy
  burrito bypass -u "https://target.com/search" --param q --type xss --proxy http://127.0.0.1:8080

  # Multiple payload types
  burrito bypass -u "https://target.com/api" --param input --type sqli,xss

  # Custom payloads
  burrito bypass -u "https://target.com/api" --param id --payload "' OR 1=1--"

  # With ensemble LLM
  burrito bypass -u "https://target.com/api" --param id --type sqli --ensemble`,
	RunE: runBypass,
}

func init() {
	rootCmd.AddCommand(bypassCmd)

	// Target flags
	bypassCmd.Flags().StringP("url", "u", "", "Target URL (required)")
	bypassCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	bypassCmd.Flags().StringP("data", "d", "", "Request body")
	bypassCmd.Flags().StringArrayP("header", "H", nil, "Custom headers")
	bypassCmd.Flags().String("param", "", "Target parameter name (required)")
	bypassCmd.Flags().String("position", "query", "Parameter position: query, body, header, path, cookie")
	bypassCmd.Flags().String("content-type", "", "Content-Type for body")

	// Attack configuration
	bypassCmd.Flags().StringP("type", "t", "sqli", "Attack type: xss, sqli, cmdi, path_traversal, ssti, xxe, all")
	bypassCmd.Flags().StringP("payload", "P", "", "Single custom payload")
	bypassCmd.Flags().String("payload-file", "", "File with payloads (one per line)")
	bypassCmd.Flags().Bool("polyglot", false, "Include polyglot payloads")

	// Bypass engine settings
	bypassCmd.Flags().Int("max-iterations", 15, "Max iterations per payload")
	bypassCmd.Flags().Int("max-payloads", 30, "Max base payloads to test")
	bypassCmd.Flags().Int("mutation-depth", 5, "Max mutation chain depth")
	bypassCmd.Flags().Bool("detect-waf", true, "Auto-detect WAF type")
	bypassCmd.Flags().String("waf-type", "", "Force specific WAF type")
	bypassCmd.Flags().Bool("use-learned", true, "Use learned patterns")
	bypassCmd.Flags().Bool("evolve", false, "Enable genetic evolution")

	// LLM settings
	bypassCmd.Flags().StringP("provider", "p", "anthropic", "LLM provider: openai, anthropic, ollama, lmstudio, groq")
	bypassCmd.Flags().String("model", "", "Model name")
	bypassCmd.Flags().String("api-key", "", "API key")
	bypassCmd.Flags().String("llm-url", "", "Base URL for local LLM")
	bypassCmd.Flags().Bool("ensemble", false, "Use multi-model ensemble")
	bypassCmd.Flags().Float64("temperature", 0.3, "LLM temperature")

	// HTTP settings
	bypassCmd.Flags().String("proxy", "", "HTTP proxy URL")
	bypassCmd.Flags().Float64("rate-limit", 5.0, "Requests per second")
	bypassCmd.Flags().Duration("timeout", 30*time.Second, "Request timeout")
	bypassCmd.Flags().String("auth", "", "Authorization header")
	bypassCmd.Flags().StringArray("cookie", nil, "Cookies")
	bypassCmd.Flags().String("user-agent", "", "Custom User-Agent")
	bypassCmd.Flags().Bool("no-ssl-verify", false, "Skip SSL verification")

	// Output settings
	bypassCmd.Flags().StringP("output", "o", "", "Output file")
	bypassCmd.Flags().StringP("format", "f", "text", "Output format: json, text, markdown, html, burp, nuclei")
	bypassCmd.Flags().Bool("show-all", false, "Show all attempts")
	bypassCmd.Flags().Bool("curl", true, "Generate curl commands")
	bypassCmd.Flags().String("save-requests", "", "Save all requests to directory")

	// Advanced
	bypassCmd.Flags().Bool("aggressive", false, "More aggressive mutations")
	bypassCmd.Flags().Bool("stealth", false, "Stealth mode (slower)")
	bypassCmd.Flags().Bool("dry-run", false, "Generate without sending")

	// Required flags
	bypassCmd.MarkFlagRequired("url")
	bypassCmd.MarkFlagRequired("param")

	// Bind to viper
	viper.BindPFlags(bypassCmd.Flags())
}

func runBypass(cmd *cobra.Command, args []string) error {
	// Get flags
	targetURL, _ := cmd.Flags().GetString("url")
	method, _ := cmd.Flags().GetString("method")
	param, _ := cmd.Flags().GetString("param")
	position, _ := cmd.Flags().GetString("position")
	attackTypes, _ := cmd.Flags().GetString("type")
	customPayload, _ := cmd.Flags().GetString("payload")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	showAll, _ := cmd.Flags().GetBool("show-all")
	maxIterations, _ := cmd.Flags().GetInt("max-iterations")
	maxPayloads, _ := cmd.Flags().GetInt("max-payloads")
	detectWAF, _ := cmd.Flags().GetBool("detect-waf")
	providerName, _ := cmd.Flags().GetString("provider")
	apiKey, _ := cmd.Flags().GetString("api-key")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")
	timeout, _ := cmd.Flags().GetDuration("timeout")
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
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, cleaning up...")
		cancel()
	}()

	// Print banner
	printBanner()

	// Initialize components
	fmt.Println("Initializing...")

	// Create HTTP client
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

	// Create LLM provider
	llmProvider, err := createLLMProvider(providerName, apiKey)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}
	fmt.Printf("Using LLM provider: %s (%s)\n", llmProvider.Name(), llmProvider.Model())

	// Create WAF detector
	wafDetector, err := waf.NewDetector()
	if err != nil {
		return fmt.Errorf("failed to create WAF detector: %w", err)
	}

	// Create learning store
	learnStore := learning.NewStore("~/.bypassburrito/learned-patterns.yaml", true)
	if err := learnStore.Load(); err != nil {
		fmt.Printf("Warning: Could not load learned patterns: %v\n", err)
	}

	// Build target config
	target := types.TargetConfig{
		URL:       targetURL,
		Method:    method,
		Parameter: param,
		Position:  parsePosition(position),
	}

	// Load payloads
	payloadLib := payloads.NewPayloadLibrary()
	if err := payloadLib.LoadEmbedded(); err != nil {
		fmt.Printf("Warning: Could not load embedded payloads: %v\n", err)
	}

	// Get payloads based on attack type
	var basePayloads []types.Payload
	if customPayload != "" {
		basePayloads = []types.Payload{{Value: customPayload, Type: types.AttackType(attackTypes)}}
	} else {
		for _, at := range strings.Split(attackTypes, ",") {
			attackType := types.AttackType(strings.TrimSpace(at))
			payloadsForType := payloadLib.GetPayloads(attackType)
			if len(payloadsForType) > maxPayloads {
				payloadsForType = payloadsForType[:maxPayloads]
			}
			basePayloads = append(basePayloads, payloadsForType...)
		}
	}

	if len(basePayloads) == 0 {
		return fmt.Errorf("no payloads found for attack type: %s", attackTypes)
	}

	fmt.Printf("Loaded %d base payloads for %s\n", len(basePayloads), attackTypes)

	// Create bypass config
	bypassConfig := types.BypassConfig{
		MaxIterations: maxIterations,
		MaxPayloads:   maxPayloads,
		DetectWAF:     detectWAF,
		UseLearned:    viper.GetBool("use-learned"),
		Strategies: types.StrategyConfig{
			Enabled: []string{"encoding", "obfuscation", "fragmentation", "polymorphic", "contextual"},
		},
	}

	// Create bypass loop
	bypassLoop := bypass.NewBypassLoop(llmProvider, wafDetector, httpClient, bypassConfig)

	// Create bypass request
	request := types.BypassRequest{
		ID:       bypass.GenerateID(),
		Target:   target,
		Payloads: basePayloads,
		Options: types.BypassOptions{
			Aggressive: viper.GetBool("aggressive"),
			Stealth:    viper.GetBool("stealth"),
		},
	}

	// Create progress bar
	bar := progressbar.NewOptions(len(basePayloads)*maxIterations,
		progressbar.OptionSetDescription("Testing payloads"),
		progressbar.OptionSetWidth(40),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Subscribe to events
	events := bypassLoop.Subscribe(request.ID)
	go func() {
		for event := range events {
			switch event.Type {
			case "iteration_start":
				bar.Add(1)
			case "waf_detected":
				if fp, ok := event.Data.(*types.WAFFingerprint); ok {
					fmt.Printf("\n%s WAF detected: %s (confidence: %.0f%%)\n",
						color.YellowString("[!]"),
						fp.Type,
						fp.Confidence*100)
				}
			case "bypass_found":
				if attempt, ok := event.Data.(types.BypassAttempt); ok {
					fmt.Printf("\n%s Bypass found! Payload: %s\n",
						color.GreenString("[+]"),
						truncate(attempt.Payload.Value, 80))
				}
			}
		}
	}()

	// Run bypass
	fmt.Println("\nStarting bypass generation...")
	startTime := time.Now()

	result, err := bypassLoop.Run(ctx, request)
	if err != nil {
		return fmt.Errorf("bypass failed: %w", err)
	}

	bar.Finish()
	fmt.Println()

	// Print results
	printResults(result, showAll)

	// Generate output
	reporter := output.NewReporter(outputFormat)
	if outputFile != "" {
		if err := reporter.WriteToFile(result, outputFile); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("\nResults written to: %s\n", outputFile)
	}

	// Record to learning store
	for _, attempt := range result.AllAttempts {
		wafType := types.WAFUnknown
		if result.WAFDetected != nil {
			wafType = result.WAFDetected.Type
		}
		success := attempt.Result == types.ResultBypassed
		learnStore.Record(&attempt, wafType, success)
	}
	learnStore.Save()

	// Summary
	fmt.Printf("\nCompleted in %s\n", time.Since(startTime).Round(time.Millisecond))
	fmt.Printf("Total attempts: %d\n", result.TotalIterations)
	if result.Success {
		color.Green("Status: BYPASS FOUND")
	} else {
		color.Red("Status: No bypass found")
	}

	return nil
}

func createLLMProvider(name, apiKey string) (llm.Provider, error) {
	// Try environment variable if not provided
	if apiKey == "" {
		switch name {
		case "anthropic":
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		case "openai":
			apiKey = os.Getenv("OPENAI_API_KEY")
		case "groq":
			apiKey = os.Getenv("GROQ_API_KEY")
		}
	}

	config := types.ProviderConfig{
		APIKey:      apiKey,
		Temperature: viper.GetFloat64("temperature"),
		MaxTokens:   8192,
	}

	switch name {
	case "anthropic":
		model := viper.GetString("model")
		if model == "" {
			model = "claude-sonnet-4-20250514"
		}
		config.Model = model
		return llm.NewAnthropicProvider(config)
	case "openai":
		model := viper.GetString("model")
		if model == "" {
			model = "gpt-4o"
		}
		config.Model = model
		return llm.NewOpenAIProvider(config)
	case "ollama":
		model := viper.GetString("model")
		if model == "" {
			model = "llama3:70b"
		}
		config.Model = model
		config.BaseURL = viper.GetString("llm-url")
		if config.BaseURL == "" {
			config.BaseURL = "http://localhost:11434"
		}
		return llm.NewOllamaProvider(config)
	case "lmstudio":
		model := viper.GetString("model")
		config.Model = model
		config.BaseURL = viper.GetString("llm-url")
		if config.BaseURL == "" {
			config.BaseURL = "http://localhost:1234"
		}
		return llm.NewLMStudioProvider(config)
	case "groq":
		model := viper.GetString("model")
		if model == "" {
			model = "llama-3.1-70b-versatile"
		}
		config.Model = model
		return llm.NewGroqProvider(config)
	default:
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
}

func parsePosition(s string) types.ParameterPosition {
	switch strings.ToLower(s) {
	case "query":
		return types.PositionQuery
	case "body":
		return types.PositionBody
	case "header":
		return types.PositionHeader
	case "cookie":
		return types.PositionCookie
	case "path":
		return types.PositionPath
	default:
		return types.PositionQuery
	}
}

func printBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Print(`
  ____                              ____                  _ _
 | __ ) _   _ _ __   __ _ ___ ___  | __ ) _   _ _ __ _ __(_) |_ ___
 |  _ \| | | | '_ \ / _' / __/ __| |  _ \| | | | '__| '__| | __/ _ \
 | |_) | |_| | |_) | (_| \__ \__ \ | |_) | |_| | |  | |  | | || (_) |
 |____/ \__, | .__/ \__,_|___/___/ |____/ \__,_|_|  |_|  |_|\__\___/
        |___/|_|                                             🌯

  Wrap Around Any WAF - LLM-Powered Bypass Generator
`)
}

func printResults(result *types.BypassResult, showAll bool) {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	if result.Success && result.SuccessfulBypass != nil {
		green.Println("\n=== BYPASS SUCCESSFUL ===")
		fmt.Printf("\nOriginal payload: %s\n", result.OriginalPayload.Value)
		fmt.Printf("Bypass payload:   %s\n", result.SuccessfulBypass.Payload.Value)
		fmt.Printf("Mutations:        %s\n", strings.Join(result.SuccessfulBypass.Mutations, ", "))
		fmt.Printf("Iterations:       %d\n", result.SuccessfulBypass.Iteration)

		if result.CurlCommand != "" {
			fmt.Println("\nCurl command:")
			yellow.Println(result.CurlCommand)
		}
	} else {
		red.Println("\n=== NO BYPASS FOUND ===")
	}

	if showAll && len(result.AllAttempts) > 0 {
		fmt.Println("\n=== All Attempts ===")
		for i, attempt := range result.AllAttempts {
			status := ""
			switch attempt.Result {
			case types.ResultBypassed:
				status = green.Sprint("[BYPASS]")
			case types.ResultBlocked:
				status = red.Sprint("[BLOCKED]")
			case types.ResultError:
				status = yellow.Sprint("[ERROR]")
			default:
				status = "[UNKNOWN]"
			}
			fmt.Printf("%3d. %s %s\n", i+1, status, truncate(attempt.Payload.Value, 60))
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// Ensure strategies package is used
var _ = strategies.NewEncodingMutator
