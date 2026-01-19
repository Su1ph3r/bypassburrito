package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/su1ph3r/bypassburrito/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start server mode for Burp Suite integration",
	Long: `Start BypassBurrito in server mode to enable Burp Suite Pro integration.

The server provides a REST API and WebSocket endpoints for:
- Submitting bypass requests
- Streaming real-time progress
- Managing the request queue
- Accessing learned patterns

The companion Burp Suite extension connects to this server.

Examples:
  # Start server on default port
  burrito serve

  # Custom port with authentication
  burrito serve --port 9000 --auth-token "secret"

  # Allow external connections
  burrito serve --host 0.0.0.0 --port 8089`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().Int("port", 8089, "Server port")
	serveCmd.Flags().String("host", "localhost", "Host to bind")
	serveCmd.Flags().Bool("cors", true, "Enable CORS")
	serveCmd.Flags().String("auth-token", "", "Require auth token for API access")
	serveCmd.Flags().Int("max-concurrent", 5, "Max concurrent bypass operations")
	serveCmd.Flags().Bool("websocket", true, "Enable WebSocket for real-time updates")
	serveCmd.Flags().Bool("no-color", false, "Disable colored output")

	// LLM settings (same as bypass)
	serveCmd.Flags().StringP("provider", "p", "anthropic", "Default LLM provider")
	serveCmd.Flags().String("model", "", "Default model name")
	serveCmd.Flags().String("api-key", "", "API key")

	viper.BindPFlags(serveCmd.Flags())
}

func runServe(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	host, _ := cmd.Flags().GetString("host")
	enableCORS, _ := cmd.Flags().GetBool("cors")
	authToken, _ := cmd.Flags().GetString("auth-token")
	maxConcurrent, _ := cmd.Flags().GetInt("max-concurrent")
	enableWebSocket, _ := cmd.Flags().GetBool("websocket")
	noColor, _ := cmd.Flags().GetBool("no-color")
	provider, _ := cmd.Flags().GetString("provider")
	apiKey, _ := cmd.Flags().GetString("api-key")

	if noColor {
		color.NoColor = true
	}

	// Get API key from environment if not provided
	if apiKey == "" {
		switch provider {
		case "anthropic":
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		case "openai":
			apiKey = os.Getenv("OPENAI_API_KEY")
		case "groq":
			apiKey = os.Getenv("GROQ_API_KEY")
		}
	}

	// Print banner
	printServerBanner()

	// Create server config
	config := server.Config{
		Host:            host,
		Port:            port,
		EnableCORS:      enableCORS,
		AuthToken:       authToken,
		MaxConcurrent:   maxConcurrent,
		EnableWebSocket: enableWebSocket,
		LLMProvider:     provider,
		LLMAPIKey:       apiKey,
		LLMModel:        viper.GetString("model"),
	}

	// Create and start server
	srv, err := server.New(config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down server...")
		srv.Shutdown()
	}()

	// Print server info
	fmt.Printf("Server starting on %s:%d\n", host, port)
	fmt.Println()
	fmt.Println("API Endpoints:")
	fmt.Printf("  POST   /api/v1/bypass        - Submit bypass request\n")
	fmt.Printf("  GET    /api/v1/bypass/:id    - Get bypass status\n")
	fmt.Printf("  DELETE /api/v1/bypass/:id    - Cancel bypass\n")
	fmt.Printf("  POST   /api/v1/detect        - Detect WAF\n")
	fmt.Printf("  GET    /api/v1/queue         - List queue\n")
	fmt.Printf("  GET    /api/v1/patterns      - List learned patterns\n")
	fmt.Printf("  GET    /api/v1/health        - Health check\n")
	if enableWebSocket {
		fmt.Printf("  WS     /api/v1/bypass/:id/ws - Real-time updates\n")
	}
	fmt.Println()

	if authToken != "" {
		fmt.Println("Authentication: Enabled (use Authorization header)")
	} else {
		color.Yellow("Warning: No authentication configured. Consider using --auth-token")
	}
	fmt.Println()

	// Start server (blocks until shutdown)
	return srv.Start()
}

func printServerBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Print(`
  ____                              ____                  _ _
 | __ ) _   _ _ __   __ _ ___ ___  | __ ) _   _ _ __ _ __(_) |_ ___
 |  _ \| | | | '_ \ / _' / __/ __| |  _ \| | | | '__| '__| | __/ _ \
 | |_) | |_| | |_) | (_| \__ \__ \ | |_) | |_| | |  | |  | | || (_) |
 |____/ \__, | .__/ \__,_|___/___/ |____/ \__,_|_|  |_|  |_|\__\___/
        |___/|_|                                             🌯

  BypassBurrito Server - Burp Suite Integration Mode
`)
}
