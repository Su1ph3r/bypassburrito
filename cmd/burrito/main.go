package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "burrito",
	Short: "BypassBurrito - Wrap around any WAF",
	Long: `BypassBurrito is an LLM-powered WAF bypass generator that wraps around
Web Application Firewalls using intelligent mutation strategies.

Features:
  - Multi-provider LLM support (OpenAI, Anthropic, Ollama, LM Studio, Groq)
  - Intelligent WAF detection and fingerprinting
  - Adaptive mutation strategies (extra spicy)
  - Learning system with pattern evolution
  - Multiple output formats (JSON, Markdown, HTML, Burp, Nuclei)
  - Burp Suite Pro integration via server mode

Example:
  burrito bypass -u "https://target.com/api" --param id --type sqli
  burrito detect -u "https://target.com" --deep
  burrito serve --port 8089`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bypassburrito.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("no_color", rootCmd.PersistentFlags().Lookup("no-color"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bypassburrito")
	}

	// Environment variables
	viper.SetEnvPrefix("BURRITO")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}
