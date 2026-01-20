package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/su1ph3r/bypassburrito/pkg/plugins"
)

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Manage mutation plugins",
	Long: `Manage custom mutation plugins for WAF bypass generation.

Plugins allow you to extend BypassBurrito with custom mutation strategies
written in Go. Plugins are loaded from ~/.bypassburrito/plugins/ by default.

Examples:
  # List all available plugins
  burrito plugins list

  # Show plugin details
  burrito plugins info myplugin

  # Get plugin directory path
  burrito plugins dir`,
}

var pluginsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available plugins",
	Long:  "List all mutation plugins found in the plugin directory.",
	RunE:  runPluginsList,
}

var pluginsInfoCmd = &cobra.Command{
	Use:   "info [name]",
	Short: "Show plugin details",
	Long:  "Show detailed information about a specific plugin.",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsInfo,
}

var pluginsDirCmd = &cobra.Command{
	Use:   "dir",
	Short: "Show plugin directory path",
	Long:  "Show the path to the plugin directory.",
	RunE:  runPluginsDir,
}

func init() {
	rootCmd.AddCommand(pluginsCmd)
	pluginsCmd.AddCommand(pluginsListCmd)
	pluginsCmd.AddCommand(pluginsInfoCmd)
	pluginsCmd.AddCommand(pluginsDirCmd)

	// Add flag for custom plugin directory
	pluginsCmd.PersistentFlags().String("plugin-dir", "", "Custom plugin directory (default: ~/.bypassburrito/plugins)")
}

func getPluginDir(cmd *cobra.Command) string {
	dir, _ := cmd.Flags().GetString("plugin-dir")
	if dir != "" {
		return dir
	}

	// Default to ~/.bypassburrito/plugins
	home, err := os.UserHomeDir()
	if err != nil {
		return "./plugins"
	}
	return filepath.Join(home, ".bypassburrito", "plugins")
}

func runPluginsList(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir(cmd)
	dataDir := filepath.Join(filepath.Dir(pluginDir), "plugin-data")

	loader := plugins.NewPluginLoader(pluginDir, dataDir)

	// Discover all plugins (loaded and unloaded)
	allPlugins := loader.Discover()

	if len(allPlugins) == 0 {
		fmt.Printf("No plugins found in: %s\n\n", pluginDir)
		fmt.Println("To install a plugin, place a compiled .so file in the plugin directory.")
		fmt.Println("See documentation for how to create custom plugins.")
		return nil
	}

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Printf("\nAvailable Plugins (%d found)\n", len(allPlugins))
	fmt.Println(strings.Repeat("─", 60))

	for _, info := range allPlugins {
		// Plugin name and version
		if info.Version != "" {
			fmt.Printf("\n  %s", color.CyanString(info.Name))
			fmt.Printf(" v%s", info.Version)
		} else {
			fmt.Printf("\n  %s", color.CyanString(info.Name))
		}

		// Status
		if info.Loaded {
			green.Print(" [loaded]")
		} else if info.Error != "" {
			color.Red(" [error]")
		}
		fmt.Println()

		// Description
		if info.Description != "" {
			fmt.Printf("    %s\n", info.Description)
		}

		// Author
		if info.Author != "" {
			fmt.Printf("    Author: %s\n", info.Author)
		}

		// Supported types
		if len(info.SupportedAttackTypes) > 0 {
			types := make([]string, len(info.SupportedAttackTypes))
			for i, t := range info.SupportedAttackTypes {
				types[i] = string(t)
			}
			fmt.Printf("    Attack types: %s\n", strings.Join(types, ", "))
		}

		if len(info.SupportedWAFTypes) > 0 {
			types := make([]string, len(info.SupportedWAFTypes))
			for i, t := range info.SupportedWAFTypes {
				types[i] = string(t)
			}
			fmt.Printf("    WAF types: %s\n", strings.Join(types, ", "))
		}

		// Error message if failed to load
		if info.Error != "" {
			yellow.Printf("    Error: %s\n", info.Error)
		}
	}

	fmt.Println()
	fmt.Printf("Plugin directory: %s\n", pluginDir)

	return nil
}

func runPluginsInfo(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir(cmd)
	dataDir := filepath.Join(filepath.Dir(pluginDir), "plugin-data")

	loader := plugins.NewPluginLoader(pluginDir, dataDir)

	// Try to load all plugins
	_ = loader.LoadAll()

	// Get the requested plugin
	plugin, ok := loader.Get(args[0])
	if !ok {
		return fmt.Errorf("plugin not found or failed to load: %s", args[0])
	}

	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Printf("\nPlugin: %s\n", plugin.Name())
	fmt.Println(strings.Repeat("─", 50))

	fmt.Printf("Version:     %s\n", plugin.Version())
	fmt.Printf("Author:      %s\n", plugin.Author())
	fmt.Printf("Description: %s\n", plugin.Description())
	fmt.Printf("Priority:    %d\n", plugin.Priority())

	// Supported attack types
	attackTypes := plugin.SupportedAttackTypes()
	if len(attackTypes) == 0 {
		fmt.Println("Attack Types: all")
	} else {
		types := make([]string, len(attackTypes))
		for i, t := range attackTypes {
			types[i] = string(t)
		}
		fmt.Printf("Attack Types: %s\n", strings.Join(types, ", "))
	}

	// Supported WAF types
	wafTypes := plugin.SupportedWAFTypes()
	if len(wafTypes) == 0 {
		fmt.Println("WAF Types:    all")
	} else {
		types := make([]string, len(wafTypes))
		for i, t := range wafTypes {
			types[i] = string(t)
		}
		fmt.Printf("WAF Types:    %s\n", strings.Join(types, ", "))
	}

	fmt.Println()

	return nil
}

func runPluginsDir(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir(cmd)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	fmt.Println(pluginDir)
	return nil
}
