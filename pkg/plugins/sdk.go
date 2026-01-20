// Package plugins provides the Mutation Plugin SDK for BypassBurrito.
// Users can write custom mutation plugins in Go that integrate seamlessly
// with the bypass engine.
package plugins

import (
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// MutationPlugin is the interface that all mutation plugins must implement.
// Plugins are loaded dynamically and integrated into the mutation chain.
type MutationPlugin interface {
	// Name returns the unique identifier for this plugin
	Name() string

	// Version returns the semantic version of this plugin
	Version() string

	// Description returns a human-readable description of what this plugin does
	Description() string

	// Author returns the plugin author information
	Author() string

	// Mutate generates mutation variants for a given payload.
	// It receives the payload and context information about the current bypass attempt.
	Mutate(payload string, ctx MutationContext) []MutationResult

	// Priority returns the execution priority (lower = earlier).
	// Plugins with lower priority values are executed first.
	Priority() int

	// SupportedAttackTypes returns which attack types this plugin supports.
	// Return nil or empty slice to support all attack types.
	SupportedAttackTypes() []types.AttackType

	// SupportedWAFTypes returns which WAF types this plugin is optimized for.
	// Return nil or empty slice to apply to all WAFs.
	SupportedWAFTypes() []types.WAFType

	// Initialize is called when the plugin is loaded.
	// Use this for any setup or resource initialization.
	Initialize(config PluginConfig) error

	// Cleanup is called when the plugin is unloaded.
	// Use this to release any resources.
	Cleanup() error
}

// MutationContext provides context information to the plugin about the current
// bypass attempt. This allows plugins to make intelligent decisions based on
// what has been tried before and what the target environment looks like.
type MutationContext struct {
	// AttackType is the type of attack being attempted (sqli, xss, etc.)
	AttackType types.AttackType `json:"attack_type"`

	// WAFType is the detected or configured WAF type
	WAFType types.WAFType `json:"waf_type"`

	// Position is where the payload will be injected (query, body, header, etc.)
	Position types.ParameterPosition `json:"position"`

	// ContentType is the content type of the request body (if applicable)
	ContentType string `json:"content_type,omitempty"`

	// PreviousTries contains mutations that have already been attempted
	PreviousTries []string `json:"previous_tries"`

	// BlockedPatterns contains patterns that caused blocks
	BlockedPatterns []string `json:"blocked_patterns,omitempty"`

	// SuccessfulMutations contains mutations that have worked before
	SuccessfulMutations []string `json:"successful_mutations,omitempty"`

	// Iteration is the current bypass iteration number
	Iteration int `json:"iteration"`

	// MaxIterations is the maximum number of iterations configured
	MaxIterations int `json:"max_iterations"`

	// TargetURL is the URL being tested (for context, not for making requests)
	TargetURL string `json:"target_url,omitempty"`

	// CustomData allows passing arbitrary data between plugins
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
}

// MutationResult represents a single mutation output from a plugin.
type MutationResult struct {
	// Payload is the mutated payload string
	Payload string `json:"payload"`

	// Mutations is a list of mutation names applied to produce this payload
	Mutations []string `json:"mutations"`

	// Description explains what this mutation does
	Description string `json:"description"`

	// Confidence is the plugin's confidence that this mutation will bypass (0.0-1.0)
	Confidence float64 `json:"confidence"`

	// Tags are optional categorization tags for this mutation
	Tags []string `json:"tags,omitempty"`

	// Metadata allows plugins to attach arbitrary data to results
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// PluginConfig holds configuration options passed to plugins during initialization.
type PluginConfig struct {
	// PluginDir is the directory where plugins are located
	PluginDir string `json:"plugin_dir"`

	// DataDir is a directory where plugins can store persistent data
	DataDir string `json:"data_dir"`

	// LogLevel sets the verbosity of plugin logging
	LogLevel string `json:"log_level"`

	// Options contains plugin-specific configuration options
	Options map[string]interface{} `json:"options,omitempty"`
}

// PluginInfo contains metadata about a loaded plugin.
type PluginInfo struct {
	// Name is the plugin's unique identifier
	Name string `json:"name"`

	// Version is the semantic version
	Version string `json:"version"`

	// Description is a human-readable description
	Description string `json:"description"`

	// Author is the plugin author
	Author string `json:"author"`

	// Path is the file path to the plugin
	Path string `json:"path"`

	// Priority is the execution priority
	Priority int `json:"priority"`

	// SupportedAttackTypes lists supported attack types
	SupportedAttackTypes []types.AttackType `json:"supported_attack_types,omitempty"`

	// SupportedWAFTypes lists supported WAF types
	SupportedWAFTypes []types.WAFType `json:"supported_waf_types,omitempty"`

	// Loaded indicates whether the plugin is currently loaded
	Loaded bool `json:"loaded"`

	// Error contains any error message if the plugin failed to load
	Error string `json:"error,omitempty"`
}

// PluginSymbols defines the symbol names that must be exported by plugins.
const (
	// PluginSymbolNew is the symbol name for the plugin constructor function.
	// The function must have signature: func() MutationPlugin
	PluginSymbolNew = "NewPlugin"

	// PluginSymbolVersion is the symbol name for the version string.
	// This is optional but recommended for quick version checking without loading.
	PluginSymbolVersion = "PluginVersion"

	// PluginSymbolName is the symbol name for the name string.
	// This is optional but recommended for quick identification without loading.
	PluginSymbolName = "PluginName"
)

// BaseMutationPlugin provides a base implementation of MutationPlugin
// that plugin authors can embed to reduce boilerplate.
type BaseMutationPlugin struct {
	name                 string
	version              string
	description          string
	author               string
	priority             int
	supportedAttackTypes []types.AttackType
	supportedWAFTypes    []types.WAFType
	config               PluginConfig
}

// NewBaseMutationPlugin creates a new base plugin with the given metadata.
func NewBaseMutationPlugin(name, version, description, author string) *BaseMutationPlugin {
	return &BaseMutationPlugin{
		name:        name,
		version:     version,
		description: description,
		author:      author,
		priority:    100, // Default middle priority
	}
}

// Name returns the plugin name.
func (p *BaseMutationPlugin) Name() string { return p.name }

// Version returns the plugin version.
func (p *BaseMutationPlugin) Version() string { return p.version }

// Description returns the plugin description.
func (p *BaseMutationPlugin) Description() string { return p.description }

// Author returns the plugin author.
func (p *BaseMutationPlugin) Author() string { return p.author }

// Priority returns the plugin priority.
func (p *BaseMutationPlugin) Priority() int { return p.priority }

// SetPriority sets the plugin priority.
func (p *BaseMutationPlugin) SetPriority(priority int) { p.priority = priority }

// SupportedAttackTypes returns supported attack types.
func (p *BaseMutationPlugin) SupportedAttackTypes() []types.AttackType {
	return p.supportedAttackTypes
}

// SetSupportedAttackTypes sets the supported attack types.
func (p *BaseMutationPlugin) SetSupportedAttackTypes(types []types.AttackType) {
	p.supportedAttackTypes = types
}

// SupportedWAFTypes returns supported WAF types.
func (p *BaseMutationPlugin) SupportedWAFTypes() []types.WAFType {
	return p.supportedWAFTypes
}

// SetSupportedWAFTypes sets the supported WAF types.
func (p *BaseMutationPlugin) SetSupportedWAFTypes(types []types.WAFType) {
	p.supportedWAFTypes = types
}

// Initialize stores the config. Override this to add custom initialization.
func (p *BaseMutationPlugin) Initialize(config PluginConfig) error {
	p.config = config
	return nil
}

// Cleanup does nothing by default. Override to add cleanup logic.
func (p *BaseMutationPlugin) Cleanup() error {
	return nil
}

// Mutate must be overridden by actual plugins.
func (p *BaseMutationPlugin) Mutate(payload string, ctx MutationContext) []MutationResult {
	return nil
}

// Config returns the plugin configuration.
func (p *BaseMutationPlugin) Config() PluginConfig {
	return p.config
}

// SupportsAttackType checks if the plugin supports a given attack type.
func (p *BaseMutationPlugin) SupportsAttackType(attackType types.AttackType) bool {
	if len(p.supportedAttackTypes) == 0 {
		return true // Supports all if none specified
	}
	for _, t := range p.supportedAttackTypes {
		if t == attackType || t == types.AttackAll {
			return true
		}
	}
	return false
}

// SupportsWAFType checks if the plugin supports a given WAF type.
func (p *BaseMutationPlugin) SupportsWAFType(wafType types.WAFType) bool {
	if len(p.supportedWAFTypes) == 0 {
		return true // Supports all if none specified
	}
	for _, t := range p.supportedWAFTypes {
		if t == wafType || t == types.WAFUnknown {
			return true
		}
	}
	return false
}
