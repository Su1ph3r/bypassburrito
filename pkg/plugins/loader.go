package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// PluginLoader handles loading and managing mutation plugins.
type PluginLoader struct {
	mu        sync.RWMutex
	pluginDir string
	dataDir   string
	plugins   map[string]*loadedPlugin
	config    PluginConfig
}

// loadedPlugin holds a loaded plugin and its handle.
type loadedPlugin struct {
	info   PluginInfo
	plugin MutationPlugin
	handle *plugin.Plugin
}

// PluginMetadata represents the metadata YAML file for a plugin.
type PluginMetadata struct {
	Name        string                 `yaml:"name"`
	Version     string                 `yaml:"version"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	Priority    int                    `yaml:"priority"`
	Options     map[string]interface{} `yaml:"options,omitempty"`
}

// NewPluginLoader creates a new plugin loader.
func NewPluginLoader(pluginDir, dataDir string) *PluginLoader {
	return &PluginLoader{
		pluginDir: pluginDir,
		dataDir:   dataDir,
		plugins:   make(map[string]*loadedPlugin),
		config: PluginConfig{
			PluginDir: pluginDir,
			DataDir:   dataDir,
			LogLevel:  "info",
		},
	}
}

// SetConfig sets the plugin configuration.
func (l *PluginLoader) SetConfig(config PluginConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = config
}

// LoadAll discovers and loads all plugins in the plugin directory.
func (l *PluginLoader) LoadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create plugin directory if it doesn't exist
	if err := os.MkdirAll(l.pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	// Find all .so files
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	var loadErrors []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".so") {
			continue
		}

		path := filepath.Join(l.pluginDir, name)
		if err := l.loadPluginLocked(path); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("some plugins failed to load:\n  %s", strings.Join(loadErrors, "\n  "))
	}

	return nil
}

// Load loads a single plugin from the given path.
func (l *PluginLoader) Load(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadPluginLocked(path)
}

// loadPluginLocked loads a plugin while holding the lock.
func (l *PluginLoader) loadPluginLocked(path string) error {
	// Check if already loaded
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Load the plugin shared object
	p, err := plugin.Open(absPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look up the NewPlugin function
	newPluginSym, err := p.Lookup(PluginSymbolNew)
	if err != nil {
		return fmt.Errorf("plugin missing %s symbol: %w", PluginSymbolNew, err)
	}

	// Assert the function signature
	newPluginFunc, ok := newPluginSym.(func() MutationPlugin)
	if !ok {
		return fmt.Errorf("invalid %s signature, expected func() MutationPlugin", PluginSymbolNew)
	}

	// Create the plugin instance
	mutPlugin := newPluginFunc()
	if mutPlugin == nil {
		return fmt.Errorf("plugin constructor returned nil")
	}

	// Load metadata from YAML if available
	metadata := l.loadMetadata(path)

	// Apply metadata overrides
	config := l.config
	if metadata != nil && metadata.Options != nil {
		config.Options = metadata.Options
	}

	// Initialize the plugin
	if err := mutPlugin.Initialize(config); err != nil {
		return fmt.Errorf("plugin initialization failed: %w", err)
	}

	// Build plugin info
	info := PluginInfo{
		Name:                 mutPlugin.Name(),
		Version:              mutPlugin.Version(),
		Description:          mutPlugin.Description(),
		Author:               mutPlugin.Author(),
		Path:                 absPath,
		Priority:             mutPlugin.Priority(),
		SupportedAttackTypes: mutPlugin.SupportedAttackTypes(),
		SupportedWAFTypes:    mutPlugin.SupportedWAFTypes(),
		Loaded:               true,
	}

	// Store the loaded plugin
	l.plugins[info.Name] = &loadedPlugin{
		info:   info,
		plugin: mutPlugin,
		handle: p,
	}

	return nil
}

// loadMetadata loads the metadata YAML file for a plugin.
func (l *PluginLoader) loadMetadata(pluginPath string) *PluginMetadata {
	// Look for .yaml or .yml file with same base name
	baseName := strings.TrimSuffix(pluginPath, filepath.Ext(pluginPath))
	for _, ext := range []string{".yaml", ".yml"} {
		metaPath := baseName + ext
		if data, err := os.ReadFile(metaPath); err == nil {
			var metadata PluginMetadata
			if err := yaml.Unmarshal(data, &metadata); err == nil {
				return &metadata
			}
		}
	}
	return nil
}

// Unload unloads a plugin by name.
func (l *PluginLoader) Unload(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	lp, ok := l.plugins[name]
	if !ok {
		return fmt.Errorf("plugin not loaded: %s", name)
	}

	// Call cleanup
	if err := lp.plugin.Cleanup(); err != nil {
		return fmt.Errorf("plugin cleanup failed: %w", err)
	}

	// Remove from map
	delete(l.plugins, name)

	return nil
}

// UnloadAll unloads all plugins.
func (l *PluginLoader) UnloadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []string
	for name, lp := range l.plugins {
		if err := lp.plugin.Cleanup(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}

	l.plugins = make(map[string]*loadedPlugin)

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors:\n  %s", strings.Join(errs, "\n  "))
	}

	return nil
}

// Get returns a plugin by name.
func (l *PluginLoader) Get(name string) (MutationPlugin, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	lp, ok := l.plugins[name]
	if !ok {
		return nil, false
	}
	return lp.plugin, true
}

// GetAll returns all loaded plugins.
func (l *PluginLoader) GetAll() []MutationPlugin {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]MutationPlugin, 0, len(l.plugins))
	for _, lp := range l.plugins {
		result = append(result, lp.plugin)
	}
	return result
}

// List returns information about all loaded plugins.
func (l *PluginLoader) List() []PluginInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]PluginInfo, 0, len(l.plugins))
	for _, lp := range l.plugins {
		result = append(result, lp.info)
	}
	return result
}

// Discover returns information about all discoverable plugins (loaded and unloaded).
func (l *PluginLoader) Discover() []PluginInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []PluginInfo

	// Add loaded plugins
	for _, lp := range l.plugins {
		result = append(result, lp.info)
	}

	// Discover unloaded plugins
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		return result
	}

	loadedPaths := make(map[string]bool)
	for _, lp := range l.plugins {
		loadedPaths[lp.info.Path] = true
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}

		path := filepath.Join(l.pluginDir, entry.Name())
		absPath, _ := filepath.Abs(path)

		if loadedPaths[absPath] {
			continue
		}

		// Create info for unloaded plugin
		info := PluginInfo{
			Name:   strings.TrimSuffix(entry.Name(), ".so"),
			Path:   absPath,
			Loaded: false,
		}

		// Try to load metadata
		if meta := l.loadMetadata(path); meta != nil {
			info.Name = meta.Name
			info.Version = meta.Version
			info.Description = meta.Description
			info.Author = meta.Author
			info.Priority = meta.Priority
		}

		result = append(result, info)
	}

	return result
}

// PluginDir returns the plugin directory path.
func (l *PluginLoader) PluginDir() string {
	return l.pluginDir
}

// Count returns the number of loaded plugins.
func (l *PluginLoader) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.plugins)
}
