package plugins

import (
	"sort"
	"strings"
	"sync"

	"github.com/su1ph3r/bypassburrito/internal/bypass/strategies"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// PluginRegistry manages plugins and integrates them with the bypass engine.
// It provides a unified interface for applying both built-in strategies
// and custom plugins.
type PluginRegistry struct {
	mu      sync.RWMutex
	loader  *PluginLoader
	enabled map[string]bool
}

// NewPluginRegistry creates a new plugin registry with the given loader.
func NewPluginRegistry(loader *PluginLoader) *PluginRegistry {
	return &PluginRegistry{
		loader:  loader,
		enabled: make(map[string]bool),
	}
}

// EnablePlugin enables a plugin by name.
func (r *PluginRegistry) EnablePlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled[name] = true
	return nil
}

// DisablePlugin disables a plugin by name.
func (r *PluginRegistry) DisablePlugin(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.enabled, name)
}

// EnableAll enables all loaded plugins.
func (r *PluginRegistry) EnableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, p := range r.loader.GetAll() {
		r.enabled[p.Name()] = true
	}
}

// IsEnabled checks if a plugin is enabled.
func (r *PluginRegistry) IsEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled[name]
}

// GetEnabledPlugins returns all enabled plugins sorted by priority.
func (r *PluginRegistry) GetEnabledPlugins() []MutationPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []MutationPlugin
	for _, p := range r.loader.GetAll() {
		if r.enabled[p.Name()] {
			result = append(result, p)
		}
	}

	// Sort by priority (lower first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority() < result[j].Priority()
	})

	return result
}

// GetApplicablePlugins returns plugins applicable to the given attack and WAF type.
func (r *PluginRegistry) GetApplicablePlugins(attackType types.AttackType, wafType types.WAFType) []MutationPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []MutationPlugin

	for _, p := range r.loader.GetAll() {
		if !r.enabled[p.Name()] {
			continue
		}

		// Check attack type support
		attackTypes := p.SupportedAttackTypes()
		if len(attackTypes) > 0 {
			supported := false
			for _, t := range attackTypes {
				if t == attackType || t == types.AttackAll {
					supported = true
					break
				}
			}
			if !supported {
				continue
			}
		}

		// Check WAF type support
		wafTypes := p.SupportedWAFTypes()
		if len(wafTypes) > 0 {
			supported := false
			for _, t := range wafTypes {
				if t == wafType || t == types.WAFUnknown {
					supported = true
					break
				}
			}
			if !supported {
				continue
			}
		}

		result = append(result, p)
	}

	// Sort by priority
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority() < result[j].Priority()
	})

	return result
}

// ApplyPlugins applies all applicable plugins to generate mutations.
func (r *PluginRegistry) ApplyPlugins(payload string, ctx MutationContext) []MutationResult {
	plugins := r.GetApplicablePlugins(ctx.AttackType, ctx.WAFType)

	var results []MutationResult
	seen := make(map[string]bool)

	for _, p := range plugins {
		mutations := p.Mutate(payload, ctx)
		for _, m := range mutations {
			// Deduplicate by payload
			if seen[m.Payload] {
				continue
			}
			seen[m.Payload] = true
			results = append(results, m)
		}
	}

	// Sort by confidence (higher first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}

// PluginMutatorAdapter adapts a MutationPlugin to the strategies.Mutator interface.
// This allows plugins to be used directly in the existing mutation chain.
type PluginMutatorAdapter struct {
	plugin     MutationPlugin
	attackType types.AttackType
	wafType    types.WAFType
	tried      map[string]bool
}

// NewPluginMutatorAdapter creates a new adapter for the given plugin.
func NewPluginMutatorAdapter(plugin MutationPlugin, attackType types.AttackType, wafType types.WAFType) *PluginMutatorAdapter {
	return &PluginMutatorAdapter{
		plugin:     plugin,
		attackType: attackType,
		wafType:    wafType,
		tried:      make(map[string]bool),
	}
}

// Mutate implements the strategies.Mutator interface.
func (a *PluginMutatorAdapter) Mutate(payload string) []strategies.MutationResult {
	ctx := MutationContext{
		AttackType:    a.attackType,
		WAFType:       a.wafType,
		PreviousTries: a.getTriedList(),
	}

	pluginResults := a.plugin.Mutate(payload, ctx)

	results := make([]strategies.MutationResult, 0, len(pluginResults))
	for _, r := range pluginResults {
		results = append(results, strategies.MutationResult{
			Payload:     r.Payload,
			Mutation:    a.plugin.Name() + ": " + joinStrings(r.Mutations, ", "),
			Description: r.Description,
		})
	}

	return results
}

// SetTried marks a mutation as tried.
func (a *PluginMutatorAdapter) SetTried(mutation string) {
	a.tried[mutation] = true
}

// getTriedList returns the list of tried mutations.
func (a *PluginMutatorAdapter) getTriedList() []string {
	list := make([]string, 0, len(a.tried))
	for m := range a.tried {
		list = append(list, m)
	}
	return list
}

// CreatePluginMutators creates mutator adapters for all enabled plugins.
func (r *PluginRegistry) CreatePluginMutators(attackType types.AttackType, wafType types.WAFType) []strategies.Mutator {
	plugins := r.GetApplicablePlugins(attackType, wafType)

	mutators := make([]strategies.Mutator, 0, len(plugins))
	for _, p := range plugins {
		mutators = append(mutators, NewPluginMutatorAdapter(p, attackType, wafType))
	}

	return mutators
}

// RegistryStats holds statistics about the plugin registry.
type RegistryStats struct {
	TotalLoaded  int `json:"total_loaded"`
	TotalEnabled int `json:"total_enabled"`
	ByAttackType map[string]int `json:"by_attack_type"`
	ByWAFType    map[string]int `json:"by_waf_type"`
}

// Stats returns statistics about the registry.
func (r *PluginRegistry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		TotalLoaded:  r.loader.Count(),
		TotalEnabled: len(r.enabled),
		ByAttackType: make(map[string]int),
		ByWAFType:    make(map[string]int),
	}

	for _, p := range r.loader.GetAll() {
		if !r.enabled[p.Name()] {
			continue
		}

		attackTypes := p.SupportedAttackTypes()
		if len(attackTypes) == 0 {
			stats.ByAttackType["all"]++
		} else {
			for _, t := range attackTypes {
				stats.ByAttackType[string(t)]++
			}
		}

		wafTypes := p.SupportedWAFTypes()
		if len(wafTypes) == 0 {
			stats.ByWAFType["all"]++
		} else {
			for _, t := range wafTypes {
				stats.ByWAFType[string(t)]++
			}
		}
	}

	return stats
}

// Loader returns the underlying plugin loader.
func (r *PluginRegistry) Loader() *PluginLoader {
	return r.loader
}

// Helper function
func joinStrings(strs []string, sep string) string {
	return strings.Join(strs, sep)
}
