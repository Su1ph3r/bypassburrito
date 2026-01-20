package plugins

import (
	"testing"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// testPlugin implements MutationPlugin for testing
type testPlugin struct {
	*BaseMutationPlugin
	mutateFunc func(payload string, ctx MutationContext) []MutationResult
}

func newTestPlugin(name string, priority int) *testPlugin {
	base := NewBaseMutationPlugin(name, "1.0.0", "Test plugin", "Test Author")
	base.SetPriority(priority)
	return &testPlugin{
		BaseMutationPlugin: base,
	}
}

func (p *testPlugin) Mutate(payload string, ctx MutationContext) []MutationResult {
	if p.mutateFunc != nil {
		return p.mutateFunc(payload, ctx)
	}
	return []MutationResult{
		{
			Payload:     payload + "_mutated",
			Mutations:   []string{p.Name()},
			Description: "Test mutation",
			Confidence:  0.8,
		},
	}
}

// mockPluginLoader implements a minimal loader for testing
type mockPluginLoader struct {
	plugins map[string]MutationPlugin
}

func newMockPluginLoader() *mockPluginLoader {
	return &mockPluginLoader{
		plugins: make(map[string]MutationPlugin),
	}
}

func (l *mockPluginLoader) addPlugin(p MutationPlugin) {
	l.plugins[p.Name()] = p
}

func (l *mockPluginLoader) Get(name string) (MutationPlugin, bool) {
	p, ok := l.plugins[name]
	return p, ok
}

func (l *mockPluginLoader) GetAll() []MutationPlugin {
	result := make([]MutationPlugin, 0, len(l.plugins))
	for _, p := range l.plugins {
		result = append(result, p)
	}
	return result
}

func (l *mockPluginLoader) Count() int {
	return len(l.plugins)
}

func TestNewPluginRegistry(t *testing.T) {
	loader := NewPluginLoader("/tmp/plugins", "/tmp/data")
	registry := NewPluginRegistry(loader)

	if registry == nil {
		t.Fatal("NewPluginRegistry returned nil")
	}

	if registry.loader != loader {
		t.Error("loader not set correctly")
	}
}

func TestPluginRegistry_EnableDisable(t *testing.T) {
	loader := newMockPluginLoader()
	plugin := newTestPlugin("test-plugin", 100)
	loader.addPlugin(plugin)

	// Create a registry with the mock loader (we need to use a wrapper)
	realLoader := NewPluginLoader("/tmp/plugins", "/tmp/data")
	registry := NewPluginRegistry(realLoader)

	t.Run("enable plugin", func(t *testing.T) {
		err := registry.EnablePlugin("test-plugin")
		if err != nil {
			t.Errorf("EnablePlugin failed: %v", err)
		}

		if !registry.IsEnabled("test-plugin") {
			t.Error("plugin should be enabled")
		}
	})

	t.Run("disable plugin", func(t *testing.T) {
		registry.DisablePlugin("test-plugin")

		if registry.IsEnabled("test-plugin") {
			t.Error("plugin should be disabled")
		}
	})
}

func TestPluginRegistry_GetEnabledPlugins(t *testing.T) {
	loader := NewPluginLoader("/tmp/test-plugins", "/tmp/test-data")
	registry := NewPluginRegistry(loader)

	// No plugins loaded, so none enabled
	enabled := registry.GetEnabledPlugins()
	if len(enabled) != 0 {
		t.Errorf("expected 0 enabled plugins, got %d", len(enabled))
	}
}

func TestPluginRegistry_Stats(t *testing.T) {
	loader := NewPluginLoader("/tmp/test-plugins", "/tmp/test-data")
	registry := NewPluginRegistry(loader)

	stats := registry.Stats()

	if stats.TotalLoaded != 0 {
		t.Errorf("expected TotalLoaded=0, got %d", stats.TotalLoaded)
	}

	if stats.TotalEnabled != 0 {
		t.Errorf("expected TotalEnabled=0, got %d", stats.TotalEnabled)
	}
}

func TestPluginMutatorAdapter(t *testing.T) {
	plugin := newTestPlugin("adapter-test", 100)

	adapter := NewPluginMutatorAdapter(plugin, types.AttackSQLi, types.WAFCloudflare)

	t.Run("mutate returns results", func(t *testing.T) {
		results := adapter.Mutate("test payload")

		if len(results) == 0 {
			t.Error("expected at least one result")
		}

		if results[0].Payload != "test payload_mutated" {
			t.Errorf("unexpected payload: %s", results[0].Payload)
		}
	})

	t.Run("set tried mutations", func(t *testing.T) {
		adapter.SetTried("mutation1")
		adapter.SetTried("mutation2")

		tried := adapter.getTriedList()
		if len(tried) != 2 {
			t.Errorf("expected 2 tried mutations, got %d", len(tried))
		}
	})
}

func TestJoinStrings(t *testing.T) {
	testCases := []struct {
		input    []string
		sep      string
		expected string
	}{
		{[]string{}, ", ", ""},
		{[]string{"a"}, ", ", "a"},
		{[]string{"a", "b"}, ", ", "a, b"},
		{[]string{"a", "b", "c"}, "-", "a-b-c"},
	}

	for _, tc := range testCases {
		result := joinStrings(tc.input, tc.sep)
		if result != tc.expected {
			t.Errorf("joinStrings(%v, %q) = %q, expected %q", tc.input, tc.sep, result, tc.expected)
		}
	}
}

func TestPluginRegistry_Loader(t *testing.T) {
	loader := NewPluginLoader("/tmp/test-plugins", "/tmp/test-data")
	registry := NewPluginRegistry(loader)

	if registry.Loader() != loader {
		t.Error("Loader() should return the registered loader")
	}
}

func TestRegistryStats_Fields(t *testing.T) {
	stats := RegistryStats{
		TotalLoaded:  5,
		TotalEnabled: 3,
		ByAttackType: map[string]int{"sqli": 2, "xss": 1},
		ByWAFType:    map[string]int{"cloudflare": 1, "modsecurity": 2},
	}

	if stats.TotalLoaded != 5 {
		t.Error("TotalLoaded mismatch")
	}

	if stats.TotalEnabled != 3 {
		t.Error("TotalEnabled mismatch")
	}

	if stats.ByAttackType["sqli"] != 2 {
		t.Error("ByAttackType[sqli] mismatch")
	}

	if stats.ByWAFType["cloudflare"] != 1 {
		t.Error("ByWAFType[cloudflare] mismatch")
	}
}
