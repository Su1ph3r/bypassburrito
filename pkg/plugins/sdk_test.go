package plugins

import (
	"testing"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

func TestNewBaseMutationPlugin(t *testing.T) {
	plugin := NewBaseMutationPlugin("test-plugin", "1.0.0", "Test description", "Test Author")

	if plugin.Name() != "test-plugin" {
		t.Errorf("expected Name()=test-plugin, got %s", plugin.Name())
	}

	if plugin.Version() != "1.0.0" {
		t.Errorf("expected Version()=1.0.0, got %s", plugin.Version())
	}

	if plugin.Description() != "Test description" {
		t.Errorf("expected Description()=Test description, got %s", plugin.Description())
	}

	if plugin.Author() != "Test Author" {
		t.Errorf("expected Author()=Test Author, got %s", plugin.Author())
	}

	if plugin.Priority() != 100 {
		t.Errorf("expected default Priority()=100, got %d", plugin.Priority())
	}
}

func TestBaseMutationPlugin_SetPriority(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	plugin.SetPriority(50)

	if plugin.Priority() != 50 {
		t.Errorf("expected Priority()=50 after SetPriority, got %d", plugin.Priority())
	}
}

func TestBaseMutationPlugin_SupportedAttackTypes(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	t.Run("default supports all", func(t *testing.T) {
		types := plugin.SupportedAttackTypes()
		if types != nil && len(types) > 0 {
			t.Error("expected nil or empty slice for default supported attack types")
		}
	})

	t.Run("set specific types", func(t *testing.T) {
		plugin.SetSupportedAttackTypes([]types.AttackType{types.AttackSQLi, types.AttackXSS})

		supported := plugin.SupportedAttackTypes()
		if len(supported) != 2 {
			t.Errorf("expected 2 supported types, got %d", len(supported))
		}
	})
}

func TestBaseMutationPlugin_SupportedWAFTypes(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	t.Run("default supports all", func(t *testing.T) {
		wafTypes := plugin.SupportedWAFTypes()
		if wafTypes != nil && len(wafTypes) > 0 {
			t.Error("expected nil or empty slice for default supported WAF types")
		}
	})

	t.Run("set specific types", func(t *testing.T) {
		plugin.SetSupportedWAFTypes([]types.WAFType{types.WAFCloudflare, types.WAFModSecurity})

		supported := plugin.SupportedWAFTypes()
		if len(supported) != 2 {
			t.Errorf("expected 2 supported types, got %d", len(supported))
		}
	})
}

func TestBaseMutationPlugin_Initialize(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	config := PluginConfig{
		PluginDir: "/test/plugins",
		DataDir:   "/test/data",
		LogLevel:  "debug",
		Options:   map[string]interface{}{"key": "value"},
	}

	err := plugin.Initialize(config)
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
	}

	stored := plugin.Config()
	if stored.PluginDir != config.PluginDir {
		t.Error("config not stored correctly")
	}
}

func TestBaseMutationPlugin_Cleanup(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

func TestBaseMutationPlugin_Mutate(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	// Base implementation returns nil
	results := plugin.Mutate("test payload", MutationContext{})
	if results != nil {
		t.Error("expected nil from base Mutate implementation")
	}
}

func TestBaseMutationPlugin_SupportsAttackType(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	t.Run("supports all when none specified", func(t *testing.T) {
		if !plugin.SupportsAttackType(types.AttackSQLi) {
			t.Error("should support SQLi when no types specified")
		}
		if !plugin.SupportsAttackType(types.AttackXSS) {
			t.Error("should support XSS when no types specified")
		}
	})

	t.Run("supports only specified", func(t *testing.T) {
		plugin.SetSupportedAttackTypes([]types.AttackType{types.AttackSQLi})

		if !plugin.SupportsAttackType(types.AttackSQLi) {
			t.Error("should support SQLi")
		}
		if plugin.SupportsAttackType(types.AttackXSS) {
			t.Error("should not support XSS")
		}
	})

	t.Run("supports all when AttackAll specified", func(t *testing.T) {
		plugin.SetSupportedAttackTypes([]types.AttackType{types.AttackAll})

		if !plugin.SupportsAttackType(types.AttackSQLi) {
			t.Error("should support SQLi with AttackAll")
		}
		if !plugin.SupportsAttackType(types.AttackXSS) {
			t.Error("should support XSS with AttackAll")
		}
	})
}

func TestBaseMutationPlugin_SupportsWAFType(t *testing.T) {
	plugin := NewBaseMutationPlugin("test", "1.0.0", "", "")

	t.Run("supports all when none specified", func(t *testing.T) {
		if !plugin.SupportsWAFType(types.WAFCloudflare) {
			t.Error("should support Cloudflare when no types specified")
		}
	})

	t.Run("supports only specified", func(t *testing.T) {
		plugin.SetSupportedWAFTypes([]types.WAFType{types.WAFCloudflare})

		if !plugin.SupportsWAFType(types.WAFCloudflare) {
			t.Error("should support Cloudflare")
		}
		if plugin.SupportsWAFType(types.WAFModSecurity) {
			t.Error("should not support ModSecurity")
		}
	})

	t.Run("supports all when WAFUnknown specified", func(t *testing.T) {
		plugin.SetSupportedWAFTypes([]types.WAFType{types.WAFUnknown})

		if !plugin.SupportsWAFType(types.WAFCloudflare) {
			t.Error("should support Cloudflare with WAFUnknown")
		}
	})
}

func TestMutationContext(t *testing.T) {
	ctx := MutationContext{
		AttackType:          types.AttackSQLi,
		WAFType:             types.WAFCloudflare,
		Position:            types.PositionQuery,
		ContentType:         "application/json",
		PreviousTries:       []string{"encoding", "obfuscation"},
		BlockedPatterns:     []string{"SELECT", "UNION"},
		SuccessfulMutations: []string{"url_encode"},
		Iteration:           5,
		MaxIterations:       15,
		TargetURL:           "https://example.com/api",
		CustomData:          map[string]interface{}{"key": "value"},
	}

	if ctx.AttackType != types.AttackSQLi {
		t.Error("AttackType mismatch")
	}

	if ctx.WAFType != types.WAFCloudflare {
		t.Error("WAFType mismatch")
	}

	if len(ctx.PreviousTries) != 2 {
		t.Error("PreviousTries length mismatch")
	}
}

func TestMutationResult(t *testing.T) {
	result := MutationResult{
		Payload:     "<script>alert(1)</script>",
		Mutations:   []string{"html_entity_encode"},
		Description: "HTML entity encoded XSS payload",
		Confidence:  0.85,
		Tags:        []string{"xss", "encoded"},
		Metadata:    map[string]interface{}{"source": "test"},
	}

	if result.Payload == "" {
		t.Error("Payload should not be empty")
	}

	if result.Confidence < 0 || result.Confidence > 1 {
		t.Error("Confidence should be between 0 and 1")
	}

	if len(result.Mutations) != 1 {
		t.Error("Mutations length mismatch")
	}
}

func TestPluginInfo(t *testing.T) {
	info := PluginInfo{
		Name:                 "test-plugin",
		Version:              "2.0.0",
		Description:          "A test plugin",
		Author:               "Test Author",
		Path:                 "/path/to/plugin.so",
		Priority:             50,
		SupportedAttackTypes: []types.AttackType{types.AttackSQLi},
		SupportedWAFTypes:    []types.WAFType{types.WAFCloudflare},
		Loaded:               true,
		Error:                "",
	}

	if info.Name != "test-plugin" {
		t.Error("Name mismatch")
	}

	if !info.Loaded {
		t.Error("Loaded should be true")
	}
}

func TestPluginConfig(t *testing.T) {
	config := PluginConfig{
		PluginDir: "~/.bypassburrito/plugins",
		DataDir:   "~/.bypassburrito/plugin-data",
		LogLevel:  "info",
		Options: map[string]interface{}{
			"debug":      true,
			"maxRetries": 3,
		},
	}

	if config.PluginDir == "" {
		t.Error("PluginDir should not be empty")
	}

	if config.Options["debug"] != true {
		t.Error("Options debug should be true")
	}
}

func TestPluginSymbols(t *testing.T) {
	if PluginSymbolNew != "NewPlugin" {
		t.Errorf("expected PluginSymbolNew=NewPlugin, got %s", PluginSymbolNew)
	}

	if PluginSymbolVersion != "PluginVersion" {
		t.Errorf("expected PluginSymbolVersion=PluginVersion, got %s", PluginSymbolVersion)
	}

	if PluginSymbolName != "PluginName" {
		t.Errorf("expected PluginSymbolName=PluginName, got %s", PluginSymbolName)
	}
}
