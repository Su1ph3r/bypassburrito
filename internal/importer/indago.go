package importer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// IndagoExport represents the WAF-blocked export from Indago
type IndagoExport struct {
	ExportSource string                `json:"export_source"`
	ScanID       string                `json:"scan_id"`
	Target       string                `json:"target"`
	TotalBlocked int                   `json:"total_blocked"`
	Targets      []IndagoBlockedTarget `json:"targets"`
}

// IndagoBlockedTarget represents a single WAF-blocked target from Indago
type IndagoBlockedTarget struct {
	OriginalFindingID string `json:"original_finding_id"`
	Endpoint          string `json:"endpoint"`
	Method            string `json:"method"`
	Parameter         string `json:"parameter"`
	OriginalPayload   string `json:"original_payload"`
	WAFResponseCode   int    `json:"waf_response_code"`
	VulnerabilityType string `json:"vulnerability_type"`
}

// ParseIndagoExport parses an Indago WAF-blocked export file
func ParseIndagoExport(path string) (*IndagoExport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Indago export: %w", err)
	}

	var export IndagoExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("failed to parse Indago export: %w", err)
	}

	if export.ExportSource != "indago" {
		return nil, fmt.Errorf("expected export_source 'indago', got '%s'", export.ExportSource)
	}

	return &export, nil
}

// ToTargetConfigs converts Indago blocked targets to BypassBurrito TargetConfigs
func ToTargetConfigs(export *IndagoExport) []types.TargetConfig {
	var configs []types.TargetConfig

	for _, t := range export.Targets {
		config := types.TargetConfig{
			URL:       t.Endpoint,
			Method:    t.Method,
			Parameter: t.Parameter,
			Position:  types.PositionQuery,
		}
		configs = append(configs, config)
	}

	return configs
}

// ToAttackTypes extracts unique attack types from Indago export
func ToAttackTypes(export *IndagoExport) []types.AttackType {
	seen := make(map[string]bool)
	var attackTypes []types.AttackType

	for _, t := range export.Targets {
		if t.VulnerabilityType != "" && !seen[t.VulnerabilityType] {
			seen[t.VulnerabilityType] = true
			attackTypes = append(attackTypes, types.AttackType(t.VulnerabilityType))
		}
	}

	return attackTypes
}
