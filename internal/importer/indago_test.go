package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseIndagoExport(t *testing.T) {
	export := IndagoExport{
		ExportSource: "indago",
		ScanID:       "scan-001",
		Target:       "https://example.com",
		TotalBlocked: 2,
		Targets: []IndagoBlockedTarget{
			{
				OriginalFindingID: "f1",
				Endpoint:          "https://example.com/api/users",
				Method:            "GET",
				Parameter:         "q",
				OriginalPayload:   "<script>alert(1)</script>",
				WAFResponseCode:   403,
				VulnerabilityType: "xss",
			},
			{
				OriginalFindingID: "f2",
				Endpoint:          "https://example.com/api/search",
				Method:            "POST",
				Parameter:         "id",
				OriginalPayload:   "' OR 1=1--",
				WAFResponseCode:   403,
				VulnerabilityType: "sqli",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "indago-export.json")
	data, _ := json.Marshal(export)
	os.WriteFile(path, data, 0644)

	parsed, err := ParseIndagoExport(path)
	if err != nil {
		t.Fatalf("ParseIndagoExport failed: %v", err)
	}

	if parsed.ExportSource != "indago" {
		t.Errorf("expected 'indago', got '%s'", parsed.ExportSource)
	}
	if len(parsed.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(parsed.Targets))
	}
	if parsed.Targets[0].Endpoint != "https://example.com/api/users" {
		t.Errorf("unexpected endpoint: %s", parsed.Targets[0].Endpoint)
	}
	if parsed.Targets[1].Parameter != "id" {
		t.Errorf("unexpected parameter: %s", parsed.Targets[1].Parameter)
	}
}

func TestParseIndagoExportInvalidSource(t *testing.T) {
	export := IndagoExport{
		ExportSource: "wrong",
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-export.json")
	data, _ := json.Marshal(export)
	os.WriteFile(path, data, 0644)

	_, err := ParseIndagoExport(path)
	if err == nil {
		t.Fatal("expected error for wrong export_source")
	}
}

func TestParseIndagoExportFileNotFound(t *testing.T) {
	_, err := ParseIndagoExport("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseIndagoExportInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := ParseIndagoExport(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestToTargetConfigs(t *testing.T) {
	export := &IndagoExport{
		Targets: []IndagoBlockedTarget{
			{
				Endpoint:  "https://example.com/api/users",
				Method:    "GET",
				Parameter: "q",
			},
			{
				Endpoint:  "https://example.com/api/search",
				Method:    "POST",
				Parameter: "id",
			},
		},
	}

	configs := ToTargetConfigs(export)
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}
	if configs[0].URL != "https://example.com/api/users" {
		t.Errorf("unexpected URL: %s", configs[0].URL)
	}
	if configs[0].Parameter != "q" {
		t.Errorf("unexpected parameter: %s", configs[0].Parameter)
	}
	if configs[0].Method != "GET" {
		t.Errorf("unexpected method: %s", configs[0].Method)
	}
	if configs[1].URL != "https://example.com/api/search" {
		t.Errorf("unexpected URL: %s", configs[1].URL)
	}
	if configs[1].Method != "POST" {
		t.Errorf("unexpected method: %s", configs[1].Method)
	}
}

func TestToTargetConfigsEmpty(t *testing.T) {
	export := &IndagoExport{
		Targets: []IndagoBlockedTarget{},
	}

	configs := ToTargetConfigs(export)
	if len(configs) != 0 {
		t.Errorf("expected 0 configs, got %d", len(configs))
	}
}

func TestToAttackTypes(t *testing.T) {
	export := &IndagoExport{
		Targets: []IndagoBlockedTarget{
			{VulnerabilityType: "xss"},
			{VulnerabilityType: "sqli"},
			{VulnerabilityType: "xss"}, // duplicate
		},
	}

	attackTypes := ToAttackTypes(export)
	if len(attackTypes) != 2 {
		t.Errorf("expected 2 unique attack types, got %d", len(attackTypes))
	}
}

func TestToAttackTypesEmpty(t *testing.T) {
	export := &IndagoExport{
		Targets: []IndagoBlockedTarget{
			{VulnerabilityType: ""},
		},
	}

	attackTypes := ToAttackTypes(export)
	if len(attackTypes) != 0 {
		t.Errorf("expected 0 attack types, got %d", len(attackTypes))
	}
}
