package waf

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/su1ph3r/bypassburrito/pkg/types"
	"gopkg.in/yaml.v3"
)

//go:embed embedded_signatures.yaml
var embeddedSignatures []byte

// SignatureDatabase holds all WAF signatures
type SignatureDatabase struct {
	Version     string                          `yaml:"version"`
	LastUpdated string                          `yaml:"last_updated"`
	Signatures  map[string]types.WAFSignature   `yaml:"signatures"`
}

// LoadSignatures loads signatures from a YAML file
func LoadSignatures(path string) (*SignatureDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signatures file: %w", err)
	}

	return parseSignatures(data)
}

// LoadEmbeddedSignatures loads the embedded signatures
func LoadEmbeddedSignatures() (*SignatureDatabase, error) {
	if len(embeddedSignatures) == 0 {
		// If embedded signatures are not available, return defaults
		return DefaultSignatures(), nil
	}
	return parseSignatures(embeddedSignatures)
}

// parseSignatures parses signature YAML data
func parseSignatures(data []byte) (*SignatureDatabase, error) {
	var db SignatureDatabase
	if err := yaml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse signatures: %w", err)
	}
	return &db, nil
}

// DefaultSignatures returns built-in default signatures
func DefaultSignatures() *SignatureDatabase {
	return &SignatureDatabase{
		Version:     "1.0",
		LastUpdated: "2025-01-19",
		Signatures: map[string]types.WAFSignature{
			"cloudflare": {
				WAFType: types.WAFCloudflare,
				Name:    "Cloudflare WAF",
				Vendor:  "Cloudflare Inc.",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)cf-ray", Weight: 0.4},
						{Pattern: "(?i)server:\\s*cloudflare", Weight: 0.5},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)cloudflare", Weight: 0.3},
						{Pattern: "(?i)ray id:", Weight: 0.4},
					},
					StatusCodes: []int{403, 503},
				},
				BlockIndicators: []string{"Ray ID", "Error 1020"},
				KnownBypasses:   []string{"Unicode normalization", "Double URL encoding"},
			},
			"modsecurity": {
				WAFType: types.WAFModSecurity,
				Name:    "ModSecurity",
				Vendor:  "Trustwave SpiderLabs",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)mod_security", Weight: 0.5},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)mod_security", Weight: 0.5},
						{Pattern: "(?i)not acceptable", Weight: 0.3},
					},
					StatusCodes: []int{403, 406},
				},
				BlockIndicators: []string{"ModSecurity", "Access denied"},
				KnownBypasses:   []string{"Comment injection", "Case variation"},
			},
			"aws_waf": {
				WAFType: types.WAFAWSWaf,
				Name:    "AWS WAF",
				Vendor:  "Amazon Web Services",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)x-amzn-requestid", Weight: 0.3},
						{Pattern: "(?i)x-amz-cf-id", Weight: 0.3},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)aws waf", Weight: 0.5},
						{Pattern: "(?i)request blocked", Weight: 0.4},
					},
					StatusCodes: []int{403},
				},
				BlockIndicators: []string{"Request blocked", "AWS WAF"},
				KnownBypasses:   []string{"Unicode encoding", "Parameter pollution"},
			},
			"akamai": {
				WAFType: types.WAFAkamai,
				Name:    "Akamai Kona Site Defender",
				Vendor:  "Akamai Technologies",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)akamai", Weight: 0.5},
						{Pattern: "(?i)x-akamai-", Weight: 0.4},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)reference #", Weight: 0.4},
					},
					StatusCodes: []int{403},
				},
				BlockIndicators: []string{"Reference #", "Access Denied"},
				KnownBypasses:   []string{"URL encoding variations"},
			},
			"imperva": {
				WAFType: types.WAFImperva,
				Name:    "Imperva SecureSphere",
				Vendor:  "Imperva",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)x-iinfo", Weight: 0.5},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)incapsula", Weight: 0.5},
						{Pattern: "(?i)incident id", Weight: 0.4},
					},
					Cookies: []types.PatternWeight{
						{Pattern: "incap_ses_", Weight: 0.5},
						{Pattern: "visid_incap_", Weight: 0.5},
					},
					StatusCodes: []int{403},
				},
				BlockIndicators: []string{"Incapsula", "Incident ID"},
				KnownBypasses:   []string{"Unicode normalization", "Double encoding"},
			},
			"f5_bigip": {
				WAFType: types.WAFBIGIP,
				Name:    "F5 BIG-IP ASM",
				Vendor:  "F5 Networks",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)bigip", Weight: 0.5},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)support id", Weight: 0.5},
						{Pattern: "(?i)request rejected", Weight: 0.4},
					},
					Cookies: []types.PatternWeight{
						{Pattern: "BIGipServer", Weight: 0.5},
					},
					StatusCodes: []int{403, 501},
				},
				BlockIndicators: []string{"Request Rejected", "Support ID"},
				KnownBypasses:   []string{"Comment insertion", "Case manipulation"},
			},
			"sucuri": {
				WAFType: types.WAFSucuri,
				Name:    "Sucuri WAF",
				Vendor:  "Sucuri/GoDaddy",
				Detection: types.DetectionSignatures{
					Headers: []types.PatternWeight{
						{Pattern: "(?i)x-sucuri-", Weight: 0.5},
					},
					Body: []types.PatternWeight{
						{Pattern: "(?i)sucuri", Weight: 0.4},
						{Pattern: "(?i)cloudproxy", Weight: 0.4},
					},
					StatusCodes: []int{403},
				},
				BlockIndicators: []string{"Sucuri", "CloudProxy"},
				KnownBypasses:   []string{"URL encoding", "Unicode characters"},
			},
			"wordfence": {
				WAFType: types.WAFWordfence,
				Name:    "Wordfence",
				Vendor:  "Defiant Inc.",
				Detection: types.DetectionSignatures{
					Body: []types.PatternWeight{
						{Pattern: "(?i)wordfence", Weight: 0.5},
						{Pattern: "(?i)generated by wordfence", Weight: 0.6},
					},
					StatusCodes: []int{403, 503},
				},
				BlockIndicators: []string{"Wordfence", "Generated by Wordfence"},
				KnownBypasses:   []string{"IP rotation", "Header manipulation"},
			},
		},
	}
}

// GetSignature returns a specific WAF signature
func (db *SignatureDatabase) GetSignature(wafType string) (*types.WAFSignature, bool) {
	sig, ok := db.Signatures[wafType]
	return &sig, ok
}

// GetAllWAFTypes returns all known WAF types
func (db *SignatureDatabase) GetAllWAFTypes() []string {
	types := make([]string, 0, len(db.Signatures))
	for t := range db.Signatures {
		types = append(types, t)
	}
	return types
}

// MergeSignatures merges another signature database into this one
func (db *SignatureDatabase) MergeSignatures(other *SignatureDatabase) {
	for k, v := range other.Signatures {
		db.Signatures[k] = v
	}
}
