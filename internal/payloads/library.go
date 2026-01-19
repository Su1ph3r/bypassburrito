package payloads

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/*.yaml
var embeddedPayloads embed.FS

// PayloadLibrary manages base payloads for different attack types
type PayloadLibrary struct {
	payloads   map[types.AttackType][]types.Payload
	categories map[types.AttackType]map[string][]types.Payload // Type -> Category -> Payloads
}

// PayloadFile represents a YAML payload file structure
type PayloadFile struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	AttackType  string           `yaml:"attack_type"`
	Category    string           `yaml:"category"`
	Payloads    []PayloadEntry   `yaml:"payloads"`
}

// PayloadEntry represents a single payload in the file
type PayloadEntry struct {
	Value       string   `yaml:"value"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Severity    string   `yaml:"severity,omitempty"`
	Context     string   `yaml:"context,omitempty"` // Where this payload works best
}

// NewPayloadLibrary creates a new payload library
func NewPayloadLibrary() *PayloadLibrary {
	return &PayloadLibrary{
		payloads:   make(map[types.AttackType][]types.Payload),
		categories: make(map[types.AttackType]map[string][]types.Payload),
	}
}

// LoadEmbedded loads embedded payloads
func (l *PayloadLibrary) LoadEmbedded() error {
	return fs.WalkDir(embeddedPayloads, "embedded", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := embeddedPayloads.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read embedded payload %s: %w", path, err)
		}

		return l.parsePayloadFile(data)
	})
}

// LoadFromDirectory loads payloads from a directory
func (l *PayloadLibrary) LoadFromDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := fs.ReadFile(nil, path)
		if err != nil {
			return fmt.Errorf("failed to read payload file %s: %w", path, err)
		}

		return l.parsePayloadFile(data)
	})
}

// LoadFromFile loads payloads from a single file
func (l *PayloadLibrary) LoadFromFile(data []byte) error {
	return l.parsePayloadFile(data)
}

// parsePayloadFile parses a YAML payload file
func (l *PayloadLibrary) parsePayloadFile(data []byte) error {
	var file PayloadFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("failed to parse payload file: %w", err)
	}

	attackType := types.AttackType(file.AttackType)

	// Initialize category map if needed
	if l.categories[attackType] == nil {
		l.categories[attackType] = make(map[string][]types.Payload)
	}

	for _, entry := range file.Payloads {
		payload := types.Payload{
			Value:       entry.Value,
			Type:        attackType,
			Description: entry.Description,
			Tags:        entry.Tags,
		}

		l.payloads[attackType] = append(l.payloads[attackType], payload)

		if file.Category != "" {
			l.categories[attackType][file.Category] = append(
				l.categories[attackType][file.Category],
				payload,
			)
		}
	}

	return nil
}

// GetPayloads returns all payloads for an attack type
func (l *PayloadLibrary) GetPayloads(attackType types.AttackType) []types.Payload {
	return l.payloads[attackType]
}

// GetPayloadsByCategory returns payloads for a specific category
func (l *PayloadLibrary) GetPayloadsByCategory(attackType types.AttackType, category string) []types.Payload {
	if cats, ok := l.categories[attackType]; ok {
		return cats[category]
	}
	return nil
}

// GetCategories returns all categories for an attack type
func (l *PayloadLibrary) GetCategories(attackType types.AttackType) []string {
	cats := make([]string, 0)
	if catMap, ok := l.categories[attackType]; ok {
		for cat := range catMap {
			cats = append(cats, cat)
		}
	}
	return cats
}

// GetAllTypes returns all attack types with payloads
func (l *PayloadLibrary) GetAllTypes() []types.AttackType {
	types := make([]types.AttackType, 0, len(l.payloads))
	for t := range l.payloads {
		types = append(types, t)
	}
	return types
}

// Count returns the total number of payloads
func (l *PayloadLibrary) Count() int {
	total := 0
	for _, payloads := range l.payloads {
		total += len(payloads)
	}
	return total
}

// CountByType returns the count for a specific type
func (l *PayloadLibrary) CountByType(attackType types.AttackType) int {
	return len(l.payloads[attackType])
}

// Filter returns payloads matching the filter function
func (l *PayloadLibrary) Filter(attackType types.AttackType, filter func(types.Payload) bool) []types.Payload {
	var result []types.Payload
	for _, p := range l.payloads[attackType] {
		if filter(p) {
			result = append(result, p)
		}
	}
	return result
}

// GetByTags returns payloads with specific tags
func (l *PayloadLibrary) GetByTags(attackType types.AttackType, tags ...string) []types.Payload {
	return l.Filter(attackType, func(p types.Payload) bool {
		for _, tag := range tags {
			for _, pTag := range p.Tags {
				if pTag == tag {
					return true
				}
			}
		}
		return false
	})
}

// AddPayload adds a custom payload
func (l *PayloadLibrary) AddPayload(payload types.Payload) {
	l.payloads[payload.Type] = append(l.payloads[payload.Type], payload)
}

// AddPayloads adds multiple custom payloads
func (l *PayloadLibrary) AddPayloads(payloads []types.Payload) {
	for _, p := range payloads {
		l.AddPayload(p)
	}
}
