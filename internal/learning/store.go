package learning

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
	"gopkg.in/yaml.v3"
)

// Store manages persistence of learned bypass patterns
type Store struct {
	mu       sync.RWMutex
	patterns map[string]*types.LearnedPattern // Key: pattern ID
	index    *PatternIndex
	path     string
	autoSave bool
	dirty    bool
}

// PatternIndex provides efficient lookups
type PatternIndex struct {
	ByWAF       map[types.WAFType][]string        // WAF type -> pattern IDs
	ByAttack    map[types.AttackType][]string     // Attack type -> pattern IDs
	ByMutation  map[string][]string               // Mutation name -> pattern IDs
	BySuccess   map[float64][]string              // Success rate bucket -> pattern IDs
	Combined    map[string][]string               // "waf:attack" -> pattern IDs
}

// NewStore creates a new pattern store
func NewStore(path string, autoSave bool) *Store {
	return &Store{
		patterns: make(map[string]*types.LearnedPattern),
		index:    newPatternIndex(),
		path:     path,
		autoSave: autoSave,
		dirty:    false,
	}
}

func newPatternIndex() *PatternIndex {
	return &PatternIndex{
		ByWAF:      make(map[types.WAFType][]string),
		ByAttack:   make(map[types.AttackType][]string),
		ByMutation: make(map[string][]string),
		BySuccess:  make(map[float64][]string),
		Combined:   make(map[string][]string),
	}
}

// Load loads patterns from disk
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return nil
	}

	// Expand home directory
	path := expandPath(s.path)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's OK
		}
		return fmt.Errorf("failed to read patterns file: %w", err)
	}

	var patterns []*types.LearnedPattern

	// Try YAML first, then JSON
	if err := yaml.Unmarshal(data, &patterns); err != nil {
		if err := json.Unmarshal(data, &patterns); err != nil {
			return fmt.Errorf("failed to parse patterns file: %w", err)
		}
	}

	// Clear existing data
	s.patterns = make(map[string]*types.LearnedPattern)
	s.index = newPatternIndex()

	// Load patterns and rebuild index
	for _, p := range patterns {
		s.patterns[p.ID] = p
		s.indexPattern(p)
	}

	return nil
}

// Save persists patterns to disk
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.path == "" {
		return nil
	}

	path := expandPath(s.path)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Convert to slice
	patterns := make([]*types.LearnedPattern, 0, len(s.patterns))
	for _, p := range s.patterns {
		patterns = append(patterns, p)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(patterns)
	if err != nil {
		return fmt.Errorf("failed to marshal patterns: %w", err)
	}

	// Write atomically
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write patterns file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to save patterns file: %w", err)
	}

	s.dirty = false
	return nil
}

// Record records a bypass attempt result
func (s *Store) Record(attempt *types.BypassAttempt, wafType types.WAFType, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate pattern key
	key := generatePatternKey(attempt.Payload.Type, wafType, attempt.Mutations)

	pattern, exists := s.patterns[key]
	if !exists {
		pattern = &types.LearnedPattern{
			ID:          key,
			WAFType:     wafType,
			AttackType:  attempt.Payload.Type,
			Mutations:   attempt.Mutations,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			SuccessRate: 0,
			Stats: types.PatternUsageStats{
				TotalAttempts:      0,
				SuccessfulAttempts: 0,
			},
		}
		s.patterns[key] = pattern
		s.indexPattern(pattern)
	}

	// Update stats
	pattern.LastSeen = time.Now()
	pattern.Stats.TotalAttempts++
	if success {
		pattern.Stats.SuccessfulAttempts++
		if attempt.Response != nil {
			pattern.Stats.AvgResponseTime = (pattern.Stats.AvgResponseTime*float64(pattern.Stats.SuccessfulAttempts-1) +
				float64(attempt.Duration.Milliseconds())) / float64(pattern.Stats.SuccessfulAttempts)
		}
	}

	// Recalculate success rate
	pattern.SuccessRate = float64(pattern.Stats.SuccessfulAttempts) / float64(pattern.Stats.TotalAttempts)

	// Store example payload on success
	if success && pattern.ExamplePayload == "" {
		pattern.ExamplePayload = attempt.Payload.Value
	}

	s.dirty = true

	// Auto-save if enabled
	if s.autoSave && s.dirty {
		go s.Save()
	}
}

// GetPatterns returns patterns matching the criteria
func (s *Store) GetPatterns(wafType types.WAFType, attackType types.AttackType) []*types.LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", wafType, attackType)
	ids, ok := s.index.Combined[key]
	if !ok {
		return nil
	}

	patterns := make([]*types.LearnedPattern, 0, len(ids))
	for _, id := range ids {
		if p, exists := s.patterns[id]; exists {
			patterns = append(patterns, p)
		}
	}

	return patterns
}

// GetByWAF returns all patterns for a specific WAF
func (s *Store) GetByWAF(wafType types.WAFType) []*types.LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.index.ByWAF[wafType]
	patterns := make([]*types.LearnedPattern, 0, len(ids))
	for _, id := range ids {
		if p, exists := s.patterns[id]; exists {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// GetByAttack returns all patterns for a specific attack type
func (s *Store) GetByAttack(attackType types.AttackType) []*types.LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.index.ByAttack[attackType]
	patterns := make([]*types.LearnedPattern, 0, len(ids))
	for _, id := range ids {
		if p, exists := s.patterns[id]; exists {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// GetTopPatterns returns the top N patterns by success rate
func (s *Store) GetTopPatterns(n int) []*types.LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Collect all patterns
	patterns := make([]*types.LearnedPattern, 0, len(s.patterns))
	for _, p := range s.patterns {
		// Only include patterns with enough attempts
		if p.Stats.TotalAttempts >= 2 {
			patterns = append(patterns, p)
		}
	}

	// Sort by success rate (simple bubble sort for small lists)
	for i := 0; i < len(patterns)-1; i++ {
		for j := 0; j < len(patterns)-i-1; j++ {
			if patterns[j].SuccessRate < patterns[j+1].SuccessRate {
				patterns[j], patterns[j+1] = patterns[j+1], patterns[j]
			}
		}
	}

	if n > len(patterns) {
		n = len(patterns)
	}

	return patterns[:n]
}

// GetRecentPatterns returns recently successful patterns
func (s *Store) GetRecentPatterns(since time.Duration) []*types.LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	patterns := make([]*types.LearnedPattern, 0)

	for _, p := range s.patterns {
		if p.LastSeen.After(cutoff) && p.SuccessRate > 0 {
			patterns = append(patterns, p)
		}
	}

	return patterns
}

// GetSuggestedMutations returns mutations that worked well for similar contexts
func (s *Store) GetSuggestedMutations(wafType types.WAFType, attackType types.AttackType) []string {
	patterns := s.GetPatterns(wafType, attackType)

	// Count mutation success
	mutationSuccess := make(map[string]float64)
	mutationCount := make(map[string]int)

	for _, p := range patterns {
		for _, m := range p.Mutations {
			mutationSuccess[m] += p.SuccessRate
			mutationCount[m]++
		}
	}

	// Calculate average success per mutation
	type mutScore struct {
		name  string
		score float64
	}

	scores := make([]mutScore, 0, len(mutationSuccess))
	for m, total := range mutationSuccess {
		scores = append(scores, mutScore{
			name:  m,
			score: total / float64(mutationCount[m]),
		})
	}

	// Sort by score
	for i := 0; i < len(scores)-1; i++ {
		for j := 0; j < len(scores)-i-1; j++ {
			if scores[j].score < scores[j+1].score {
				scores[j], scores[j+1] = scores[j+1], scores[j]
			}
		}
	}

	// Extract top mutation names
	result := make([]string, 0, len(scores))
	for _, s := range scores {
		result = append(result, s.name)
	}

	return result
}

// Count returns the total number of patterns
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.patterns)
}

// Delete removes a pattern by ID
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, exists := s.patterns[id]; exists {
		s.removeFromIndex(p)
		delete(s.patterns, id)
		s.dirty = true
	}
}

// Prune removes patterns below minimum success rate or older than maxAge
func (s *Store) Prune(minSuccessRate float64, maxAge time.Duration, minUses int) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, p := range s.patterns {
		shouldRemove := false

		if minSuccessRate > 0 && p.SuccessRate < minSuccessRate && p.Stats.TotalAttempts >= 5 {
			shouldRemove = true
		}

		if maxAge > 0 && p.LastSeen.Before(cutoff) {
			shouldRemove = true
		}

		if minUses > 0 && p.Stats.TotalAttempts < minUses {
			shouldRemove = true
		}

		if shouldRemove {
			s.removeFromIndex(p)
			delete(s.patterns, id)
			removed++
		}
	}

	if removed > 0 {
		s.dirty = true
	}

	return removed
}

// Export exports patterns to a file
func (s *Store) Export(path string, wafFilter types.WAFType) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	patterns := make([]*types.LearnedPattern, 0, len(s.patterns))
	for _, p := range s.patterns {
		if wafFilter == "" || p.WAFType == wafFilter {
			// Create a copy without sensitive data if needed
			exported := *p
			patterns = append(patterns, &exported)
		}
	}

	data, err := yaml.Marshal(patterns)
	if err != nil {
		return fmt.Errorf("failed to marshal patterns: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Import imports patterns from a file
func (s *Store) Import(path string, merge bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	var patterns []*types.LearnedPattern
	if err := yaml.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("failed to parse import file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !merge {
		s.patterns = make(map[string]*types.LearnedPattern)
		s.index = newPatternIndex()
	}

	for _, p := range patterns {
		if existing, exists := s.patterns[p.ID]; exists && merge {
			// Merge stats
			existing.Stats.TotalAttempts += p.Stats.TotalAttempts
			existing.Stats.SuccessfulAttempts += p.Stats.SuccessfulAttempts
			existing.SuccessRate = float64(existing.Stats.SuccessfulAttempts) / float64(existing.Stats.TotalAttempts)
			if p.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = p.LastSeen
			}
		} else {
			s.patterns[p.ID] = p
			s.indexPattern(p)
		}
	}

	s.dirty = true
	return nil
}

// indexPattern adds a pattern to all indexes
func (s *Store) indexPattern(p *types.LearnedPattern) {
	s.index.ByWAF[p.WAFType] = append(s.index.ByWAF[p.WAFType], p.ID)
	s.index.ByAttack[p.AttackType] = append(s.index.ByAttack[p.AttackType], p.ID)

	for _, m := range p.Mutations {
		s.index.ByMutation[m] = append(s.index.ByMutation[m], p.ID)
	}

	key := fmt.Sprintf("%s:%s", p.WAFType, p.AttackType)
	s.index.Combined[key] = append(s.index.Combined[key], p.ID)
}

// removeFromIndex removes a pattern from all indexes
func (s *Store) removeFromIndex(p *types.LearnedPattern) {
	s.index.ByWAF[p.WAFType] = removeString(s.index.ByWAF[p.WAFType], p.ID)
	s.index.ByAttack[p.AttackType] = removeString(s.index.ByAttack[p.AttackType], p.ID)

	for _, m := range p.Mutations {
		s.index.ByMutation[m] = removeString(s.index.ByMutation[m], p.ID)
	}

	key := fmt.Sprintf("%s:%s", p.WAFType, p.AttackType)
	s.index.Combined[key] = removeString(s.index.Combined[key], p.ID)
}

// Helper functions

func generatePatternKey(attackType types.AttackType, wafType types.WAFType, mutations []string) string {
	// Create a unique key based on attack, waf, and mutations
	mutKey := ""
	for _, m := range mutations {
		mutKey += m + "|"
	}
	return fmt.Sprintf("%s:%s:%s", attackType, wafType, mutKey)
}

func removeString(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}
