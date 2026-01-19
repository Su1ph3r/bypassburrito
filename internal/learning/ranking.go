package learning

import (
	"sort"
	"time"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Ranker provides ranking and scoring for patterns
type Ranker struct {
	store *Store

	// Weights for scoring
	SuccessWeight   float64
	RecencyWeight   float64
	ConsistencyWeight float64
	UsageWeight     float64
}

// NewRanker creates a new pattern ranker
func NewRanker(store *Store) *Ranker {
	return &Ranker{
		store:            store,
		SuccessWeight:    0.5,
		RecencyWeight:    0.2,
		ConsistencyWeight: 0.2,
		UsageWeight:      0.1,
	}
}

// RankedPattern wraps a pattern with ranking info
type RankedPattern struct {
	Pattern       *types.LearnedPattern
	Score         float64
	SuccessScore  float64
	RecencyScore  float64
	ConsistencyScore float64
	UsageScore    float64
}

// Rank scores and ranks patterns for a given context
func (r *Ranker) Rank(wafType types.WAFType, attackType types.AttackType) []RankedPattern {
	patterns := r.store.GetPatterns(wafType, attackType)
	return r.rankPatterns(patterns)
}

// RankAll ranks all patterns in the store
func (r *Ranker) RankAll() []RankedPattern {
	var allPatterns []*types.LearnedPattern
	for _, attackType := range r.getAllAttackTypes() {
		patterns := r.store.GetByAttack(attackType)
		allPatterns = append(allPatterns, patterns...)
	}
	return r.rankPatterns(allPatterns)
}

// RankByWAF ranks patterns for a specific WAF
func (r *Ranker) RankByWAF(wafType types.WAFType) []RankedPattern {
	patterns := r.store.GetByWAF(wafType)
	return r.rankPatterns(patterns)
}

func (r *Ranker) rankPatterns(patterns []*types.LearnedPattern) []RankedPattern {
	if len(patterns) == 0 {
		return nil
	}

	// Calculate scores for each pattern
	ranked := make([]RankedPattern, 0, len(patterns))
	for _, p := range patterns {
		rp := r.scorePattern(p)
		ranked = append(ranked, rp)
	}

	// Sort by score descending
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].Score > ranked[j].Score
	})

	return ranked
}

func (r *Ranker) scorePattern(p *types.LearnedPattern) RankedPattern {
	rp := RankedPattern{Pattern: p}

	// Success score: direct success rate
	rp.SuccessScore = p.SuccessRate

	// Recency score: how recently was this pattern used successfully
	daysSinceUse := time.Since(p.LastSeen).Hours() / 24
	if daysSinceUse < 1 {
		rp.RecencyScore = 1.0
	} else if daysSinceUse < 7 {
		rp.RecencyScore = 0.8
	} else if daysSinceUse < 30 {
		rp.RecencyScore = 0.5
	} else if daysSinceUse < 90 {
		rp.RecencyScore = 0.3
	} else {
		rp.RecencyScore = 0.1
	}

	// Consistency score: how consistent is the success rate
	// Based on sample size and variance
	if p.Stats.TotalAttempts >= 10 {
		rp.ConsistencyScore = 1.0
	} else if p.Stats.TotalAttempts >= 5 {
		rp.ConsistencyScore = 0.7
	} else if p.Stats.TotalAttempts >= 2 {
		rp.ConsistencyScore = 0.4
	} else {
		rp.ConsistencyScore = 0.1
	}

	// Usage score: prefer patterns that have been tested more
	if p.Stats.TotalAttempts >= 20 {
		rp.UsageScore = 1.0
	} else if p.Stats.TotalAttempts >= 10 {
		rp.UsageScore = 0.7
	} else if p.Stats.TotalAttempts >= 5 {
		rp.UsageScore = 0.5
	} else {
		rp.UsageScore = float64(p.Stats.TotalAttempts) / 5.0
	}

	// Calculate weighted score
	rp.Score = rp.SuccessScore*r.SuccessWeight +
		rp.RecencyScore*r.RecencyWeight +
		rp.ConsistencyScore*r.ConsistencyWeight +
		rp.UsageScore*r.UsageWeight

	return rp
}

// GetBestMutations returns the best mutation combinations for a context
func (r *Ranker) GetBestMutations(wafType types.WAFType, attackType types.AttackType, n int) [][]string {
	ranked := r.Rank(wafType, attackType)

	result := make([][]string, 0, n)
	seen := make(map[string]bool)

	for _, rp := range ranked {
		// Create key from mutations
		key := mutationsKey(rp.Pattern.Mutations)
		if seen[key] {
			continue
		}
		seen[key] = true

		result = append(result, rp.Pattern.Mutations)
		if len(result) >= n {
			break
		}
	}

	return result
}

// SuggestNextMutation suggests the next mutation to try based on partial chain
func (r *Ranker) SuggestNextMutation(wafType types.WAFType, attackType types.AttackType, currentChain []string) string {
	patterns := r.store.GetPatterns(wafType, attackType)

	// Score each possible next mutation
	scores := make(map[string]float64)
	counts := make(map[string]int)

	for _, p := range patterns {
		if len(p.Mutations) <= len(currentChain) {
			continue
		}

		// Check if this pattern starts with our current chain
		matches := true
		for i, m := range currentChain {
			if i >= len(p.Mutations) || p.Mutations[i] != m {
				matches = false
				break
			}
		}

		if matches && len(p.Mutations) > len(currentChain) {
			nextMut := p.Mutations[len(currentChain)]
			scores[nextMut] += p.SuccessRate
			counts[nextMut]++
		}
	}

	// Find best next mutation
	bestMut := ""
	bestScore := 0.0

	for m, total := range scores {
		avg := total / float64(counts[m])
		if avg > bestScore {
			bestScore = avg
			bestMut = m
		}
	}

	return bestMut
}

// ComparePatterns compares two patterns and returns which is better
func (r *Ranker) ComparePatterns(p1, p2 *types.LearnedPattern) int {
	s1 := r.scorePattern(p1)
	s2 := r.scorePattern(p2)

	if s1.Score > s2.Score {
		return 1
	} else if s1.Score < s2.Score {
		return -1
	}
	return 0
}

// GetRecommendations returns recommendations for a bypass attempt
type Recommendation struct {
	Mutations   []string
	Confidence  float64
	Reasoning   string
	SampleCount int
}

func (r *Ranker) GetRecommendations(wafType types.WAFType, attackType types.AttackType, n int) []Recommendation {
	ranked := r.Rank(wafType, attackType)

	recs := make([]Recommendation, 0, n)
	for i := 0; i < n && i < len(ranked); i++ {
		rp := ranked[i]
		rec := Recommendation{
			Mutations:   rp.Pattern.Mutations,
			Confidence:  rp.Score,
			SampleCount: rp.Pattern.Stats.TotalAttempts,
		}

		// Generate reasoning
		if rp.SuccessScore > 0.7 {
			rec.Reasoning = "High success rate historically"
		} else if rp.RecencyScore > 0.7 {
			rec.Reasoning = "Recently successful"
		} else if rp.ConsistencyScore > 0.7 {
			rec.Reasoning = "Consistent results across attempts"
		} else {
			rec.Reasoning = "Based on historical patterns"
		}

		recs = append(recs, rec)
	}

	return recs
}

func (r *Ranker) getAllAttackTypes() []types.AttackType {
	return []types.AttackType{
		types.AttackXSS,
		types.AttackSQLi,
		types.AttackCmdInjection,
		types.AttackPathTraversal,
		types.AttackSSTI,
		types.AttackXXE,
	}
}

func mutationsKey(mutations []string) string {
	key := ""
	for _, m := range mutations {
		key += m + "|"
	}
	return key
}
