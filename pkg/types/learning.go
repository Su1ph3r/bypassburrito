package types

import "time"

// LearnedPattern represents a successful bypass pattern
type LearnedPattern struct {
	ID              string            `json:"id" yaml:"id"`
	WAFType         WAFType           `json:"waf_type" yaml:"waf_type"`
	AttackType      AttackType        `json:"attack_type" yaml:"attack_type"`
	OriginalPayload string            `json:"original_payload" yaml:"original_payload"`
	BypassPayload   string            `json:"bypass_payload" yaml:"bypass_payload"`
	ExamplePayload  string            `json:"example_payload,omitempty" yaml:"example_payload,omitempty"`
	Mutations       []string          `json:"mutations" yaml:"mutations"`
	MutationChain   string            `json:"mutation_chain,omitempty" yaml:"mutation_chain,omitempty"`
	SuccessCount    int               `json:"success_count" yaml:"success_count"`
	FailureCount    int               `json:"failure_count" yaml:"failure_count"`
	SuccessRate     float64           `json:"success_rate" yaml:"success_rate"`
	LastUsed        time.Time         `json:"last_used" yaml:"last_used"`
	LastSeen        time.Time         `json:"last_seen" yaml:"last_seen"`
	FirstSeen       time.Time         `json:"first_seen" yaml:"first_seen"`
	CreatedAt       time.Time         `json:"created_at" yaml:"created_at"`
	Tags            []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Context         PatternContext    `json:"context,omitempty" yaml:"context,omitempty"`
	Stats           PatternUsageStats `json:"stats,omitempty" yaml:"stats,omitempty"`
}

// PatternUsageStats holds usage statistics for a pattern
type PatternUsageStats struct {
	TotalAttempts      int       `json:"total_attempts" yaml:"total_attempts"`
	SuccessfulAttempts int       `json:"successful_attempts" yaml:"successful_attempts"`
	Successes          int       `json:"successes" yaml:"successes"`
	Failures           int       `json:"failures" yaml:"failures"`
	AvgResponseTime    float64   `json:"avg_response_time" yaml:"avg_response_time"`
	LastAttempt        time.Time `json:"last_attempt" yaml:"last_attempt"`
}

// PatternContext captures the context where a pattern succeeded
type PatternContext struct {
	Position     ParameterPosition `json:"position,omitempty" yaml:"position,omitempty"`
	ContentType  string            `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	HTTPMethod   string            `json:"http_method,omitempty" yaml:"http_method,omitempty"`
	ParamName    string            `json:"param_name,omitempty" yaml:"param_name,omitempty"`
}

// PatternStore represents the complete learned patterns store
type PatternStore struct {
	Version      string           `yaml:"version"`
	LastUpdated  time.Time        `yaml:"last_updated"`
	Patterns     []LearnedPattern `yaml:"patterns"`
	Statistics   PatternStats     `yaml:"statistics"`
}

// PatternStats holds aggregate statistics
type PatternStats struct {
	TotalPatterns     int                    `yaml:"total_patterns"`
	TotalSuccesses    int                    `yaml:"total_successes"`
	TotalFailures     int                    `yaml:"total_failures"`
	ByWAF             map[WAFType]int        `yaml:"by_waf"`
	ByAttackType      map[AttackType]int     `yaml:"by_attack_type"`
	TopMutations      []MutationStat         `yaml:"top_mutations"`
	LastEvolution     time.Time              `yaml:"last_evolution,omitempty"`
}

// MutationStat represents statistics for a mutation
type MutationStat struct {
	Mutation     string  `yaml:"mutation"`
	SuccessRate  float64 `yaml:"success_rate"`
	TotalUses    int     `yaml:"total_uses"`
}

// PatternQuery represents criteria for querying patterns
type PatternQuery struct {
	WAFType       WAFType        `json:"waf_type,omitempty"`
	AttackType    AttackType     `json:"attack_type,omitempty"`
	MinSuccessRate float64       `json:"min_success_rate,omitempty"`
	MaxAge        time.Duration  `json:"max_age,omitempty"`
	Tags          []string       `json:"tags,omitempty"`
	Position      ParameterPosition `json:"position,omitempty"`
	Limit         int            `json:"limit,omitempty"`
	SortBy        PatternSortBy  `json:"sort_by,omitempty"`
}

// PatternSortBy represents sorting options
type PatternSortBy string

const (
	SortBySuccessRate PatternSortBy = "success_rate"
	SortByRecent      PatternSortBy = "recent"
	SortByUsageCount  PatternSortBy = "usage_count"
)

// EvolutionConfig holds genetic algorithm configuration
type EvolutionSettings struct {
	Generations    int     `yaml:"generations"`
	PopulationSize int     `yaml:"population_size"`
	MutationRate   float64 `yaml:"mutation_rate"`
	CrossoverRate  float64 `yaml:"crossover_rate"`
	EliteCount     int     `yaml:"elite_count"`
	TournamentSize int     `yaml:"tournament_size"`
}

// Individual represents an individual in genetic algorithm
type Individual struct {
	Genome      []string `json:"genome"`
	Fitness     float64  `json:"fitness"`
	Generations int      `json:"generations"`
	Origin      string   `json:"origin"` // "initial", "crossover", "mutation"
}

// Population represents a population in genetic algorithm
type Population struct {
	Individuals   []Individual `json:"individuals"`
	Generation    int          `json:"generation"`
	BestFitness   float64      `json:"best_fitness"`
	AvgFitness    float64      `json:"avg_fitness"`
	Diversity     float64      `json:"diversity"`
}

// EvolutionResult represents the result of evolution
type EvolutionResult struct {
	BestIndividual  Individual        `json:"best_individual"`
	BestIndividuals []Individual      `json:"best_individuals"`
	TopPatterns     []*LearnedPattern `json:"top_patterns"`
	FinalGeneration int               `json:"final_generation"`
	Generations     int               `json:"generations"`
	Converged       bool              `json:"converged"`
	ImprovementRate float64           `json:"improvement_rate"`
	History         []GenerationStats `json:"history"`
}

// GenerationStats holds statistics for one generation
type GenerationStats struct {
	Generation  int     `json:"generation"`
	BestFitness float64 `json:"best_fitness"`
	AvgFitness  float64 `json:"avg_fitness"`
	Diversity   float64 `json:"diversity"`
}

// ClusterInfo represents a cluster of similar patterns
type ClusterInfo struct {
	ID          string           `json:"id"`
	Centroid    string           `json:"centroid"`
	Patterns    []LearnedPattern `json:"patterns"`
	Size        int              `json:"size"`
	AvgSuccess  float64          `json:"avg_success_rate"`
	CommonMutations []string     `json:"common_mutations"`
}

// PatternExport represents patterns for export/sharing
type PatternExport struct {
	Version       string           `yaml:"version"`
	ExportedAt    time.Time        `yaml:"exported_at"`
	Anonymized    bool             `yaml:"anonymized"`
	WAFType       WAFType          `yaml:"waf_type,omitempty"`
	AttackType    AttackType       `yaml:"attack_type,omitempty"`
	Patterns      []LearnedPattern `yaml:"patterns"`
	Statistics    PatternStats     `yaml:"statistics"`
}

// PatternImportResult represents the result of importing patterns
type PatternImportResult struct {
	Imported    int      `json:"imported"`
	Duplicates  int      `json:"duplicates"`
	Conflicts   int      `json:"conflicts"`
	Errors      []string `json:"errors,omitempty"`
}
