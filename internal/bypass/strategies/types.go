package strategies

import "github.com/su1ph3r/bypassburrito/pkg/types"

// MutationResult represents the result of a mutation
type MutationResult struct {
	Payload     string
	Mutation    string
	Description string
}

// Mutator interface for all mutation strategies
type Mutator interface {
	Mutate(payload string) []MutationResult
}

// MutatorFunc is a function type that implements Mutator
type MutatorFunc func(payload string) []MutationResult

// Mutate implements Mutator interface
func (f MutatorFunc) Mutate(payload string) []MutationResult {
	return f(payload)
}

// MutationChain combines multiple mutators
type MutationChain struct {
	Name        string
	Description string
	Mutators    []Mutator
	MaxDepth    int
}

// NewMutationChain creates a new mutation chain
func NewMutationChain(name, description string, mutators ...Mutator) *MutationChain {
	return &MutationChain{
		Name:        name,
		Description: description,
		Mutators:    mutators,
		MaxDepth:    3,
	}
}

// Mutate applies the chain of mutations
func (c *MutationChain) Mutate(payload string) []MutationResult {
	var results []MutationResult

	// Apply each mutator
	for _, mutator := range c.Mutators {
		mutations := mutator.Mutate(payload)
		results = append(results, mutations...)

		// Apply chained mutations (mutations on mutations)
		if c.MaxDepth > 1 {
			for _, m := range mutations {
				for _, nextMutator := range c.Mutators {
					chainedMutations := nextMutator.Mutate(m.Payload)
					for _, cm := range chainedMutations {
						results = append(results, MutationResult{
							Payload:     cm.Payload,
							Mutation:    m.Mutation + " + " + cm.Mutation,
							Description: m.Description + " then " + cm.Description,
						})
					}
				}
			}
		}
	}

	return results
}

// StrategyRegistry holds all available mutation strategies
type StrategyRegistry struct {
	strategies map[string]Mutator
	chains     map[string]*MutationChain
}

// NewStrategyRegistry creates a new strategy registry with default strategies
func NewStrategyRegistry() *StrategyRegistry {
	r := &StrategyRegistry{
		strategies: make(map[string]Mutator),
		chains:     make(map[string]*MutationChain),
	}

	// Register default strategies
	r.Register("encoding", NewEncodingMutator())
	r.Register("obfuscation", NewObfuscationMutator())
	r.Register("adversarial", NewAdversarialMutator())

	// Register default chains
	r.RegisterChain(NewMutationChain(
		"aggressive",
		"Aggressive bypass chain",
		NewEncodingMutator(),
		NewObfuscationMutator(),
		NewAdversarialMutator(),
	))

	return r
}

// Register registers a mutation strategy
func (r *StrategyRegistry) Register(name string, mutator Mutator) {
	r.strategies[name] = mutator
}

// RegisterChain registers a mutation chain
func (r *StrategyRegistry) RegisterChain(chain *MutationChain) {
	r.chains[chain.Name] = chain
}

// Get returns a mutation strategy by name
func (r *StrategyRegistry) Get(name string) (Mutator, bool) {
	m, ok := r.strategies[name]
	return m, ok
}

// GetChain returns a mutation chain by name
func (r *StrategyRegistry) GetChain(name string) (*MutationChain, bool) {
	c, ok := r.chains[name]
	return c, ok
}

// GetAllStrategies returns all registered strategies
func (r *StrategyRegistry) GetAllStrategies() map[string]Mutator {
	return r.strategies
}

// ApplyAll applies all enabled strategies to a payload
func (r *StrategyRegistry) ApplyAll(payload string, enabled []string) []MutationResult {
	var results []MutationResult

	for _, name := range enabled {
		if mutator, ok := r.strategies[name]; ok {
			mutations := mutator.Mutate(payload)
			results = append(results, mutations...)
		}
		if chain, ok := r.chains[name]; ok {
			mutations := chain.Mutate(payload)
			results = append(results, mutations...)
		}
	}

	return results
}

// CreateMutatorsFromConfig creates mutators from configuration
func CreateMutatorsFromConfig(config types.StrategyConfig) []Mutator {
	var mutators []Mutator

	for _, strategyName := range config.Enabled {
		switch strategyName {
		case "encoding":
			mutators = append(mutators, &EncodingMutator{
				URL:            config.Encoding.URL,
				DoubleURL:      config.Encoding.DoubleURL,
				Unicode:        config.Encoding.Unicode,
				OverlongUnicode: config.Encoding.OverlongUnicode,
				HTMLEntity:     config.Encoding.HTMLEntity,
				Mixed:          config.Encoding.Mixed,
			})
		case "obfuscation":
			mutators = append(mutators, &ObfuscationMutator{
				CommentInjection:       config.Obfuscation.CommentInjection,
				CaseRandomization:      config.Obfuscation.CaseRandomization,
				WhitespaceSubstitution: config.Obfuscation.WhitespaceSubstitution,
				NullBytes:              config.Obfuscation.NullBytes,
			})
		case "adversarial":
			mutators = append(mutators, &AdversarialMutator{
				Homoglyphs:     config.Adversarial.Homoglyphs,
				InvisibleChars: config.Adversarial.InvisibleChars,
				BiDiOverride:   config.Adversarial.BiDiOverride,
			})
		case "fragmentation":
			mutators = append(mutators, NewFragmentationMutator())
		case "polymorphic":
			mutators = append(mutators, NewPolymorphicMutator())
		case "contextual":
			mutators = append(mutators, NewContextualMutator())
		}
	}

	return mutators
}
