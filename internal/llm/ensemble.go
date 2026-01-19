package llm

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// EnsembleProvider implements the Provider interface using multiple providers
type EnsembleProvider struct {
	BaseProvider
	providers []weightedProvider
	strategy  EnsembleStrategy
}

// weightedProvider holds a provider with its weight
type weightedProvider struct {
	provider Provider
	weight   float64
}

// EnsembleStrategy defines how to aggregate responses
type EnsembleStrategy string

const (
	StrategyMajorityVote    EnsembleStrategy = "majority_vote"
	StrategyWeightedAverage EnsembleStrategy = "weighted_average"
	StrategyBestConfidence  EnsembleStrategy = "best_confidence"
	StrategyFirst           EnsembleStrategy = "first" // First successful response
)

// ProviderResult holds the result from a single provider
type ProviderResult struct {
	ProviderName string
	Content      string
	Error        error
	Weight       float64
}

// NewEnsembleProvider creates a new ensemble provider
func NewEnsembleProvider(config types.ProviderConfig) (*EnsembleProvider, error) {
	if !config.Ensemble.Enabled || len(config.Ensemble.Providers) == 0 {
		return nil, fmt.Errorf("%w: ensemble requires at least one provider", ErrInvalidConfig)
	}

	var providers []weightedProvider
	for _, pw := range config.Ensemble.Providers {
		// Create a config for each provider
		providerConfig := types.ProviderConfig{
			Name:        pw.Name,
			Model:       pw.Model,
			APIKey:      config.APIKey, // Use main API key by default
			BaseURL:     config.BaseURL,
			MaxTokens:   config.MaxTokens,
			Temperature: config.Temperature,
		}

		provider, err := NewProvider(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider %s: %w", pw.Name, err)
		}

		weight := pw.Weight
		if weight <= 0 {
			weight = 1.0 / float64(len(config.Ensemble.Providers))
		}

		providers = append(providers, weightedProvider{
			provider: provider,
			weight:   weight,
		})
	}

	strategy := EnsembleStrategy(config.Ensemble.Strategy)
	if strategy == "" {
		strategy = StrategyWeightedAverage
	}

	return &EnsembleProvider{
		BaseProvider: BaseProvider{config: config},
		providers:    providers,
		strategy:     strategy,
	}, nil
}

// Analyze queries all providers and aggregates responses
func (p *EnsembleProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem queries all providers with a system message
func (p *EnsembleProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	results := make(chan ProviderResult, len(p.providers))
	var wg sync.WaitGroup

	// Query all providers in parallel
	for _, wp := range p.providers {
		wg.Add(1)
		go func(wp weightedProvider) {
			defer wg.Done()
			content, err := wp.provider.AnalyzeWithSystem(ctx, system, prompt)
			results <- ProviderResult{
				ProviderName: wp.provider.Name(),
				Content:      content,
				Error:        err,
				Weight:       wp.weight,
			}
		}(wp)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []ProviderResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return p.aggregate(allResults)
}

// AnalyzeStructured queries all providers and returns the best structured result
func (p *EnsembleProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add instruction to return JSON
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}

// Name returns the provider name
func (p *EnsembleProvider) Name() string {
	return "ensemble"
}

// Model returns a description of models being used
func (p *EnsembleProvider) Model() string {
	models := ""
	for i, wp := range p.providers {
		if i > 0 {
			models += ", "
		}
		models += wp.provider.Name() + ":" + wp.provider.Model()
	}
	return models
}

// aggregate combines results based on the strategy
func (p *EnsembleProvider) aggregate(results []ProviderResult) (string, error) {
	// Filter successful results
	var successfulResults []ProviderResult
	var lastError error
	for _, r := range results {
		if r.Error == nil {
			successfulResults = append(successfulResults, r)
		} else {
			lastError = r.Error
		}
	}

	if len(successfulResults) == 0 {
		return "", fmt.Errorf("all providers failed, last error: %w", lastError)
	}

	switch p.strategy {
	case StrategyFirst:
		return successfulResults[0].Content, nil

	case StrategyMajorityVote:
		return p.majorityVote(successfulResults), nil

	case StrategyBestConfidence:
		return p.bestConfidence(successfulResults), nil

	case StrategyWeightedAverage:
		fallthrough
	default:
		return p.weightedSelect(successfulResults), nil
	}
}

// majorityVote returns the most common response
func (p *EnsembleProvider) majorityVote(results []ProviderResult) string {
	votes := make(map[string]int)
	for _, r := range results {
		votes[r.Content]++
	}

	var maxVotes int
	var winner string
	for content, count := range votes {
		if count > maxVotes {
			maxVotes = count
			winner = content
		}
	}

	return winner
}

// bestConfidence returns the response with highest weight
func (p *EnsembleProvider) bestConfidence(results []ProviderResult) string {
	var best ProviderResult
	for _, r := range results {
		if r.Weight > best.Weight {
			best = r
		}
	}
	return best.Content
}

// weightedSelect returns content from provider with highest cumulative weight
func (p *EnsembleProvider) weightedSelect(results []ProviderResult) string {
	// Sort by weight descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Weight > results[j].Weight
	})

	// Return the highest weighted result
	return results[0].Content
}
