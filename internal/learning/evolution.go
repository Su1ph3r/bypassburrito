package learning

import (
	"math/rand"
	"sort"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// GeneticEvolver implements genetic algorithm for pattern evolution
type GeneticEvolver struct {
	PopulationSize int
	MutationRate   float64
	CrossoverRate  float64
	Generations    int
	EliteCount     int
	store          *Store
}

// NewGeneticEvolver creates a new genetic evolver
func NewGeneticEvolver(store *Store) *GeneticEvolver {
	return &GeneticEvolver{
		PopulationSize: 50,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		Generations:    10,
		EliteCount:     5,
		store:          store,
	}
}

// WithPopulationSize sets population size
func (e *GeneticEvolver) WithPopulationSize(size int) *GeneticEvolver {
	e.PopulationSize = size
	return e
}

// WithGenerations sets number of generations
func (e *GeneticEvolver) WithGenerations(n int) *GeneticEvolver {
	e.Generations = n
	return e
}

// WithMutationRate sets mutation rate
func (e *GeneticEvolver) WithMutationRate(rate float64) *GeneticEvolver {
	e.MutationRate = rate
	return e
}

// Evolve runs the genetic algorithm to evolve mutation chains
func (e *GeneticEvolver) Evolve(wafType types.WAFType, attackType types.AttackType, allMutations []string) *types.EvolutionResult {
	// Initialize population from learned patterns
	population := e.initializePopulation(wafType, attackType, allMutations)

	result := &types.EvolutionResult{
		Generations:   e.Generations,
		BestIndividual: types.Individual{},
	}

	for gen := 0; gen < e.Generations; gen++ {
		// Evaluate fitness
		e.evaluateFitness(population)

		// Sort by fitness
		sort.Slice(population, func(i, j int) bool {
			return population[i].Fitness > population[j].Fitness
		})

		// Track best
		if len(population) > 0 && population[0].Fitness > result.BestIndividual.Fitness {
			result.BestIndividual = copyIndividual(population[0])
		}

		// Selection
		selected := e.tournamentSelection(population)

		// Crossover
		offspring := e.crossover(selected)

		// Mutation
		e.mutate(offspring, allMutations)

		// Elitism - keep best individuals
		newPopulation := make([]types.Individual, 0, e.PopulationSize)
		for i := 0; i < e.EliteCount && i < len(population); i++ {
			newPopulation = append(newPopulation, copyIndividual(population[i]))
		}

		// Fill rest with offspring
		for i := 0; len(newPopulation) < e.PopulationSize && i < len(offspring); i++ {
			newPopulation = append(newPopulation, offspring[i])
		}

		population = newPopulation
	}

	// Final evaluation
	e.evaluateFitness(population)
	sort.Slice(population, func(i, j int) bool {
		return population[i].Fitness > population[j].Fitness
	})

	if len(population) > 0 && population[0].Fitness > result.BestIndividual.Fitness {
		result.BestIndividual = copyIndividual(population[0])
	}

	// Top patterns
	for i := 0; i < 10 && i < len(population); i++ {
		result.TopPatterns = append(result.TopPatterns, &types.LearnedPattern{
			Mutations:   population[i].Genome,
			SuccessRate: population[i].Fitness,
			WAFType:     wafType,
			AttackType:  attackType,
		})
	}

	return result
}

// initializePopulation creates initial population
func (e *GeneticEvolver) initializePopulation(wafType types.WAFType, attackType types.AttackType, allMutations []string) []types.Individual {
	population := make([]types.Individual, 0, e.PopulationSize)

	// Seed from learned patterns
	patterns := e.store.GetPatterns(wafType, attackType)
	for _, p := range patterns {
		if len(population) >= e.PopulationSize/2 {
			break
		}
		population = append(population, types.Individual{
			Genome:      copyStrings(p.Mutations),
			Fitness:     p.SuccessRate,
			Generations: 1,
		})
	}

	// Fill with random individuals
	for len(population) < e.PopulationSize {
		genome := generateRandomGenome(allMutations, 3+rand.Intn(5))
		population = append(population, types.Individual{
			Genome:      genome,
			Fitness:     0,
			Generations: 0,
		})
	}

	return population
}

// evaluateFitness calculates fitness for each individual
func (e *GeneticEvolver) evaluateFitness(population []types.Individual) {
	for i := range population {
		// Base fitness from historical data
		fitness := e.lookupHistoricalFitness(population[i].Genome)

		// Bonus for diversity (using different mutations)
		uniqueMutations := make(map[string]bool)
		for _, m := range population[i].Genome {
			uniqueMutations[m] = true
		}
		diversityBonus := float64(len(uniqueMutations)) / float64(len(population[i].Genome)+1) * 0.1

		// Penalty for very long chains
		lengthPenalty := 0.0
		if len(population[i].Genome) > 7 {
			lengthPenalty = float64(len(population[i].Genome)-7) * 0.02
		}

		population[i].Fitness = fitness + diversityBonus - lengthPenalty

		// Clamp to [0, 1]
		if population[i].Fitness < 0 {
			population[i].Fitness = 0
		}
		if population[i].Fitness > 1 {
			population[i].Fitness = 1
		}
	}
}

// lookupHistoricalFitness gets fitness from learned patterns
func (e *GeneticEvolver) lookupHistoricalFitness(genome []string) float64 {
	// Check if we have historical data for this mutation combination
	patterns := e.store.GetTopPatterns(100)

	bestMatch := 0.0
	for _, p := range patterns {
		// Count matching mutations
		matches := 0
		for _, m := range genome {
			for _, pm := range p.Mutations {
				if m == pm {
					matches++
					break
				}
			}
		}

		if len(genome) > 0 {
			similarity := float64(matches) / float64(len(genome))
			weighted := similarity * p.SuccessRate
			if weighted > bestMatch {
				bestMatch = weighted
			}
		}
	}

	return bestMatch
}

// tournamentSelection selects individuals using tournament selection
func (e *GeneticEvolver) tournamentSelection(population []types.Individual) []types.Individual {
	selected := make([]types.Individual, 0, len(population))
	tournamentSize := 3

	for i := 0; i < len(population); i++ {
		// Select tournament participants
		best := population[rand.Intn(len(population))]
		for j := 1; j < tournamentSize; j++ {
			candidate := population[rand.Intn(len(population))]
			if candidate.Fitness > best.Fitness {
				best = candidate
			}
		}
		selected = append(selected, copyIndividual(best))
	}

	return selected
}

// crossover performs crossover between selected individuals
func (e *GeneticEvolver) crossover(selected []types.Individual) []types.Individual {
	offspring := make([]types.Individual, 0, len(selected))

	for i := 0; i < len(selected)-1; i += 2 {
		parent1 := selected[i]
		parent2 := selected[i+1]

		if rand.Float64() < e.CrossoverRate {
			// Single-point crossover
			child1, child2 := e.singlePointCrossover(parent1, parent2)
			offspring = append(offspring, child1, child2)
		} else {
			offspring = append(offspring, copyIndividual(parent1), copyIndividual(parent2))
		}
	}

	return offspring
}

// singlePointCrossover performs single-point crossover
func (e *GeneticEvolver) singlePointCrossover(p1, p2 types.Individual) (types.Individual, types.Individual) {
	if len(p1.Genome) == 0 || len(p2.Genome) == 0 {
		return copyIndividual(p1), copyIndividual(p2)
	}

	point1 := rand.Intn(len(p1.Genome))
	point2 := rand.Intn(len(p2.Genome))

	child1Genome := append(copyStrings(p1.Genome[:point1]), p2.Genome[point2:]...)
	child2Genome := append(copyStrings(p2.Genome[:point2]), p1.Genome[point1:]...)

	return types.Individual{Genome: child1Genome, Generations: p1.Generations + 1},
		types.Individual{Genome: child2Genome, Generations: p2.Generations + 1}
}

// mutate applies mutations to offspring
func (e *GeneticEvolver) mutate(offspring []types.Individual, allMutations []string) {
	for i := range offspring {
		if rand.Float64() < e.MutationRate {
			e.mutateIndividual(&offspring[i], allMutations)
		}
	}
}

// mutateIndividual applies a random mutation to an individual
func (e *GeneticEvolver) mutateIndividual(ind *types.Individual, allMutations []string) {
	if len(allMutations) == 0 {
		return
	}

	mutationType := rand.Intn(3)
	switch mutationType {
	case 0: // Add a mutation
		newMutation := allMutations[rand.Intn(len(allMutations))]
		pos := rand.Intn(len(ind.Genome) + 1)
		ind.Genome = insertString(ind.Genome, pos, newMutation)

	case 1: // Remove a mutation
		if len(ind.Genome) > 1 {
			pos := rand.Intn(len(ind.Genome))
			ind.Genome = append(ind.Genome[:pos], ind.Genome[pos+1:]...)
		}

	case 2: // Replace a mutation
		if len(ind.Genome) > 0 {
			pos := rand.Intn(len(ind.Genome))
			ind.Genome[pos] = allMutations[rand.Intn(len(allMutations))]
		}
	}
}

// Helper functions

func copyIndividual(ind types.Individual) types.Individual {
	return types.Individual{
		Genome:      copyStrings(ind.Genome),
		Fitness:     ind.Fitness,
		Generations: ind.Generations,
	}
}

func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	result := make([]string, len(s))
	copy(result, s)
	return result
}

func generateRandomGenome(allMutations []string, length int) []string {
	if len(allMutations) == 0 {
		return nil
	}

	genome := make([]string, length)
	for i := 0; i < length; i++ {
		genome[i] = allMutations[rand.Intn(len(allMutations))]
	}
	return genome
}

func insertString(slice []string, pos int, s string) []string {
	if pos >= len(slice) {
		return append(slice, s)
	}
	slice = append(slice[:pos+1], slice[pos:]...)
	slice[pos] = s
	return slice
}
