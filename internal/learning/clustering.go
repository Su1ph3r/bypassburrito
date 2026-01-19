package learning

import (
	"math"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// PayloadClusterer groups similar payloads together
type PayloadClusterer struct {
	store *Store
}

// Cluster represents a group of similar patterns
type Cluster struct {
	ID          int
	Centroid    []string           // Representative mutations
	Members     []*types.LearnedPattern
	AvgSuccess  float64
	Size        int
}

// NewPayloadClusterer creates a new clusterer
func NewPayloadClusterer(store *Store) *PayloadClusterer {
	return &PayloadClusterer{store: store}
}

// ClusterByMutation clusters patterns by their mutation similarity
func (c *PayloadClusterer) ClusterByMutation(patterns []*types.LearnedPattern, k int) []Cluster {
	if len(patterns) == 0 || k <= 0 {
		return nil
	}

	if k > len(patterns) {
		k = len(patterns)
	}

	// Initialize clusters with random centroids
	clusters := make([]Cluster, k)
	for i := 0; i < k; i++ {
		clusters[i] = Cluster{
			ID:      i,
			Members: make([]*types.LearnedPattern, 0),
		}
		if i < len(patterns) {
			clusters[i].Centroid = copyStrings(patterns[i].Mutations)
		}
	}

	// K-means iteration
	maxIterations := 50
	for iter := 0; iter < maxIterations; iter++ {
		// Clear members
		for i := range clusters {
			clusters[i].Members = make([]*types.LearnedPattern, 0)
		}

		// Assign patterns to nearest cluster
		for _, p := range patterns {
			nearestCluster := 0
			nearestDist := math.MaxFloat64

			for i, cluster := range clusters {
				dist := c.mutationDistance(p.Mutations, cluster.Centroid)
				if dist < nearestDist {
					nearestDist = dist
					nearestCluster = i
				}
			}

			clusters[nearestCluster].Members = append(clusters[nearestCluster].Members, p)
		}

		// Update centroids
		changed := false
		for i := range clusters {
			if len(clusters[i].Members) > 0 {
				newCentroid := c.computeCentroid(clusters[i].Members)
				if !equalMutations(clusters[i].Centroid, newCentroid) {
					clusters[i].Centroid = newCentroid
					changed = true
				}
			}
		}

		if !changed {
			break
		}
	}

	// Calculate statistics for each cluster
	for i := range clusters {
		clusters[i].Size = len(clusters[i].Members)
		clusters[i].AvgSuccess = c.avgSuccess(clusters[i].Members)
	}

	// Remove empty clusters
	result := make([]Cluster, 0, len(clusters))
	for _, cluster := range clusters {
		if cluster.Size > 0 {
			result = append(result, cluster)
		}
	}

	return result
}

// ClusterForWAF clusters patterns for a specific WAF
func (c *PayloadClusterer) ClusterForWAF(wafType types.WAFType, k int) []Cluster {
	patterns := c.store.GetByWAF(wafType)
	return c.ClusterByMutation(patterns, k)
}

// FindSimilarPatterns finds patterns similar to a given mutation chain
func (c *PayloadClusterer) FindSimilarPatterns(mutations []string, threshold float64) []*types.LearnedPattern {
	allPatterns := c.store.GetTopPatterns(1000)

	similar := make([]*types.LearnedPattern, 0)
	for _, p := range allPatterns {
		dist := c.mutationDistance(mutations, p.Mutations)
		if dist <= threshold {
			similar = append(similar, p)
		}
	}

	return similar
}

// mutationDistance calculates Jaccard distance between mutation sets
func (c *PayloadClusterer) mutationDistance(m1, m2 []string) float64 {
	if len(m1) == 0 && len(m2) == 0 {
		return 0
	}

	set1 := make(map[string]bool)
	for _, m := range m1 {
		set1[m] = true
	}

	set2 := make(map[string]bool)
	for _, m := range m2 {
		set2[m] = true
	}

	// Count intersection
	intersection := 0
	for m := range set1 {
		if set2[m] {
			intersection++
		}
	}

	// Union size
	union := make(map[string]bool)
	for m := range set1 {
		union[m] = true
	}
	for m := range set2 {
		union[m] = true
	}

	if len(union) == 0 {
		return 0
	}

	// Jaccard distance = 1 - (intersection / union)
	return 1.0 - float64(intersection)/float64(len(union))
}

// computeCentroid finds the most representative mutation set
func (c *PayloadClusterer) computeCentroid(patterns []*types.LearnedPattern) []string {
	if len(patterns) == 0 {
		return nil
	}

	// Count mutation frequencies
	mutationFreq := make(map[string]int)
	for _, p := range patterns {
		for _, m := range p.Mutations {
			mutationFreq[m]++
		}
	}

	// Include mutations that appear in majority of patterns
	threshold := len(patterns) / 2
	if threshold < 1 {
		threshold = 1
	}

	centroid := make([]string, 0)
	for m, count := range mutationFreq {
		if count >= threshold {
			centroid = append(centroid, m)
		}
	}

	// If no common mutations, use the most successful pattern's mutations
	if len(centroid) == 0 && len(patterns) > 0 {
		best := patterns[0]
		for _, p := range patterns[1:] {
			if p.SuccessRate > best.SuccessRate {
				best = p
			}
		}
		centroid = copyStrings(best.Mutations)
	}

	return centroid
}

func (c *PayloadClusterer) avgSuccess(patterns []*types.LearnedPattern) float64 {
	if len(patterns) == 0 {
		return 0
	}

	sum := 0.0
	for _, p := range patterns {
		sum += p.SuccessRate
	}
	return sum / float64(len(patterns))
}

func equalMutations(m1, m2 []string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for i := range m1 {
		if m1[i] != m2[i] {
			return false
		}
	}
	return true
}

// AnalyzeClusters provides insights about clusters
type ClusterAnalysis struct {
	TotalClusters     int
	AverageClusterSize float64
	BestCluster       *Cluster
	MostCommonMutations []string
	DiversityScore    float64
}

func (c *PayloadClusterer) AnalyzeClusters(clusters []Cluster) *ClusterAnalysis {
	if len(clusters) == 0 {
		return &ClusterAnalysis{}
	}

	analysis := &ClusterAnalysis{
		TotalClusters: len(clusters),
	}

	// Calculate average size
	totalSize := 0
	for _, cluster := range clusters {
		totalSize += cluster.Size
	}
	analysis.AverageClusterSize = float64(totalSize) / float64(len(clusters))

	// Find best cluster
	bestIdx := 0
	for i, cluster := range clusters {
		if cluster.AvgSuccess > clusters[bestIdx].AvgSuccess {
			bestIdx = i
		}
	}
	analysis.BestCluster = &clusters[bestIdx]

	// Find most common mutations across all clusters
	mutationCounts := make(map[string]int)
	for _, cluster := range clusters {
		for _, m := range cluster.Centroid {
			mutationCounts[m]++
		}
	}

	// Get top 5 mutations
	type mutCount struct {
		mut   string
		count int
	}
	counts := make([]mutCount, 0, len(mutationCounts))
	for m, count := range mutationCounts {
		counts = append(counts, mutCount{m, count})
	}
	// Sort by count descending
	for i := 0; i < len(counts)-1; i++ {
		for j := 0; j < len(counts)-i-1; j++ {
			if counts[j].count < counts[j+1].count {
				counts[j], counts[j+1] = counts[j+1], counts[j]
			}
		}
	}

	for i := 0; i < 5 && i < len(counts); i++ {
		analysis.MostCommonMutations = append(analysis.MostCommonMutations, counts[i].mut)
	}

	// Calculate diversity score (how different are the clusters)
	if len(clusters) > 1 {
		totalDist := 0.0
		comparisons := 0
		for i := 0; i < len(clusters); i++ {
			for j := i + 1; j < len(clusters); j++ {
				totalDist += c.mutationDistance(clusters[i].Centroid, clusters[j].Centroid)
				comparisons++
			}
		}
		if comparisons > 0 {
			analysis.DiversityScore = totalDist / float64(comparisons)
		}
	}

	return analysis
}
