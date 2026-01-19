package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CachedProvider wraps a provider with caching
type CachedProvider struct {
	provider Provider
	cache    *responseCache
	ttl      time.Duration
}

// responseCache holds cached responses
type responseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

// cacheEntry holds a cached response
type cacheEntry struct {
	content   string
	timestamp time.Time
}

// NewCachedProvider creates a provider with caching
func NewCachedProvider(provider Provider, ttl time.Duration) *CachedProvider {
	cp := &CachedProvider{
		provider: provider,
		cache: &responseCache{
			entries: make(map[string]*cacheEntry),
		},
		ttl: ttl,
	}

	// Start cleanup goroutine
	go cp.cleanupLoop()

	return cp
}

// Analyze sends a prompt with caching
func (p *CachedProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	return p.AnalyzeWithSystem(ctx, "", prompt)
}

// AnalyzeWithSystem sends a prompt with system message and caching
func (p *CachedProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	key := p.cacheKey(system, prompt)

	// Check cache
	if cached := p.getFromCache(key); cached != "" {
		return cached, nil
	}

	// Call underlying provider
	content, err := p.provider.AnalyzeWithSystem(ctx, system, prompt)
	if err != nil {
		return "", err
	}

	// Store in cache
	p.setCache(key, content)

	return content, nil
}

// AnalyzeStructured with caching (note: we cache the raw response)
func (p *CachedProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	// Add JSON instruction
	jsonPrompt := prompt + "\n\nRespond with valid JSON only, no markdown formatting or extra text."

	content, err := p.Analyze(ctx, jsonPrompt)
	if err != nil {
		return err
	}

	return ParseJSONResponse(content, result)
}

// Name returns the provider name
func (p *CachedProvider) Name() string {
	return p.provider.Name() + "-cached"
}

// Model returns the model being used
func (p *CachedProvider) Model() string {
	return p.provider.Model()
}

// ClearCache clears all cached entries
func (p *CachedProvider) ClearCache() {
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()
	p.cache.entries = make(map[string]*cacheEntry)
}

// cacheKey generates a cache key from system and prompt
func (p *CachedProvider) cacheKey(system, prompt string) string {
	combined := p.provider.Name() + ":" + p.provider.Model() + ":" + system + ":" + prompt
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// getFromCache retrieves a valid cached response
func (p *CachedProvider) getFromCache(key string) string {
	p.cache.mu.RLock()
	defer p.cache.mu.RUnlock()

	entry, ok := p.cache.entries[key]
	if !ok {
		return ""
	}

	// Check if expired
	if time.Since(entry.timestamp) > p.ttl {
		return ""
	}

	return entry.content
}

// setCache stores a response in cache
func (p *CachedProvider) setCache(key, content string) {
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()

	p.cache.entries[key] = &cacheEntry{
		content:   content,
		timestamp: time.Now(),
	}
}

// cleanupLoop periodically removes expired entries
func (p *CachedProvider) cleanupLoop() {
	ticker := time.NewTicker(p.ttl)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanup()
	}
}

// cleanup removes expired entries
func (p *CachedProvider) cleanup() {
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()

	now := time.Now()
	for key, entry := range p.cache.entries {
		if now.Sub(entry.timestamp) > p.ttl {
			delete(p.cache.entries, key)
		}
	}
}
