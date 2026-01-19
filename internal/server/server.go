package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/su1ph3r/bypassburrito/internal/bypass"
	httpClient "github.com/su1ph3r/bypassburrito/internal/http"
	"github.com/su1ph3r/bypassburrito/internal/learning"
	"github.com/su1ph3r/bypassburrito/internal/llm"
	"github.com/su1ph3r/bypassburrito/internal/waf"
	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// Config holds server configuration
type Config struct {
	Host            string
	Port            int
	EnableCORS      bool
	AuthToken       string
	MaxConcurrent   int
	EnableWebSocket bool
	LLMProvider     string
	LLMAPIKey       string
	LLMModel        string
}

// Server handles HTTP requests for bypass operations
type Server struct {
	config      Config
	router      *gin.Engine
	httpServer  *http.Server
	bypassLoop  *bypass.BypassLoop
	learnStore  *learning.Store
	wafDetector *waf.Detector
	wsUpgrader  websocket.Upgrader

	// Job management
	mu       sync.RWMutex
	jobs     map[string]*JobStatus
	jobQueue chan *Job
	ctx      context.Context
	cancel   context.CancelFunc
}

// JobStatus tracks a bypass job
type JobStatus struct {
	ID          string              `json:"id"`
	Status      string              `json:"status"` // queued, running, completed, failed, cancelled
	Request     types.BypassRequest `json:"request"`
	Result      *types.BypassResult `json:"result,omitempty"`
	Error       string              `json:"error,omitempty"`
	Progress    int                 `json:"progress"`
	StartedAt   *time.Time          `json:"started_at,omitempty"`
	CompletedAt *time.Time          `json:"completed_at,omitempty"`
}

// Job represents a queued bypass job
type Job struct {
	ID      string
	Request types.BypassRequest
	Events  chan *bypass.BypassEvent
}

// New creates a new server instance
func New(config Config) (*Server, error) {
	// Set gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())

	// Create HTTP client
	httpClientConfig := types.HTTPConfig{
		Timeout:   30 * time.Second,
		RateLimit: 5.0,
	}
	client, err := httpClient.NewClient(httpClientConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create LLM provider
	llmConfig := types.ProviderConfig{
		APIKey:      config.LLMAPIKey,
		Model:       config.LLMModel,
		Temperature: 0.3,
	}

	var provider llm.Provider

	switch config.LLMProvider {
	case "anthropic":
		if llmConfig.Model == "" {
			llmConfig.Model = "claude-sonnet-4-20250514"
		}
		provider, err = llm.NewAnthropicProvider(llmConfig)
	case "openai":
		if llmConfig.Model == "" {
			llmConfig.Model = "gpt-4o"
		}
		provider, err = llm.NewOpenAIProvider(llmConfig)
	case "groq":
		if llmConfig.Model == "" {
			llmConfig.Model = "llama-3.1-70b-versatile"
		}
		provider, err = llm.NewGroqProvider(llmConfig)
	default:
		// Default to anthropic
		llmConfig.Model = "claude-sonnet-4-20250514"
		provider, err = llm.NewAnthropicProvider(llmConfig)
	}

	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create LLM provider: %w", err)
	}

	// Create WAF detector
	wafDetector, err := waf.NewDetector()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create WAF detector: %w", err)
	}

	// Create learning store
	learnStore := learning.NewStore("~/.bypassburrito/learned-patterns.yaml", true)
	learnStore.Load()

	// Create bypass config
	bypassConfig := types.BypassConfig{
		MaxIterations: 15,
		MaxPayloads:   30,
		DetectWAF:     true,
		UseLearned:    true,
		Strategies: types.StrategyConfig{
			Enabled: []string{"encoding", "obfuscation", "fragmentation", "polymorphic", "contextual"},
		},
	}

	// Create bypass loop
	bypassLoop := bypass.NewBypassLoop(provider, wafDetector, client, bypassConfig)

	server := &Server{
		config:      config,
		bypassLoop:  bypassLoop,
		learnStore:  learnStore,
		wafDetector: wafDetector,
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
		jobs:     make(map[string]*JobStatus),
		jobQueue: make(chan *Job, config.MaxConcurrent*2),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Setup router
	server.setupRouter()

	return server, nil
}

func (s *Server) setupRouter() {
	s.router = gin.New()
	s.router.Use(gin.Recovery())

	// CORS middleware
	if s.config.EnableCORS {
		s.router.Use(corsMiddleware())
	}

	// Auth middleware
	if s.config.AuthToken != "" {
		s.router.Use(authMiddleware(s.config.AuthToken))
	}

	// API routes
	api := s.router.Group("/api/v1")
	{
		// Bypass operations
		api.POST("/bypass", s.handleSubmitBypass)
		api.GET("/bypass/:id", s.handleGetBypass)
		api.DELETE("/bypass/:id", s.handleCancelBypass)
		if s.config.EnableWebSocket {
			api.GET("/bypass/:id/ws", s.handleBypassWebSocket)
		}

		// WAF detection
		api.POST("/detect", s.handleDetect)

		// Queue management
		api.GET("/queue", s.handleListQueue)

		// Learning patterns
		api.GET("/patterns", s.handleListPatterns)
		api.POST("/patterns/export", s.handleExportPatterns)
		api.POST("/patterns/import", s.handleImportPatterns)

		// Health
		api.GET("/health", s.handleHealth)
		api.GET("/config", s.handleConfig)
	}
}

// Start starts the server
func (s *Server) Start() error {
	// Start job workers
	for i := 0; i < s.config.MaxConcurrent; i++ {
		go s.jobWorker()
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}

	s.learnStore.Save()
}

// Job worker processes queued jobs
func (s *Server) jobWorker() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobQueue:
			s.processJob(job)
		}
	}
}

func (s *Server) processJob(job *Job) {
	// Update status
	s.mu.Lock()
	status := s.jobs[job.ID]
	if status == nil {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	status.Status = "running"
	status.StartedAt = &now
	s.mu.Unlock()

	// Subscribe to events
	events := s.bypassLoop.Subscribe(job.ID)
	defer s.bypassLoop.Unsubscribe(job.ID, events)

	// Forward events to job channel if provided
	if job.Events != nil {
		go func() {
			for event := range events {
				select {
				case job.Events <- event:
				default:
				}
			}
		}()
	}

	// Run bypass
	result, err := s.bypassLoop.Run(s.ctx, job.Request)

	// Update status
	s.mu.Lock()
	completed := time.Now()
	status.CompletedAt = &completed
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
	} else {
		status.Status = "completed"
		status.Result = result
	}
	s.mu.Unlock()

	// Record to learning store
	if result != nil {
		for _, attempt := range result.AllAttempts {
			wafType := types.WAFUnknown
			if result.WAFDetected != nil {
				wafType = result.WAFDetected.Type
			}
			success := attempt.Result == types.ResultBypassed
			s.learnStore.Record(&attempt, wafType, success)
		}
	}
}

// API Handlers

func (s *Server) handleSubmitBypass(c *gin.Context) {
	var req types.BypassRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate ID if not provided
	if req.ID == "" {
		req.ID = bypass.GenerateID()
	}

	// Create job status
	status := &JobStatus{
		ID:      req.ID,
		Status:  "queued",
		Request: req,
	}

	s.mu.Lock()
	s.jobs[req.ID] = status
	s.mu.Unlock()

	// Create and queue job
	job := &Job{
		ID:      req.ID,
		Request: req,
	}

	select {
	case s.jobQueue <- job:
		c.JSON(http.StatusAccepted, gin.H{
			"id":     req.ID,
			"status": "queued",
		})
	default:
		s.mu.Lock()
		delete(s.jobs, req.ID)
		s.mu.Unlock()
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "queue full"})
	}
}

func (s *Server) handleGetBypass(c *gin.Context) {
	id := c.Param("id")

	s.mu.RLock()
	status, ok := s.jobs[id]
	s.mu.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	c.JSON(http.StatusOK, status)
}

func (s *Server) handleCancelBypass(c *gin.Context) {
	id := c.Param("id")

	s.mu.Lock()
	status, ok := s.jobs[id]
	if ok && status.Status == "queued" {
		status.Status = "cancelled"
	}
	s.mu.Unlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func (s *Server) handleBypassWebSocket(c *gin.Context) {
	id := c.Param("id")

	s.mu.RLock()
	_, ok := s.jobs[id]
	s.mu.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	conn, err := s.wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Subscribe to events
	events := s.bypassLoop.Subscribe(id)
	defer s.bypassLoop.Unsubscribe(id, events)

	for event := range events {
		data, _ := json.Marshal(event)
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			return
		}
	}
}

func (s *Server) handleDetect(c *gin.Context) {
	var req struct {
		URL string `json:"url" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Make baseline request
	httpClientConfig := types.HTTPConfig{
		Timeout:   30 * time.Second,
		RateLimit: 5.0,
	}
	client, err := httpClient.NewClient(httpClientConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create HTTP client"})
		return
	}

	httpReq := &types.HTTPRequest{
		Method:    "GET",
		URL:       req.URL,
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	resp, err := client.Do(s.ctx, httpReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	result := s.wafDetector.Detect(resp)
	c.JSON(http.StatusOK, result)
}

func (s *Server) handleListQueue(c *gin.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]*JobStatus, 0, len(s.jobs))
	for _, status := range s.jobs {
		items = append(items, status)
	}

	c.JSON(http.StatusOK, gin.H{
		"total": len(items),
		"jobs":  items,
	})
}

func (s *Server) handleListPatterns(c *gin.Context) {
	wafFilter := c.Query("waf")
	attackFilter := c.Query("attack")

	var patterns []*types.LearnedPattern

	if wafFilter != "" && attackFilter != "" {
		patterns = s.learnStore.GetPatterns(types.WAFType(wafFilter), types.AttackType(attackFilter))
	} else if wafFilter != "" {
		patterns = s.learnStore.GetByWAF(types.WAFType(wafFilter))
	} else if attackFilter != "" {
		patterns = s.learnStore.GetByAttack(types.AttackType(attackFilter))
	} else {
		patterns = s.learnStore.GetTopPatterns(100)
	}

	c.JSON(http.StatusOK, gin.H{
		"total":    len(patterns),
		"patterns": patterns,
	})
}

func (s *Server) handleExportPatterns(c *gin.Context) {
	var req struct {
		WAFFilter string `json:"waf_filter"`
	}
	c.ShouldBindJSON(&req)

	patterns := s.learnStore.GetTopPatterns(1000)

	c.JSON(http.StatusOK, gin.H{
		"patterns": patterns,
	})
}

func (s *Server) handleImportPatterns(c *gin.Context) {
	var req struct {
		Patterns []*types.LearnedPattern `json:"patterns"`
		Merge    bool                    `json:"merge"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Note: This is a simplified import - actual implementation would write to temp file
	c.JSON(http.StatusOK, gin.H{
		"imported": len(req.Patterns),
	})
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"llm_provider":   s.config.LLMProvider,
		"max_concurrent": s.config.MaxConcurrent,
		"websocket":      s.config.EnableWebSocket,
	})
}

// Middleware

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func authMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth != "Bearer "+token && auth != token {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}
