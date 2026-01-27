# BypassBurrito - Claude Code Instructions

## Project Overview

BypassBurrito is an LLM-powered WAF bypass generator for authorized penetration testing. It uses intelligent mutation strategies combined with machine learning to discover ways to evade Web Application Firewalls.

**IMPORTANT:** This tool is intended for authorized security testing only. Always ensure you have explicit permission before testing any system.

## Architecture

```
bypassburrito/
├── cmd/burrito/            # CLI entry point (Cobra)
│   ├── main.go             # Root command setup
│   ├── bypass.go           # Main bypass command
│   ├── detect.go           # WAF detection command
│   ├── infer.go            # WAF rule inference command
│   ├── plugins.go          # Plugin management commands
│   └── serve.go            # API server mode
├── internal/
│   ├── bypass/             # Core bypass engine
│   │   ├── loop.go         # Main bypass orchestrator
│   │   ├── analyzer.go     # Response classification
│   │   ├── minimizer.go    # Payload minimization
│   │   ├── strategies/     # Mutation strategies
│   │   ├── oracle/         # Response oracle analysis
│   │   │   ├── oracle.go   # Oracle interface & coordinator
│   │   │   ├── timing.go   # Timing side-channel analyzer
│   │   │   ├── differential.go  # Body diffing
│   │   │   ├── fingerprint.go   # Error fingerprinting
│   │   │   └── content.go  # Content-length analyzer
│   │   └── statemachine/   # Multi-request state machine
│   │       ├── machine.go  # State machine orchestrator
│   │       ├── state.go    # State definitions
│   │       ├── sequence.go # Attack sequence loading
│   │       └── transitions.go  # Conditional branching
│   ├── waf/                # WAF detection & inference
│   │   ├── detector.go     # WAF fingerprinting
│   │   ├── signatures.go   # Signature database
│   │   └── inference.go    # Rule inference engine
│   ├── llm/                # LLM providers
│   │   ├── provider.go     # Provider interface
│   │   ├── anthropic.go    # Claude integration
│   │   ├── openai.go       # GPT integration
│   │   └── ollama.go       # Local LLM support
│   ├── learning/           # Pattern learning system
│   │   ├── store.go        # Pattern persistence
│   │   └── evolution.go    # Genetic algorithm
│   ├── http/               # HTTP utilities
│   │   ├── client.go       # HTTP client wrapper
│   │   └── protocol/       # Protocol-level evasion
│   │       ├── protocol.go # Evasion interface
│   │       ├── http2.go    # HTTP/2 manipulation
│   │       ├── websocket.go # WebSocket attacks
│   │       └── chunked.go  # Chunked encoding tricks
│   ├── solver/             # Challenge solving
│   │   ├── solver.go       # Solver interface & manager
│   │   ├── browser.go      # Headless browser integration
│   │   ├── cloudflare.go   # Cloudflare challenge handler
│   │   └── captcha.go      # CAPTCHA API integration
│   ├── output/             # Report generation
│   │   └── reporter.go     # Multi-format reporting
│   └── payloads/           # Payload library
├── pkg/
│   ├── types/              # Shared type definitions
│   │   ├── config.go       # Configuration structs
│   │   ├── payload.go      # Payload types
│   │   ├── response.go     # Response types
│   │   └── waf.go          # WAF types
│   └── plugins/            # Plugin SDK
│       ├── sdk.go          # Plugin interface
│       ├── loader.go       # Plugin loader
│       └── registry.go     # Plugin registry
├── configs/                # Configuration files
│   └── sequences/          # Attack sequence definitions
│       ├── csrf_bypass.yaml    # CSRF token extraction
│       └── auth_bypass.yaml    # Auth bypass chains
└── go.mod                  # Go module definition
```

## Key Commands

```bash
# Generate WAF bypass payloads
burrito bypass -u <url> --param <param> --type sqli

# Detect WAF type
burrito detect -u <url> --deep

# Infer WAF rules
burrito infer -u <url> --param <param> --samples 100

# List plugins
burrito plugins list

# Start API server
burrito serve --port 8089
```

## Development Guidelines

### Adding New Mutation Strategies

1. Create a new file in `internal/bypass/strategies/`
2. Implement the `Mutator` interface:
   ```go
   type Mutator interface {
       Mutate(payload string) []MutationResult
   }
   ```
3. Register in `CreateMutatorsFromConfig()` in `types.go`

### Creating Plugins

Plugins are Go shared objects (.so) that implement `MutationPlugin`:

```go
type MutationPlugin interface {
    Name() string
    Version() string
    Description() string
    Author() string
    Mutate(payload string, ctx MutationContext) []MutationResult
    Priority() int
    SupportedAttackTypes() []types.AttackType
    SupportedWAFTypes() []types.WAFType
    Initialize(config PluginConfig) error
    Cleanup() error
}
```

Place compiled plugins in `~/.bypassburrito/plugins/`

### Adding LLM Providers

1. Create a new file in `internal/llm/`
2. Implement the `Provider` interface
3. Add case in `createLLMProvider()` in `bypass.go`

---

## Feature TODOs

### Implemented Features

- [x] **Response Oracle Analysis** - Timing side-channels, error fingerprinting, body diffing, content-length anomaly detection (`internal/bypass/oracle/`)
- [x] **Protocol-Level Evasion** - HTTP/2 manipulation, WebSocket support, chunked transfer tricks (`internal/http/protocol/`)
- [x] **JavaScript Challenge Solver** - Headless browser CAPTCHA/JS challenge solving with 2captcha/AntiCaptcha integration (`internal/solver/`)
- [x] **SSTI Mutation Strategy** - Template injection bypass for Jinja2, Twig, Freemarker (`internal/bypass/strategies/ssti.go`)
- [x] **NoSQL Mutation Strategy** - MongoDB/CouchDB injection mutations (`internal/bypass/strategies/nosql.go`)
- [x] **Multi-Request State Machine** - Stateful attack sequences with variable extraction and conditional branching (`internal/bypass/statemachine/`)

### High Priority

- [ ] **HTTP Request Smuggling** - CL.TE, TE.CL, TE.TE desync techniques for WAF bypass
- [ ] **Encoder Chain Builder** - User-composable transformation pipelines for custom encoding chains
- [ ] **Attack Surface Discovery** - Hidden parameter and endpoint mining with intelligent fuzzing
- [ ] **Collaborative Bypass Sharing** - Anonymized pattern sharing network for the community
- [ ] **Automated Nuclei Generation** - Generate Nuclei templates from successful bypasses for regression testing
- [ ] **Burp Suite Extension** - Native Burp extension for seamless integration

### Medium Priority

- [ ] **gRPC/Protobuf Support** - WAF bypass techniques for gRPC services
- [ ] **Cache Poisoning Module** - Web cache poisoning payloads and detection
- [ ] **Unicode Normalization Attacks** - NFKC/NFKD bypass techniques exploiting normalization differences
- [ ] **Polyglot Payload Generator** - Multi-context payloads that work across XSS/SQLi/SSTI
- [ ] **WAF Confusion Attacks** - Exploit encoding interpretation differences between WAF and backend
- [ ] **Payload Semantic Equivalence** - Generate functionally identical variants using code analysis
- [ ] **Time-Based Mutation Scheduling** - Vary timing patterns to avoid behavioral detection
- [ ] **Context-Aware Payload Generation** - Analyze target framework for smarter payloads

### Lower Priority

- [ ] **DNS Rebinding Detector** - DNS rebinding vulnerability detection
- [ ] **Real-Time Bypass Intelligence** - Community pattern sharing with reputation system
- [ ] **Semantic Payload Generator** - LLM-powered payload creation based on context analysis
- [ ] **GraphQL-Specific Mutations** - Field aliasing, query batching, introspection tricks
- [ ] **ML Model Extraction Probes** - Probe ML-based WAF decision boundaries
- [ ] **Bypass Chain Visualization** - Interactive mutation tree visualization
- [ ] **CI/CD Integration** - GitHub Actions for WAF regression testing
- [ ] **Burp Collaborator Integration** - Out-of-band bypass detection
- [ ] **API Fuzzing Mode** - Automatic parameter discovery and testing
- [ ] **Rate Limit Evasion** - Techniques to bypass rate limiting
- [ ] **Session Token Rotation** - Automatic session refresh during testing

### Technical Debt

- [ ] Add comprehensive unit tests for all strategies
- [ ] Improve error handling and recovery
- [ ] Add metrics and observability
- [ ] Create plugin development documentation
- [ ] Add configuration validation
- [ ] Add unit tests for oracle, protocol, solver, and statemachine packages
- [ ] Integrate oracle with bypass loop for automatic baseline establishment
- [ ] Add CLI flags for new features (--sequence, --solver, --http2, etc.)

---

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Build
go build -o burrito ./cmd/burrito
```

## Configuration

Default config location: `~/.bypassburrito.yaml`

```yaml
provider:
  name: anthropic
  model: claude-sonnet-4-20250514
  temperature: 0.3

http:
  timeout: 30s
  rate_limit: 5.0
  verify_ssl: true
  protocol:
    prefer_http2: false
    enable_websocket: true
    chunked_evasion: true
    connection_reuse: true

bypass:
  max_iterations: 15
  max_payloads: 30
  detect_waf: true
  strategies:
    enabled:
      - encoding
      - obfuscation
      - fragmentation
      - polymorphic
      - contextual
      - adversarial
      - ssti      # Template injection mutations
      - nosql     # NoSQL injection mutations
  oracle:
    enabled: true
    timing_threshold: 0.3
    content_length_threshold: 0.1
    baseline_samples: 5
    error_fingerprinting: true

learning:
  enabled: true
  store_path: ~/.bypassburrito/learned-patterns.yaml
  auto_save: true

solver:
  enabled: false
  browser_path: ""           # Auto-detect Chrome/Chromium
  headless: true
  captcha_service: ""        # "2captcha" or "anticaptcha"
  captcha_api_key: ""        # Use environment variable
  max_attempts: 3
  timeout_seconds: 60

sequence:
  enabled: false
  path: ~/.bypassburrito/sequences
  default_timeout: 30
```

## Security Considerations

- Never store API keys in code or config files - use environment variables
- Always verify you have authorization before testing
- Be mindful of rate limits to avoid triggering security alerts
- Review generated payloads before using in production environments
