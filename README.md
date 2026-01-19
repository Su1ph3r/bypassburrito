# BypassBurrito 🌯

**Wrap Around Any WAF** - An LLM-powered Web Application Firewall bypass generator for authorized penetration testing.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

BypassBurrito uses Large Language Models to intelligently generate WAF bypass payloads through iterative mutation strategies. It analyzes WAF responses, understands blocking patterns, and evolves payloads to evade detection while maintaining attack functionality.

```
  ____                              ____                  _ _
 | __ ) _   _ _ __   __ _ ___ ___  | __ ) _   _ _ __ _ __(_) |_ ___
 |  _ \| | | | '_ \ / _` / __/ __| |  _ \| | | | '__| '__| | __/ _ \
 | |_) | |_| | |_) | (_| \__ \__ \ | |_) | |_| | |  | |  | | || (_) |
 |____/ \__, | .__/ \__,_|___/___/ |____/ \__,_|_|  |_|  |_|\__\___/
        |___/|_|                                             🌯
```

## Features

### Multi-Provider LLM Support
- **Anthropic Claude** - Claude 3.5 Sonnet/Opus for sophisticated analysis
- **OpenAI GPT** - GPT-4o for versatile bypass generation
- **Groq** - Fast inference with Llama 3.1 70B
- **Ollama** - Local model support for privacy
- **LM Studio** - Local model integration
- **Ensemble Mode** - Combine multiple models for consensus-based bypasses

### Intelligent WAF Detection
- **Signature-based detection** for 12+ WAF vendors (Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, F5, Sucuri, etc.)
- **Behavioral analysis** - Timing patterns, rate limits, response fingerprinting
- **OWASP CRS detection** - Identify ModSecurity Core Rule Set configurations
- **Confidence scoring** - Bayesian probability of WAF identification

### Advanced Mutation Strategies
- **Encoding** - URL, Unicode, HTML entities, mixed encodings, overlong UTF-8
- **Obfuscation** - Comment injection, case randomization, whitespace manipulation
- **Fragmentation** - Payload splitting, chunked encoding, parameter pollution
- **Polymorphic** - Semantically equivalent but structurally different payloads
- **Contextual** - HTTP context-aware mutations (JSON, XML, form data)
- **Adversarial ML** - Homoglyphs, invisible characters, bidirectional overrides

### Learning System
- **Pattern persistence** - Store successful bypasses for future use
- **Success rate tracking** - Rank mutations by effectiveness per WAF
- **Genetic evolution** - Evolve bypass patterns over time
- **Team sharing** - Export/import learned patterns

### Burp Suite Pro Integration
- **Native extension** - Full Burp Suite Pro integration via companion extension
- **Right-click bypass** - Send any request for bypass testing
- **Real-time streaming** - WebSocket updates during bypass attempts
- **Issue reporting** - Bypasses reported as Burp Scanner findings

### Multiple Output Formats
- **JSON** - Machine-readable results
- **Markdown** - Human-readable reports
- **HTML** - Interactive web reports
- **Burp XML** - Import findings into Burp
- **Nuclei** - Generate Nuclei templates from successful bypasses
- **Curl** - Reproducible curl commands

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/su1ph3r/bypassburrito.git
cd bypassburrito

# Build
go build -o burrito ./cmd/wafex/

# Or install globally
go install ./cmd/wafex/
```

### Requirements

- Go 1.23 or later
- LLM API key (Anthropic, OpenAI, or Groq) OR local model (Ollama/LM Studio)

## Quick Start

### 1. Set up your API key

```bash
# For Anthropic (recommended)
export ANTHROPIC_API_KEY="your-key-here"

# Or for OpenAI
export OPENAI_API_KEY="your-key-here"

# Or for Groq
export GROQ_API_KEY="your-key-here"
```

### 2. Detect WAF

```bash
burrito detect -u "https://target.com"

# Deep analysis with behavioral profiling
burrito detect -u "https://target.com" --deep
```

### 3. Generate Bypasses

```bash
# SQLi bypass
burrito bypass -u "https://target.com/api" --param id --type sqli

# XSS bypass with proxy (for Burp)
burrito bypass -u "https://target.com/search" --param q --type xss \
  --proxy http://127.0.0.1:8080

# Multiple attack types
burrito bypass -u "https://target.com/api" --param input --type sqli,xss

# Custom payload
burrito bypass -u "https://target.com/api" --param id \
  --payload "' OR 1=1--"
```

## Usage

### Bypass Command

```bash
burrito bypass [flags]

Target:
  -u, --url string              Target URL (required)
  -m, --method string           HTTP method (default: GET)
  -d, --data string             Request body
  -H, --header strings          Custom headers
      --param string            Target parameter (required)
      --position string         Parameter position: query, body, header, cookie

Attack:
  -t, --type string             Attack type: xss, sqli, cmdi, path_traversal, ssti, xxe
  -P, --payload string          Custom payload
      --payload-file string     File with payloads

Engine:
      --max-iterations int      Max iterations per payload (default: 15)
      --max-payloads int        Max base payloads (default: 30)
      --detect-waf              Auto-detect WAF (default: true)
      --use-learned             Use learned patterns (default: true)
      --evolve                  Enable genetic evolution

LLM:
  -p, --provider string         LLM provider: anthropic, openai, ollama, groq
      --model string            Model name
      --ensemble                Use multi-model ensemble

HTTP:
      --proxy string            HTTP proxy URL
      --rate-limit float        Requests/second (default: 5)
      --timeout duration        Request timeout (default: 30s)

Output:
  -o, --output string           Output file
  -f, --format string           Format: json, markdown, html, burp, nuclei
      --show-all                Show all attempts
      --curl                    Generate curl commands
```

### Detect Command

```bash
burrito detect [flags]

  -u, --url string          Target URL (required)
      --deep                Deep behavioral analysis
      --probe-payloads      Use payloads to trigger WAF (default: true)
      --identify-ruleset    Identify WAF ruleset (OWASP CRS)
  -o, --output string       Output file
  -f, --format string       Format: json, text, markdown
```

### Server Mode (Burp Integration)

```bash
burrito serve [flags]

      --port int              Server port (default: 8089)
      --host string           Host to bind (default: localhost)
      --cors                  Enable CORS (default: true)
      --auth-token string     Require auth token
      --max-concurrent int    Max concurrent operations (default: 5)
      --websocket             Enable WebSocket (default: true)
```

## Burp Suite Extension

BypassBurrito includes a native Burp Suite Pro extension for seamless integration.

### Building the Extension

```bash
cd burp-extension
mvn clean package
# Output: target/bypassburrito-burp-1.0.0.jar
```

### Installation

1. Start the BypassBurrito server: `burrito serve`
2. In Burp Suite: Extensions → Add → Select JAR file
3. Configure server URL in the BypassBurrito tab

### Features

- Right-click "Send to BypassBurrito" on any request
- Quick bypass options for SQLi, XSS, CMDi, Path Traversal
- WAF detection from context menu
- Real-time results in dedicated tab
- Automatic Burp Scanner issue reporting

See [burp-extension/README.md](burp-extension/README.md) for full documentation.

## Supported WAFs

| WAF | Detection | Evasion Profile |
|-----|-----------|-----------------|
| Cloudflare | ✅ | ✅ |
| ModSecurity | ✅ | ✅ |
| AWS WAF | ✅ | ✅ |
| Akamai | ✅ | ✅ |
| Imperva/Incapsula | ✅ | ✅ |
| F5 BIG-IP | ✅ | ✅ |
| Sucuri | ✅ | ✅ |
| Wordfence | ✅ | ✅ |
| Fortinet | ✅ | ✅ |
| Barracuda | ✅ | ✅ |
| Citrix | ✅ | ✅ |
| Palo Alto | ✅ | ✅ |
| Radware | ✅ | ✅ |

## Supported Attack Types

| Type | Description |
|------|-------------|
| `sqli` | SQL Injection (Union, Boolean Blind, Time Blind, Error-based) |
| `xss` | Cross-Site Scripting (Reflected, Stored, DOM) |
| `cmdi` | Command Injection (Unix, Windows) |
| `path_traversal` | Path/Directory Traversal |
| `ssti` | Server-Side Template Injection |
| `xxe` | XML External Entity |

## Configuration

Configuration file: `~/.bypassburrito.yaml`

```yaml
provider:
  name: anthropic
  model: claude-sonnet-4-20250514
  temperature: 0.3

http:
  timeout: 30s
  rate_limit: 5.0
  proxy_url: ""

bypass:
  max_iterations: 15
  max_payloads: 30
  detect_waf: true
  use_learned: true
  strategies:
    enabled:
      - encoding
      - obfuscation
      - fragmentation
      - polymorphic
      - contextual
      - adversarial

learning:
  enabled: true
  store_path: ~/.bypassburrito/learned-patterns.yaml
  auto_save: true

output:
  format: text
  color: true
  show_all_attempts: false
```

## Examples

### Basic SQLi Bypass

```bash
burrito bypass -u "https://shop.example.com/product" \
  --param id --type sqli
```

### XSS with Burp Proxy

```bash
burrito bypass -u "https://app.example.com/search" \
  --param q --type xss \
  --proxy http://127.0.0.1:8080 \
  --show-all
```

### Deep WAF Analysis + Targeted Bypass

```bash
# First, analyze the WAF
burrito detect -u "https://target.com" --deep -o waf-report.json

# Then bypass with specific WAF type
burrito bypass -u "https://target.com/api" \
  --param query --type sqli \
  --waf-type cloudflare \
  --use-learned --evolve \
  -f markdown -o report.md
```

### Generate Nuclei Templates

```bash
burrito bypass -u "https://target.com/vuln" \
  --param input --type xss \
  -f nuclei -o templates/
```

### Ensemble Mode (Multiple LLMs)

```bash
burrito bypass -u "https://critical-target.com/api" \
  --param data --type sqli \
  --ensemble \
  --max-iterations 25
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           BypassBurrito                              │
├─────────────────────────────────────────────────────────────────────┤
│  CLI (Cobra)                                                        │
│  ├── bypass     - Generate WAF bypasses                             │
│  ├── detect     - WAF detection & fingerprinting                    │
│  └── serve      - Server mode for Burp integration                  │
├─────────────────────────────────────────────────────────────────────┤
│  Core Engine                                                        │
│  ├── LLM Providers    - Anthropic, OpenAI, Groq, Ollama, LM Studio │
│  ├── WAF Detector     - Signature + behavioral analysis             │
│  ├── Mutation Engine  - 6 strategy types, multi-stage chains        │
│  ├── Learning System  - Pattern storage, ranking, evolution         │
│  └── HTTP Client      - Rate limiting, retries, session management  │
├─────────────────────────────────────────────────────────────────────┤
│  Output                                                             │
│  └── Reporters        - JSON, Markdown, HTML, Burp XML, Nuclei      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                          REST API / WebSocket
                                    │
┌───────────────────────────────────┴───────────────────────────────┐
│                    Burp Suite Pro Extension                        │
│  ├── Context Menu    - Right-click integration                     │
│  ├── Custom Tab      - Results, queue, configuration               │
│  └── Issue Reporter  - Scanner findings                            │
└────────────────────────────────────────────────────────────────────┘
```

## Legal Disclaimer

BypassBurrito is designed for **authorized security testing only**.

- Only use on systems you have explicit permission to test
- Obtain written authorization before testing
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

The authors are not responsible for misuse of this tool.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by various WAF bypass research and tools
- Built with [Cobra](https://github.com/spf13/cobra) and [Viper](https://github.com/spf13/viper)
- Burp extension uses the [Montoya API](https://portswigger.net/burp/documentation/desktop/extensions/creating)
