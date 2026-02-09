# Changelog

All notable changes to BypassBurrito will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-09

### Added

#### Cross-Tool Integration
- `--from-indago` flag on the `bypass` command for importing WAF-blocked findings from Indago
- Auto-detection of attack types from Indago WAF-blocked export format
- Multi-target warning when processing multiple blocked endpoints
- `cmd.Flags().Changed("type")` check replacing magic string comparison

## [0.2.0] - 2026-01-28

### Added
- Initial release
- Multi-provider LLM support (Anthropic, OpenAI, Groq, Ollama, LM Studio)
- Ensemble mode for multi-model consensus
- Intelligent WAF detection for 12+ vendors
- 8 mutation strategy types including SSTI and NoSQL
- Response oracle analysis (timing, differential, fingerprinting)
- Protocol-level evasion (HTTP/2, WebSocket, chunked encoding)
- JavaScript challenge solver with CAPTCHA integration
- Multi-request state machine for attack sequences
- Learning system with pattern persistence and genetic evolution
- Payload minimization with delta debugging
- WAF rule inference engine
- Plugin SDK for custom mutations
- Burp Suite Pro extension
- Multiple output formats (JSON, Markdown, HTML, Burp XML, Nuclei, Curl)

[Unreleased]: https://github.com/Su1ph3r/bypassburrito/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Su1ph3r/bypassburrito/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/bypassburrito/releases/tag/v0.2.0
