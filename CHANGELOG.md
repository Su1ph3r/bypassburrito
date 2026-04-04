# Changelog

All notable changes to BypassBurrito will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-04-04

### Added

#### New Mutation Strategies (opt-in)
- `parsing_discrepancy` strategy: charset confusion (EBCDIC, Shift_JIS, UTF-16), multipart boundary tricks, RFC 2231 continuation, bare LF terminators
- `padding` strategy: body padding to exceed WAF inspection limits (8KB/16KB/64KB/128KB targets for AWS WAF, Cloud Armor, CloudFront, Azure)
- `path_traversal` strategy: fullwidth Unicode dots/slashes, overlong UTF-8, duplication bypass, Tomcat semicolon, mixed slashes, double encoding

#### Enhanced Polymorphic Mutations (+12)
- JSON-in-SQL injection: `JSON_EXTRACT`, `JSON_VALID`, PostgreSQL JSONB operators (`@>`, `->>`)
- XSS: HTML5 Popover API (`onbeforetoggle`), SVG payloads, uncommon event handlers (`onauxclick`, `ontouchstart`, `onpointerover`), mutation XSS (mXSS)
- Command injection: `$IFS` separator, wildcard/glob abuse (`/???/??t`), variable expansion, brace expansion, base64 pipe, hex/octal encoding

#### Enhanced Protocol Evasion
- Chunked encoding: chunk extensions, CL.TE/TE.CL/TE.TE HTTP smuggling variants, Transfer-Encoding obfuscation (tab, space, mixed case)
- Differentiated CL.TE vs TE.CL wire formats (header ordering and Content-Length calculation)
- Configurable `PaddingConfig` with custom padding sizes via config file

### Fixed

#### Critical
- Panic on empty `Payloads` slice in `BypassLoop.Run()` — now returns descriptive error
- Nil pointer dereference in `ResponseAnalyzer.Analyze()` when response is nil
- `PayloadLibrary.LoadFromDirectory()` always panicked (`fs.ReadFile(nil)`) — fixed to use `os.ReadFile`
- Data race in `Store.Save()`: wrote `dirty` field under read lock — upgraded to write lock
- Data race in `RateLimiter`: `SetRate()`/`Wait()`/`Allow()` unsynchronized — added `sync.RWMutex`

#### Security
- Shell injection in `GenerateCurlCommand` via unescaped single quotes in headers/body/URL
- TLS certificate verification hardcoded to skip in `ChunkedClient` and `HTTP2Client` — now configurable

#### Bugs
- WAF detection confidence could exceed 1.0 due to status code bonus not included in denominator
- HTTP status code silently set to 0 on parse failure in chunked response reader
- Connection dial errors returned as successful responses with error string in body
- Chunk extensions in responses broke hex size parsing (`readChunkedBody`)
- Division by zero in timing oracle when all latency samples are zero
- `MinimizeMultiple` silently returned empty results with nil error when all payloads failed
- Unbounded `io.ReadAll` on HTTP response bodies — capped at 10MB
- Dead code removed from `mysqlCHAR` in fragmentation strategy

#### Concurrency
- Data race on `DefaultOracle.baselines` slice — added `sync.RWMutex`
- Data race on `ContentLengthAnalyzer.history` slice — added `sync.RWMutex`
- `JobStatus` serialized after releasing read lock in `handleGetBypass` — now copies under lock
- WebSocket subscriber blocked forever if job already completed — now sends final status immediately
- Goroutine leak in `CachedProvider.cleanupLoop` — added `Close()` method with done channel
- Auto-save goroutine errors silently lost — now logged to stderr

#### Unicode/Multi-byte
- Systemic byte-vs-rune bugs across 15 functions in 4 strategy files (obfuscation, fragmentation, adversarial, polymorphic) — all converted to rune-safe iteration
- `mysqlCHAR` produced invalid MySQL CHAR codes for multi-byte runes — fixed to use byte-level encoding

#### Observability
- WAF detection errors now emit `waf_detection_error` event instead of being silently swallowed
- LLM fallback now emits `llm_fallback` event with error details

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

[Unreleased]: https://github.com/Su1ph3r/bypassburrito/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Su1ph3r/bypassburrito/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Su1ph3r/bypassburrito/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/bypassburrito/releases/tag/v0.2.0
