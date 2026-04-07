# BypassBurrito

Feeds your blocked payloads through an LLM to generate WAF bypass variants.

## How it works

You give it a payload and a target. The LLM mutates it using encoding, obfuscation, fragmentation, and protocol-level tricks until something gets past the WAF. Rinse, repeat, evolve.

## Install

```bash
git clone https://github.com/su1ph3r/bypassburrito.git
cd bypassburrito
go build -o burrito ./cmd/burrito/
```

Requires Go 1.23+ and an LLM API key (or a local model via Ollama/LM Studio).

## Usage

```bash
# Basic SQLi bypass
burrito bypass -u "https://target.com/api" --param id --type sqli

# Feed payloads from a file
burrito bypass -u "https://target.com/api" --param id --payload-file payloads.txt

# Target a specific WAF
burrito bypass -u "https://target.com/api" --param id --type xss --waf-type cloudflare

# Output as markdown report or Nuclei templates
burrito bypass -u "https://target.com/api" --param id --type sqli -f markdown -o report.md
burrito bypass -u "https://target.com/api" --param id --type xss -f nuclei -o templates/
```

## Supported WAFs

Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, F5 BIG-IP, Sucuri, Wordfence, Fortinet, Barracuda, Citrix, Palo Alto, Radware.

## Mutation strategies

- **Encoding** — URL, Unicode, HTML entities, overlong UTF-8, mixed
- **Obfuscation** — comment injection, case randomization, whitespace tricks
- **Fragmentation** — payload splitting, chunked encoding, parameter pollution
- **Polymorphic** — structurally different but semantically equivalent rewrites
- **Contextual** — HTTP context-aware mutations (JSON, XML, form data)
- **Adversarial ML** — homoglyphs, invisible characters, bidi overrides
- **SSTI** — Jinja2, Twig, Freemarker template injection mutations
- **NoSQL** — MongoDB/CouchDB operator obfuscation

## LLM providers

Set one of these and go:

```bash
export ANTHROPIC_API_KEY="..."   # Claude
export OPENAI_API_KEY="..."      # GPT-4o
export GROQ_API_KEY="..."        # Llama 3.1 70B
# Or use --provider ollama for local models
```

## Burp integration

Start the server with `burrito serve`, then load `burp-extension/target/bypassburrito-burp-1.0.0.jar` in Burp Suite Pro. Right-click any request and hit "Send to BypassBurrito" — results stream back in real time.

## License

[MIT](LICENSE)
