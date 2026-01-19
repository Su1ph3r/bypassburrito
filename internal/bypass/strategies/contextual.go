package strategies

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// ContextualMutator applies mutations based on HTTP context
type ContextualMutator struct {
	Context HTTPContext
}

// HTTPContext holds information about the HTTP context
type HTTPContext struct {
	Position    types.ParameterPosition
	ContentType string
	Method      string
	Encoding    string
}

// NewContextualMutator creates a new contextual mutator
func NewContextualMutator() *ContextualMutator {
	return &ContextualMutator{
		Context: HTTPContext{
			Position:    types.PositionQuery,
			ContentType: "application/x-www-form-urlencoded",
			Method:      "GET",
			Encoding:    "UTF-8",
		},
	}
}

// WithContext sets the HTTP context
func (c *ContextualMutator) WithContext(ctx HTTPContext) *ContextualMutator {
	c.Context = ctx
	return c
}

// Mutate applies context-aware mutations
func (c *ContextualMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	switch c.Context.Position {
	case types.PositionQuery:
		results = append(results, c.queryMutations(payload)...)
	case types.PositionBody:
		results = append(results, c.bodyMutations(payload)...)
	case types.PositionHeader:
		results = append(results, c.headerMutations(payload)...)
	case types.PositionCookie:
		results = append(results, c.cookieMutations(payload)...)
	case types.PositionPath:
		results = append(results, c.pathMutations(payload)...)
	default:
		// Apply general mutations
		results = append(results, c.queryMutations(payload)...)
	}

	return results
}

// queryMutations applies mutations for query string parameters
func (c *ContextualMutator) queryMutations(payload string) []MutationResult {
	var results []MutationResult

	// Standard URL encoding is natural for query strings
	results = append(results, MutationResult{
		Payload:     url.QueryEscape(payload),
		Mutation:    "query_url_encode",
		Description: "URL encoding for query string",
	})

	// Double URL encoding
	results = append(results, MutationResult{
		Payload:     url.QueryEscape(url.QueryEscape(payload)),
		Mutation:    "query_double_url_encode",
		Description: "Double URL encoding for query string",
	})

	// Plus sign encoding (+ for space)
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, " ", "+"),
		Mutation:    "query_plus_space",
		Description: "Plus sign for spaces",
	})

	// Parameter pollution - duplicate parameter
	results = append(results, MutationResult{
		Payload:     payload + "&param=" + payload,
		Mutation:    "query_param_pollution",
		Description: "HTTP parameter pollution",
	})

	// Array notation
	results = append(results, MutationResult{
		Payload:     payload + "&param[]=" + payload,
		Mutation:    "query_array_notation",
		Description: "Array parameter notation",
	})

	return results
}

// bodyMutations applies mutations for request body
func (c *ContextualMutator) bodyMutations(payload string) []MutationResult {
	var results []MutationResult

	switch c.Context.ContentType {
	case "application/json":
		results = append(results, c.jsonMutations(payload)...)
	case "application/xml", "text/xml":
		results = append(results, c.xmlMutations(payload)...)
	case "multipart/form-data":
		results = append(results, c.multipartMutations(payload)...)
	default:
		// application/x-www-form-urlencoded
		results = append(results, c.formMutations(payload)...)
	}

	return results
}

// jsonMutations applies mutations for JSON bodies
func (c *ContextualMutator) jsonMutations(payload string) []MutationResult {
	var results []MutationResult

	// JSON Unicode escaping
	results = append(results, MutationResult{
		Payload:     c.jsonUnicodeEscape(payload),
		Mutation:    "json_unicode_escape",
		Description: "JSON Unicode escape sequences",
	})

	// JSON string escaping
	escaped, _ := json.Marshal(payload)
	results = append(results, MutationResult{
		Payload:     string(escaped),
		Mutation:    "json_escape",
		Description: "JSON string escaping",
	})

	// Nested JSON
	results = append(results, MutationResult{
		Payload:     `{"nested":{"value":"` + payload + `"}}`,
		Mutation:    "json_nested",
		Description: "Nested JSON structure",
	})

	// JSON array
	results = append(results, MutationResult{
		Payload:     `["` + payload + `"]`,
		Mutation:    "json_array",
		Description: "JSON array wrapper",
	})

	// JSON with extra properties
	results = append(results, MutationResult{
		Payload:     `{"value":"` + payload + `","extra":"data","more":"fields"}`,
		Mutation:    "json_extra_props",
		Description: "JSON with extra properties",
	})

	return results
}

// jsonUnicodeEscape converts characters to \uXXXX format
func (c *ContextualMutator) jsonUnicodeEscape(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			result.WriteString(fmt.Sprintf("\\u00%02x", r))
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

// xmlMutations applies mutations for XML bodies
func (c *ContextualMutator) xmlMutations(payload string) []MutationResult {
	var results []MutationResult

	// XML entity encoding
	results = append(results, MutationResult{
		Payload:     c.xmlEntityEncode(payload),
		Mutation:    "xml_entity_encode",
		Description: "XML entity encoding",
	})

	// CDATA wrapper
	results = append(results, MutationResult{
		Payload:     "<![CDATA[" + payload + "]]>",
		Mutation:    "xml_cdata",
		Description: "CDATA section wrapper",
	})

	// XML comments
	results = append(results, MutationResult{
		Payload:     "<!--" + payload + "-->",
		Mutation:    "xml_comment",
		Description: "XML comment wrapper",
	})

	// Processing instruction
	results = append(results, MutationResult{
		Payload:     "<?" + payload + "?>",
		Mutation:    "xml_pi",
		Description: "XML processing instruction",
	})

	// Numeric character references
	results = append(results, MutationResult{
		Payload:     c.xmlNumericEncode(payload),
		Mutation:    "xml_numeric_encode",
		Description: "XML numeric character references",
	})

	return results
}

// xmlEntityEncode encodes special XML characters
func (c *ContextualMutator) xmlEntityEncode(s string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
		"'", "&apos;",
		"\"", "&quot;",
	)
	return replacer.Replace(s)
}

// xmlNumericEncode converts to numeric character references
func (c *ContextualMutator) xmlNumericEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

// multipartMutations applies mutations for multipart form data
func (c *ContextualMutator) multipartMutations(payload string) []MutationResult {
	var results []MutationResult

	// Boundary manipulation
	results = append(results, MutationResult{
		Payload:     payload,
		Mutation:    "multipart_boundary_space",
		Description: "Multipart boundary with spaces",
	})

	// Filename injection
	results = append(results, MutationResult{
		Payload:     payload + `"; filename="` + payload,
		Mutation:    "multipart_filename_inject",
		Description: "Filename field injection",
	})

	// Content-Type manipulation
	results = append(results, MutationResult{
		Payload:     payload,
		Mutation:    "multipart_content_type",
		Description: "Content-Type manipulation",
	})

	return results
}

// formMutations applies mutations for form-urlencoded data
func (c *ContextualMutator) formMutations(payload string) []MutationResult {
	var results []MutationResult

	results = append(results, MutationResult{
		Payload:     url.QueryEscape(payload),
		Mutation:    "form_url_encode",
		Description: "URL encoding for form data",
	})

	// Plus encoding
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, " ", "+"),
		Mutation:    "form_plus_encode",
		Description: "Plus encoding for spaces",
	})

	// Mixed encoding
	results = append(results, MutationResult{
		Payload:     c.mixedFormEncode(payload),
		Mutation:    "form_mixed_encode",
		Description: "Mixed form encoding",
	})

	return results
}

// mixedFormEncode applies mixed encoding
func (c *ContextualMutator) mixedFormEncode(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			result.WriteString(url.QueryEscape(string(r)))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// headerMutations applies mutations for HTTP headers
func (c *ContextualMutator) headerMutations(payload string) []MutationResult {
	var results []MutationResult

	// Headers have limited charset - remove newlines
	safe := strings.ReplaceAll(payload, "\n", "")
	safe = strings.ReplaceAll(safe, "\r", "")

	results = append(results, MutationResult{
		Payload:     safe,
		Mutation:    "header_safe",
		Description: "Header-safe encoding",
	})

	// Tab substitution
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(safe, " ", "\t"),
		Mutation:    "header_tab",
		Description: "Tab substitution in header",
	})

	// Header folding (RFC 7230 deprecated but may work)
	results = append(results, MutationResult{
		Payload:     " " + safe,
		Mutation:    "header_folding",
		Description: "Header line folding",
	})

	return results
}

// cookieMutations applies mutations for cookies
func (c *ContextualMutator) cookieMutations(payload string) []MutationResult {
	var results []MutationResult

	// Cookie encoding rules
	results = append(results, MutationResult{
		Payload:     url.QueryEscape(payload),
		Mutation:    "cookie_encode",
		Description: "Cookie-safe encoding",
	})

	// Remove semicolons and equals
	safe := strings.ReplaceAll(payload, ";", "%3B")
	safe = strings.ReplaceAll(safe, "=", "%3D")
	results = append(results, MutationResult{
		Payload:     safe,
		Mutation:    "cookie_safe",
		Description: "Cookie special char encoding",
	})

	return results
}

// pathMutations applies mutations for URL path
func (c *ContextualMutator) pathMutations(payload string) []MutationResult {
	var results []MutationResult

	// Path encoding
	results = append(results, MutationResult{
		Payload:     url.PathEscape(payload),
		Mutation:    "path_encode",
		Description: "URL path encoding",
	})

	// Double encoding
	results = append(results, MutationResult{
		Payload:     url.PathEscape(url.PathEscape(payload)),
		Mutation:    "path_double_encode",
		Description: "Double path encoding",
	})

	// Dot-dot-slash variations
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, "../", "..%2F"),
		Mutation:    "path_dotdot_encode",
		Description: "Encoded dot-dot-slash",
	})

	// Backslash substitution
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, "/", "\\"),
		Mutation:    "path_backslash",
		Description: "Backslash path separator",
	})

	return results
}
