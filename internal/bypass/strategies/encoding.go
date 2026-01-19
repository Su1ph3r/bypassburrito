package strategies

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// EncodingMutator applies various encoding techniques
type EncodingMutator struct {
	URL            bool
	DoubleURL      bool
	TripleURL      bool
	Unicode        bool
	OverlongUnicode bool
	HTMLEntity     bool
	Mixed          bool
}

// NewEncodingMutator creates a new encoding mutator with all options enabled
func NewEncodingMutator() *EncodingMutator {
	return &EncodingMutator{
		URL:            true,
		DoubleURL:      true,
		TripleURL:      true,
		Unicode:        true,
		OverlongUnicode: true,
		HTMLEntity:     true,
		Mixed:          true,
	}
}

// Mutate applies encoding mutations to a payload
func (e *EncodingMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	if e.URL {
		results = append(results, MutationResult{
			Payload:     e.URLEncode(payload),
			Mutation:    "url_encode",
			Description: "Standard URL encoding",
		})
	}

	if e.DoubleURL {
		results = append(results, MutationResult{
			Payload:     e.DoubleURLEncode(payload),
			Mutation:    "double_url_encode",
			Description: "Double URL encoding",
		})
	}

	if e.TripleURL {
		results = append(results, MutationResult{
			Payload:     e.TripleURLEncode(payload),
			Mutation:    "triple_url_encode",
			Description: "Triple URL encoding",
		})
	}

	if e.Unicode {
		results = append(results, MutationResult{
			Payload:     e.UnicodeEncode(payload),
			Mutation:    "unicode_encode",
			Description: "Unicode escape encoding",
		})
		results = append(results, MutationResult{
			Payload:     e.UTF16Encode(payload),
			Mutation:    "utf16_encode",
			Description: "UTF-16 encoding",
		})
	}

	if e.OverlongUnicode {
		results = append(results, MutationResult{
			Payload:     e.OverlongUTF8Encode(payload),
			Mutation:    "overlong_utf8",
			Description: "Overlong UTF-8 encoding",
		})
	}

	if e.HTMLEntity {
		results = append(results, MutationResult{
			Payload:     e.HTMLEntityEncode(payload),
			Mutation:    "html_entity_decimal",
			Description: "HTML decimal entity encoding",
		})
		results = append(results, MutationResult{
			Payload:     e.HTMLEntityHexEncode(payload),
			Mutation:    "html_entity_hex",
			Description: "HTML hex entity encoding",
		})
		results = append(results, MutationResult{
			Payload:     e.HTMLEntityNamedEncode(payload),
			Mutation:    "html_entity_named",
			Description: "HTML named entity encoding",
		})
	}

	if e.Mixed {
		results = append(results, MutationResult{
			Payload:     e.MixedEncode(payload),
			Mutation:    "mixed_encoding",
			Description: "Mixed encoding techniques",
		})
	}

	return results
}

// URLEncode performs standard URL encoding
func (e *EncodingMutator) URLEncode(s string) string {
	return url.QueryEscape(s)
}

// DoubleURLEncode performs double URL encoding
func (e *EncodingMutator) DoubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

// TripleURLEncode performs triple URL encoding
func (e *EncodingMutator) TripleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(url.QueryEscape(s)))
}

// UnicodeEncode converts to \uXXXX format
func (e *EncodingMutator) UnicodeEncode(s string) string {
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

// UTF16Encode converts to %uXXXX format
func (e *EncodingMutator) UTF16Encode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("%%u%04x", r))
	}
	return result.String()
}

// OverlongUTF8Encode creates overlong UTF-8 sequences
func (e *EncodingMutator) OverlongUTF8Encode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			// Create overlong 2-byte sequence for ASCII
			// Normal: 0xxxxxxx
			// Overlong: 110000xx 10xxxxxx
			b1 := 0xC0 | ((byte(r) >> 6) & 0x1F)
			b2 := 0x80 | (byte(r) & 0x3F)
			result.WriteString(fmt.Sprintf("%%%02X%%%02X", b1, b2))
		} else {
			// Keep non-ASCII as-is or use standard encoding
			buf := make([]byte, 4)
			n := utf8.EncodeRune(buf, r)
			for i := 0; i < n; i++ {
				result.WriteString(fmt.Sprintf("%%%02X", buf[i]))
			}
		}
	}
	return result.String()
}

// HTMLEntityEncode converts to decimal HTML entities
func (e *EncodingMutator) HTMLEntityEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

// HTMLEntityHexEncode converts to hex HTML entities
func (e *EncodingMutator) HTMLEntityHexEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#x%x;", r))
	}
	return result.String()
}

// HTMLEntityNamedEncode converts common chars to named entities
func (e *EncodingMutator) HTMLEntityNamedEncode(s string) string {
	namedEntities := map[rune]string{
		'<':  "&lt;",
		'>':  "&gt;",
		'"':  "&quot;",
		'\'': "&apos;",
		'&':  "&amp;",
		' ':  "&nbsp;",
	}

	var result strings.Builder
	for _, r := range s {
		if named, ok := namedEntities[r]; ok {
			result.WriteString(named)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// MixedEncode applies mixed encoding (alternating techniques)
func (e *EncodingMutator) MixedEncode(s string) string {
	var result strings.Builder
	for i, r := range s {
		switch i % 4 {
		case 0:
			result.WriteString(url.QueryEscape(string(r)))
		case 1:
			result.WriteString(fmt.Sprintf("&#%d;", r))
		case 2:
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		case 3:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// HexEncode converts to hex representation
func (e *EncodingMutator) HexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

// Base64Encode is available for completeness but usually not useful for WAF bypass
// as most WAFs decode base64 automatically

// PartialEncode encodes only specific characters
func (e *EncodingMutator) PartialEncode(s string, chars string) string {
	charsToEncode := make(map[rune]bool)
	for _, c := range chars {
		charsToEncode[c] = true
	}

	var result strings.Builder
	for _, r := range s {
		if charsToEncode[r] {
			result.WriteString(url.QueryEscape(string(r)))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// SelectiveEncode encodes only dangerous characters
func (e *EncodingMutator) SelectiveEncode(s string) string {
	dangerous := "'\"<>()[];=&|`$"
	return e.PartialEncode(s, dangerous)
}
