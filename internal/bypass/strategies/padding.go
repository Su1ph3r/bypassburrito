package strategies

import (
	"fmt"
	"strings"
)

// PaddingMutator applies body padding techniques to push payloads past WAF inspection limits
type PaddingMutator struct {
	Sizes []int
}

// NewPaddingMutator creates a new padding mutator with default sizes targeting common WAF limits
func NewPaddingMutator() *PaddingMutator {
	return &PaddingMutator{
		Sizes: []int{8192, 16384, 65536, 131072},
	}
}

// Mutate applies padding mutations to a payload
func (p *PaddingMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	payloadType := detectPayloadType(payload)

	for _, size := range p.Sizes {
		label := sizeLabel(size)

		// Null byte padding — always applies
		results = append(results, MutationResult{
			Payload:     nullBytePad(payload, size),
			Mutation:    fmt.Sprintf("null_byte_pad_%s", label),
			Description: fmt.Sprintf("Prepend %s null bytes to exceed WAF %s inspection limit", label, label),
		})

		// Space padding — always applies
		results = append(results, MutationResult{
			Payload:     spacePad(payload, size),
			Mutation:    fmt.Sprintf("space_pad_%s", label),
			Description: fmt.Sprintf("Prepend %s space characters to exceed WAF %s inspection limit", label, label),
		})

		// SQL comment padding — only for SQL payloads
		if payloadType == "sql" {
			results = append(results, MutationResult{
				Payload:     sqlCommentPad(payload, size),
				Mutation:    fmt.Sprintf("sql_comment_pad_%s", label),
				Description: fmt.Sprintf("Prepend %s SQL comment block to exceed WAF %s inspection limit", label, label),
			})
		}

		// HTML comment padding — only for XSS payloads
		if payloadType == "xss" {
			results = append(results, MutationResult{
				Payload:     htmlCommentPad(payload, size),
				Mutation:    fmt.Sprintf("html_comment_pad_%s", label),
				Description: fmt.Sprintf("Prepend %s HTML comment block to exceed WAF %s inspection limit", label, label),
			})
		}

		// JS comment padding — only for XSS payloads
		if payloadType == "xss" {
			results = append(results, MutationResult{
				Payload:     jsCommentPad(payload, size),
				Mutation:    fmt.Sprintf("js_comment_pad_%s", label),
				Description: fmt.Sprintf("Prepend %s JS comment block to exceed WAF %s inspection limit", label, label),
			})
		}
	}

	// Fixed-size mutations (not per-size)
	results = append(results, MutationResult{
		Payload:     safeParamRepetition(payload),
		Mutation:    "safe_param_repetition",
		Description: "Prepend repeated safe parameters to reach 64k body size and exceed WAF inspection limit",
	})

	results = append(results, MutationResult{
		Payload:     junkQueryPrepend(payload),
		Mutation:    "junk_query_prepend",
		Description: "Prepend unique junk query parameters totaling 64k to exceed WAF inspection limit",
	})

	return results
}

// sizeLabel returns a human-readable label for a byte size (e.g., 8192 -> "8k")
func sizeLabel(size int) string {
	return fmt.Sprintf("%dk", size/1024)
}

// nullBytePad prepends null bytes before the payload to exceed WAF inspection limits
func nullBytePad(payload string, size int) string {
	var b strings.Builder
	b.Grow(size + len(payload))
	for i := 0; i < size; i++ {
		b.WriteByte(0x00)
	}
	b.WriteString(payload)
	return b.String()
}

// spacePad prepends space characters before the payload to exceed WAF inspection limits
func spacePad(payload string, size int) string {
	var b strings.Builder
	b.Grow(size + len(payload))
	for i := 0; i < size; i++ {
		b.WriteByte(' ')
	}
	b.WriteString(payload)
	return b.String()
}

// sqlCommentPad prepends a SQL block comment filled with padding before the payload
func sqlCommentPad(payload string, size int) string {
	// Format: /* + (size-4) bytes of 'A' + */ + payload
	fillSize := size - 4
	if fillSize < 0 {
		fillSize = 0
	}
	var b strings.Builder
	b.Grow(size + len(payload))
	b.WriteString("/*")
	for i := 0; i < fillSize; i++ {
		b.WriteByte('A')
	}
	b.WriteString("*/")
	b.WriteString(payload)
	return b.String()
}

// htmlCommentPad prepends an HTML comment filled with padding before the payload
func htmlCommentPad(payload string, size int) string {
	// Format: <!-- + (size-7) bytes of 'A' + --> + payload
	fillSize := size - 7
	if fillSize < 0 {
		fillSize = 0
	}
	var b strings.Builder
	b.Grow(size + len(payload))
	b.WriteString("<!--")
	for i := 0; i < fillSize; i++ {
		b.WriteByte('A')
	}
	b.WriteString("-->")
	b.WriteString(payload)
	return b.String()
}

// jsCommentPad prepends a JavaScript block comment filled with padding before the payload
func jsCommentPad(payload string, size int) string {
	// Format: /* + (size-4) bytes of 'A' + */ + payload
	fillSize := size - 4
	if fillSize < 0 {
		fillSize = 0
	}
	var b strings.Builder
	b.Grow(size + len(payload))
	b.WriteString("/*")
	for i := 0; i < fillSize; i++ {
		b.WriteByte('A')
	}
	b.WriteString("*/")
	b.WriteString(payload)
	return b.String()
}

// safeParamRepetition prepends repeated safe parameters (a=1&) to reach 65536 bytes
func safeParamRepetition(payload string) string {
	const targetSize = 65536
	param := "a=1&"
	paramLen := len(param)
	repeatCount := targetSize / paramLen

	var b strings.Builder
	b.Grow(targetSize + len(payload))
	for i := 0; i < repeatCount; i++ {
		b.WriteString(param)
	}
	b.WriteString(payload)
	return b.String()
}

// junkQueryPrepend prepends unique junk parameters (~1KB each) to reach 65536 bytes total
func junkQueryPrepend(payload string) string {
	const targetSize = 65536
	const paramValueSize = 1024

	var b strings.Builder
	b.Grow(targetSize + len(payload))

	paramIndex := 1
	written := 0
	for written < targetSize {
		key := fmt.Sprintf("junk%d=", paramIndex)
		// Fill the value portion so total param (key + value + &) is ~1KB
		valueSize := paramValueSize - len(key) - 1 // -1 for '&'
		if valueSize < 1 {
			valueSize = 1
		}

		b.WriteString(key)
		// Use a rotating fill character based on param index for uniqueness
		fillChar := byte('A' + (paramIndex-1)%26)
		for j := 0; j < valueSize; j++ {
			b.WriteByte(fillChar)
		}
		b.WriteByte('&')

		written += len(key) + valueSize + 1
		paramIndex++
	}
	b.WriteString(payload)
	return b.String()
}

// detectPayloadType inspects a payload and returns its likely type
func detectPayloadType(payload string) string {
	lower := strings.ToLower(payload)

	// Check for SQL patterns
	sqlKeywords := []string{"select ", "union ", "insert ", "update ", "delete ", "drop ", " or ", " and "}
	for _, kw := range sqlKeywords {
		if strings.Contains(lower, kw) {
			return "sql"
		}
	}

	// Check for XSS patterns
	xssPatterns := []string{"<script", "<img", "<svg", "onerror", "onload", "alert", "javascript:"}
	for _, pat := range xssPatterns {
		if strings.Contains(lower, pat) {
			return "xss"
		}
	}

	// Check for command injection patterns
	cmdiPatterns := []string{"; ", "| ", "&&", "cat ", "ls ", "whoami", "/etc/", "$("}
	for _, pat := range cmdiPatterns {
		if strings.Contains(lower, pat) {
			return "cmdi"
		}
	}

	return "unknown"
}
