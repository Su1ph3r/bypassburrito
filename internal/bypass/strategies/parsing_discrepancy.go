package strategies

import (
	"fmt"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
)

// ParsingDiscrepancyMutator exploits differences in how WAFs and backend servers parse HTTP
type ParsingDiscrepancyMutator struct{}

// NewParsingDiscrepancyMutator creates a new parsing discrepancy mutator
func NewParsingDiscrepancyMutator() *ParsingDiscrepancyMutator {
	return &ParsingDiscrepancyMutator{}
}

// Mutate applies parsing discrepancy mutations to a payload
func (p *ParsingDiscrepancyMutator) Mutate(payload string) []MutationResult {
	return []MutationResult{
		{
			Payload:     p.charsetEBCDIC(payload),
			Mutation:    "charset_ebcdic_ibm500",
			Description: "EBCDIC IBM Code Page 037 charset encoding",
		},
		{
			Payload:     p.charsetShiftJIS(payload),
			Mutation:    "charset_shift_jis",
			Description: "Shift-JIS charset encoding",
		},
		{
			Payload:     p.charsetUTF16LE(payload),
			Mutation:    "charset_utf16_le",
			Description: "UTF-16 Little Endian with BOM encoding",
		},
		{
			Payload:     p.charsetUTF16BE(payload),
			Mutation:    "charset_utf16_be",
			Description: "UTF-16 Big Endian with BOM encoding",
		},
		{
			Payload:     p.contentTypeMultipartBody(payload),
			Mutation:    "content_type_multipart_body",
			Description: "Payload wrapped in multipart form-data body",
		},
		{
			Payload:     p.duplicateBoundary(payload),
			Mutation:    "duplicate_boundary_param",
			Description: "Duplicate boundary markers with decoy and real payload",
		},
		{
			Payload:     p.rfc2231Boundary(payload),
			Mutation:    "rfc2231_boundary_continuation",
			Description: "RFC 2231 continuation-style parameter encoding",
		},
		{
			Payload:     p.bareLFTerminator(payload),
			Mutation:    "bare_lf_terminator",
			Description: "Bare LF line terminators instead of CRLF",
		},
		{
			Payload:     p.headerExtraWhitespace(payload),
			Mutation:    "header_extra_whitespace",
			Description: "Extra whitespace and tabs at strategic points",
		},
	}
}

// charsetEBCDIC encodes payload bytes using EBCDIC IBM Code Page 037
func (p *ParsingDiscrepancyMutator) charsetEBCDIC(payload string) string {
	encoded, err := charmap.CodePage037.NewEncoder().Bytes([]byte(payload))
	if err != nil {
		return payload
	}
	return fmt.Sprintf("%x", encoded)
}

// charsetShiftJIS encodes payload using Shift-JIS charset
func (p *ParsingDiscrepancyMutator) charsetShiftJIS(payload string) string {
	encoded, err := japanese.ShiftJIS.NewEncoder().Bytes([]byte(payload))
	if err != nil {
		return payload
	}
	return fmt.Sprintf("%x", encoded)
}

// charsetUTF16LE encodes payload as UTF-16 Little Endian with BOM
func (p *ParsingDiscrepancyMutator) charsetUTF16LE(payload string) string {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM)
	encoded, err := enc.NewEncoder().Bytes([]byte(payload))
	if err != nil {
		return payload
	}
	return fmt.Sprintf("%x", encoded)
}

// charsetUTF16BE encodes payload as UTF-16 Big Endian with BOM
func (p *ParsingDiscrepancyMutator) charsetUTF16BE(payload string) string {
	enc := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
	encoded, err := enc.NewEncoder().Bytes([]byte(payload))
	if err != nil {
		return payload
	}
	return fmt.Sprintf("%x", encoded)
}

// contentTypeMultipartBody wraps payload in a multipart form-data body
func (p *ParsingDiscrepancyMutator) contentTypeMultipartBody(payload string) string {
	return fmt.Sprintf(
		"--boundary123\r\nContent-Disposition: form-data; name=\"input\"\r\n\r\n%s\r\n--boundary123--",
		payload,
	)
}

// duplicateBoundary wraps payload with two different boundary markers
func (p *ParsingDiscrepancyMutator) duplicateBoundary(payload string) string {
	return fmt.Sprintf(
		"--boundary1\r\nContent-Disposition: form-data; name=\"decoy\"\r\n\r\nsafe\r\n--boundary1--\r\n--boundary2\r\nContent-Disposition: form-data; name=\"input\"\r\n\r\n%s\r\n--boundary2--",
		payload,
	)
}

// rfc2231Boundary wraps payload with RFC 2231 continuation-style parameter encoding
func (p *ParsingDiscrepancyMutator) rfc2231Boundary(payload string) string {
	return fmt.Sprintf(
		"--bound\r\nContent-Disposition: form-data; name*0=\"inp\"; name*1=\"ut\"\r\n\r\n%s\r\n--bound--",
		payload,
	)
}

// bareLFTerminator replaces CRLF with bare LF, or inserts LF before key characters
func (p *ParsingDiscrepancyMutator) bareLFTerminator(payload string) string {
	if strings.Contains(payload, "\r\n") {
		return strings.ReplaceAll(payload, "\r\n", "\n")
	}
	// Insert \n before key characters that WAFs may use as delimiters
	var result strings.Builder
	for _, r := range payload {
		if r == '<' || r == '\'' || r == '"' {
			result.WriteByte('\n')
		}
		result.WriteRune(r)
	}
	return result.String()
}

// headerExtraWhitespace inserts tabs and extra spaces at strategic points
func (p *ParsingDiscrepancyMutator) headerExtraWhitespace(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		switch r {
		case '=':
			result.WriteString("\t =")
		case '(':
			result.WriteRune(r)
			result.WriteString("\t ")
		case ')':
			result.WriteString(" \t")
			result.WriteRune(r)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}
