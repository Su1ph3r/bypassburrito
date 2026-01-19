package strategies

import (
	"strings"
)

// FragmentationMutator splits payloads across multiple parts
type FragmentationMutator struct {
	ChunkSize        int
	UseBoundary      bool
	UseParameterPollution bool
}

// NewFragmentationMutator creates a new fragmentation mutator
func NewFragmentationMutator() *FragmentationMutator {
	return &FragmentationMutator{
		ChunkSize:             5,
		UseBoundary:           true,
		UseParameterPollution: true,
	}
}

// Mutate applies fragmentation mutations to a payload
func (f *FragmentationMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	// SQL comment boundary fragmentation
	if f.UseBoundary {
		results = append(results, MutationResult{
			Payload:     f.FragmentWithSQLComments(payload, 3),
			Mutation:    "sql_comment_fragmentation",
			Description: "Fragment payload with SQL comments",
		})
		results = append(results, MutationResult{
			Payload:     f.FragmentWithSQLComments(payload, 2),
			Mutation:    "sql_comment_fragmentation_small",
			Description: "Fragment payload with smaller SQL comment chunks",
		})
	}

	// Chunk-based fragmentation
	results = append(results, MutationResult{
		Payload:     f.ChunkPayload(payload, f.ChunkSize),
		Mutation:    "chunk_fragmentation",
		Description: "Fragment into fixed-size chunks",
	})

	// Concatenation-based fragmentation (for different SQL dialects)
	results = append(results, MutationResult{
		Payload:     f.FragmentWithConcat(payload, "mysql"),
		Mutation:    "mysql_concat_fragmentation",
		Description: "Fragment using MySQL CONCAT()",
	})
	results = append(results, MutationResult{
		Payload:     f.FragmentWithConcat(payload, "mssql"),
		Mutation:    "mssql_concat_fragmentation",
		Description: "Fragment using MSSQL + concatenation",
	})
	results = append(results, MutationResult{
		Payload:     f.FragmentWithConcat(payload, "oracle"),
		Mutation:    "oracle_concat_fragmentation",
		Description: "Fragment using Oracle || concatenation",
	})

	// CHAR-based fragmentation
	results = append(results, MutationResult{
		Payload:     f.FragmentWithCHAR(payload, "mysql"),
		Mutation:    "mysql_char_fragmentation",
		Description: "Fragment using MySQL CHAR()",
	})
	results = append(results, MutationResult{
		Payload:     f.FragmentWithCHAR(payload, "mssql"),
		Mutation:    "mssql_char_fragmentation",
		Description: "Fragment using MSSQL CHAR()",
	})

	return results
}

// FragmentWithSQLComments splits payload using SQL comments
func (f *FragmentationMutator) FragmentWithSQLComments(payload string, chunkSize int) string {
	if len(payload) <= chunkSize {
		return payload
	}

	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		if i > 0 && i < len(payload)-1 && (i+1)%chunkSize == 0 {
			result.WriteString("/**/")
		}
	}
	return result.String()
}

// ChunkPayload splits payload into chunks
func (f *FragmentationMutator) ChunkPayload(payload string, chunkSize int) string {
	if len(payload) <= chunkSize {
		return payload
	}

	var chunks []string
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}
	return strings.Join(chunks, "/**/")
}

// FragmentWithConcat creates concatenation-based fragments
func (f *FragmentationMutator) FragmentWithConcat(payload string, dialect string) string {
	if len(payload) < 4 {
		return payload
	}

	// Split into parts
	parts := f.splitIntoParts(payload, 3)

	switch dialect {
	case "mysql":
		return f.mysqlConcat(parts)
	case "mssql":
		return f.mssqlConcat(parts)
	case "oracle", "postgresql":
		return f.oracleConcat(parts)
	default:
		return payload
	}
}

// splitIntoParts splits a string into n roughly equal parts
func (f *FragmentationMutator) splitIntoParts(s string, n int) []string {
	if n <= 0 {
		return []string{s}
	}

	length := len(s)
	if length <= n {
		// Return each character as a part
		parts := make([]string, length)
		for i, r := range s {
			parts[i] = string(r)
		}
		return parts
	}

	partSize := length / n
	remainder := length % n

	parts := make([]string, n)
	start := 0
	for i := 0; i < n; i++ {
		end := start + partSize
		if i < remainder {
			end++
		}
		parts[i] = s[start:end]
		start = end
	}

	return parts
}

// mysqlConcat creates MySQL CONCAT() syntax
func (f *FragmentationMutator) mysqlConcat(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return "'" + parts[0] + "'"
	}

	var quoted []string
	for _, p := range parts {
		quoted = append(quoted, "'"+p+"'")
	}
	return "CONCAT(" + strings.Join(quoted, ",") + ")"
}

// mssqlConcat creates MSSQL + syntax
func (f *FragmentationMutator) mssqlConcat(parts []string) string {
	if len(parts) == 0 {
		return ""
	}

	var quoted []string
	for _, p := range parts {
		quoted = append(quoted, "'"+p+"'")
	}
	return strings.Join(quoted, "+")
}

// oracleConcat creates Oracle || syntax
func (f *FragmentationMutator) oracleConcat(parts []string) string {
	if len(parts) == 0 {
		return ""
	}

	var quoted []string
	for _, p := range parts {
		quoted = append(quoted, "'"+p+"'")
	}
	return strings.Join(quoted, "||")
}

// FragmentWithCHAR creates CHAR()-based representations
func (f *FragmentationMutator) FragmentWithCHAR(payload string, dialect string) string {
	switch dialect {
	case "mysql":
		return f.mysqlCHAR(payload)
	case "mssql":
		return f.mssqlCHAR(payload)
	case "oracle":
		return f.oracleCHR(payload)
	default:
		return payload
	}
}

// mysqlCHAR creates MySQL CHAR() syntax
func (f *FragmentationMutator) mysqlCHAR(payload string) string {
	var codes []string
	for _, r := range payload {
		codes = append(codes, string(rune('0'+r/100)), string(rune('0'+(r%100)/10)), string(rune('0'+r%10)))
	}

	var charCodes []string
	for _, r := range payload {
		charCodes = append(charCodes, string(rune(r)))
	}

	// Build CHAR(n1,n2,n3...)
	var numCodes []string
	for _, r := range payload {
		numCodes = append(numCodes, string(rune(r)))
	}

	var result strings.Builder
	result.WriteString("CHAR(")
	for i, r := range payload {
		if i > 0 {
			result.WriteString(",")
		}
		result.WriteString(string([]byte{byte(r / 100 % 10) + '0', byte(r / 10 % 10) + '0', byte(r % 10) + '0'}))
	}
	result.WriteString(")")

	// Simpler: just write the decimal codes
	var simpleCodes []string
	for _, r := range payload {
		simpleCodes = append(simpleCodes, intToString(int(r)))
	}
	return "CHAR(" + strings.Join(simpleCodes, ",") + ")"
}

// mssqlCHAR creates MSSQL CHAR() syntax with concatenation
func (f *FragmentationMutator) mssqlCHAR(payload string) string {
	var parts []string
	for _, r := range payload {
		parts = append(parts, "CHAR("+intToString(int(r))+")")
	}
	return strings.Join(parts, "+")
}

// oracleCHR creates Oracle CHR() syntax
func (f *FragmentationMutator) oracleCHR(payload string) string {
	var parts []string
	for _, r := range payload {
		parts = append(parts, "CHR("+intToString(int(r))+")")
	}
	return strings.Join(parts, "||")
}

// intToString converts int to string without strconv for simplicity
func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte(n%10) + '0'}, digits...)
		n /= 10
	}

	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
