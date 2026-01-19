package strategies

import (
	"math/rand"
	"regexp"
	"strings"
)

// ObfuscationMutator applies code obfuscation techniques
type ObfuscationMutator struct {
	CommentInjection       bool
	CaseRandomization      bool
	WhitespaceSubstitution bool
	NullBytes              bool
}

// NewObfuscationMutator creates a new obfuscation mutator with all options enabled
func NewObfuscationMutator() *ObfuscationMutator {
	return &ObfuscationMutator{
		CommentInjection:       true,
		CaseRandomization:      true,
		WhitespaceSubstitution: true,
		NullBytes:              true,
	}
}

// Mutate applies obfuscation mutations to a payload
func (o *ObfuscationMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	if o.CommentInjection {
		// SQL-style comments
		results = append(results, MutationResult{
			Payload:     o.InjectSQLComments(payload),
			Mutation:    "sql_comment_injection",
			Description: "SQL inline comment injection (/**/)",
		})
		results = append(results, MutationResult{
			Payload:     o.InjectSQLCommentsAggressive(payload),
			Mutation:    "sql_comment_aggressive",
			Description: "Aggressive SQL comment injection",
		})

		// MySQL-specific comments
		results = append(results, MutationResult{
			Payload:     o.InjectMySQLComments(payload),
			Mutation:    "mysql_version_comment",
			Description: "MySQL version-specific comments (/*!*/)",
		})

		// Line comments
		results = append(results, MutationResult{
			Payload:     o.InjectLineComments(payload),
			Mutation:    "line_comment_injection",
			Description: "Line comment injection (--)",
		})

		// HTML comments (for XSS)
		results = append(results, MutationResult{
			Payload:     o.InjectHTMLComments(payload),
			Mutation:    "html_comment_injection",
			Description: "HTML comment injection (<!-- -->)",
		})

		// JS comments (for XSS)
		results = append(results, MutationResult{
			Payload:     o.InjectJSComments(payload),
			Mutation:    "js_comment_injection",
			Description: "JavaScript comment injection (/**/)",
		})
	}

	if o.CaseRandomization {
		results = append(results, MutationResult{
			Payload:     o.RandomizeCase(payload),
			Mutation:    "case_randomization",
			Description: "Random case variation",
		})
		results = append(results, MutationResult{
			Payload:     o.AlternatingCase(payload),
			Mutation:    "alternating_case",
			Description: "Alternating case (aLtErNaTiNg)",
		})
		results = append(results, MutationResult{
			Payload:     strings.ToUpper(payload),
			Mutation:    "uppercase",
			Description: "All uppercase",
		})
		results = append(results, MutationResult{
			Payload:     strings.ToLower(payload),
			Mutation:    "lowercase",
			Description: "All lowercase",
		})
	}

	if o.WhitespaceSubstitution {
		results = append(results, MutationResult{
			Payload:     o.SubstituteWithTabs(payload),
			Mutation:    "whitespace_tabs",
			Description: "Replace spaces with tabs",
		})
		results = append(results, MutationResult{
			Payload:     o.SubstituteWithNewlines(payload),
			Mutation:    "whitespace_newlines",
			Description: "Replace spaces with newlines",
		})
		results = append(results, MutationResult{
			Payload:     o.SubstituteWithVerticalTab(payload),
			Mutation:    "whitespace_vertical_tab",
			Description: "Replace spaces with vertical tabs",
		})
		results = append(results, MutationResult{
			Payload:     o.SubstituteWithFormFeed(payload),
			Mutation:    "whitespace_form_feed",
			Description: "Replace spaces with form feeds",
		})
		results = append(results, MutationResult{
			Payload:     o.AddExtraWhitespace(payload),
			Mutation:    "extra_whitespace",
			Description: "Add extra whitespace between tokens",
		})
	}

	if o.NullBytes {
		results = append(results, MutationResult{
			Payload:     o.InjectNullBytes(payload),
			Mutation:    "null_byte_injection",
			Description: "Inject null bytes (%00)",
		})
		results = append(results, MutationResult{
			Payload:     o.InjectNullBytesURL(payload),
			Mutation:    "null_byte_url",
			Description: "URL-encoded null bytes",
		})
	}

	return results
}

// InjectSQLComments injects /**/ between characters
func (o *ObfuscationMutator) InjectSQLComments(payload string) string {
	// Inject comments between SQL keywords
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC"}
	result := payload

	for _, keyword := range keywords {
		// Create commented version: SE/**/LECT
		commented := o.commentInWord(keyword)
		result = strings.ReplaceAll(result, keyword, commented)
		result = strings.ReplaceAll(result, strings.ToLower(keyword), strings.ToLower(commented))
	}

	return result
}

// commentInWord inserts /**/ in the middle of a word
func (o *ObfuscationMutator) commentInWord(word string) string {
	if len(word) < 2 {
		return word
	}
	mid := len(word) / 2
	return word[:mid] + "/**/" + word[mid:]
}

// InjectSQLCommentsAggressive injects /**/ between every character
func (o *ObfuscationMutator) InjectSQLCommentsAggressive(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		if i < len(payload)-1 && r != ' ' {
			result.WriteString("/**/")
		}
	}
	return result.String()
}

// InjectMySQLComments uses MySQL version-specific comments
func (o *ObfuscationMutator) InjectMySQLComments(payload string) string {
	// /*!50000 ... */ syntax is processed by MySQL 5.0+
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE"}
	result := payload

	for _, keyword := range keywords {
		versioned := "/*!50000" + keyword + "*/"
		result = strings.ReplaceAll(result, keyword, versioned)
		result = strings.ReplaceAll(result, strings.ToLower(keyword), strings.ToLower(versioned))
	}

	return result
}

// InjectLineComments injects -- or # at strategic points
func (o *ObfuscationMutator) InjectLineComments(payload string) string {
	// Add a trailing comment
	return payload + "--"
}

// InjectHTMLComments injects <!-- --> within HTML/JS
func (o *ObfuscationMutator) InjectHTMLComments(payload string) string {
	// Insert HTML comments within script tags
	result := strings.ReplaceAll(payload, "<script>", "<script><!--")
	result = strings.ReplaceAll(result, "</script>", "--></script>")
	return result
}

// InjectJSComments injects /**/ within JavaScript
func (o *ObfuscationMutator) InjectJSComments(payload string) string {
	// Inject JS comments in function calls - these are for WAF bypass testing payloads
	// al/**/ert is a common XSS bypass technique
	result := strings.ReplaceAll(payload, "alert(", "al/**/ert(")
	result = strings.ReplaceAll(result, "prompt(", "pro/**/mpt(")
	result = strings.ReplaceAll(result, "document", "docu/**/ment")
	return result
}

// RandomizeCase randomly changes the case of each character
func (o *ObfuscationMutator) RandomizeCase(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if rand.Intn(2) == 0 {
			result.WriteString(strings.ToUpper(string(r)))
		} else {
			result.WriteString(strings.ToLower(string(r)))
		}
	}
	return result.String()
}

// AlternatingCase creates aLtErNaTiNg CaSe
func (o *ObfuscationMutator) AlternatingCase(payload string) string {
	var result strings.Builder
	upper := true
	for _, r := range payload {
		if upper {
			result.WriteString(strings.ToLower(string(r)))
		} else {
			result.WriteString(strings.ToUpper(string(r)))
		}
		upper = !upper
	}
	return result.String()
}

// SubstituteWithTabs replaces spaces with tabs
func (o *ObfuscationMutator) SubstituteWithTabs(payload string) string {
	return strings.ReplaceAll(payload, " ", "\t")
}

// SubstituteWithNewlines replaces spaces with newlines
func (o *ObfuscationMutator) SubstituteWithNewlines(payload string) string {
	return strings.ReplaceAll(payload, " ", "\n")
}

// SubstituteWithVerticalTab replaces spaces with vertical tabs
func (o *ObfuscationMutator) SubstituteWithVerticalTab(payload string) string {
	return strings.ReplaceAll(payload, " ", "\v")
}

// SubstituteWithFormFeed replaces spaces with form feeds
func (o *ObfuscationMutator) SubstituteWithFormFeed(payload string) string {
	return strings.ReplaceAll(payload, " ", "\f")
}

// AddExtraWhitespace adds extra whitespace between tokens
func (o *ObfuscationMutator) AddExtraWhitespace(payload string) string {
	// Use regex to find word boundaries and add extra spaces
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(payload, "  \t  ")
}

// InjectNullBytes injects literal null bytes
func (o *ObfuscationMutator) InjectNullBytes(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		// Inject null byte after dangerous characters
		if i > 0 && i < len(payload)-1 && (r == '\'' || r == '"' || r == '<' || r == '>') {
			result.WriteByte(0x00)
		}
	}
	return result.String()
}

// InjectNullBytesURL injects URL-encoded null bytes
func (o *ObfuscationMutator) InjectNullBytesURL(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteRune(r)
		if r == '\'' || r == '"' {
			result.WriteString("%00")
		}
	}
	return result.String()
}

// StringConcatenation breaks strings using concatenation
func (o *ObfuscationMutator) StringConcatenation(payload string, dialect string) string {
	switch dialect {
	case "mysql":
		// CONCAT('sel','ect')
		return o.mysqlConcat(payload)
	case "mssql":
		// 'sel'+'ect'
		return o.mssqlConcat(payload)
	case "oracle":
		// 'sel'||'ect'
		return o.oracleConcat(payload)
	default:
		return payload
	}
}

func (o *ObfuscationMutator) mysqlConcat(payload string) string {
	if len(payload) < 4 {
		return payload
	}
	// Simple split for demonstration
	mid := len(payload) / 2
	return "CONCAT('" + payload[:mid] + "','" + payload[mid:] + "')"
}

func (o *ObfuscationMutator) mssqlConcat(payload string) string {
	if len(payload) < 4 {
		return payload
	}
	mid := len(payload) / 2
	return "'" + payload[:mid] + "'+'" + payload[mid:] + "'"
}

func (o *ObfuscationMutator) oracleConcat(payload string) string {
	if len(payload) < 4 {
		return payload
	}
	mid := len(payload) / 2
	return "'" + payload[:mid] + "'||'" + payload[mid:] + "'"
}
