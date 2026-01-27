package statemachine

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/su1ph3r/bypassburrito/pkg/types"
)

// EvaluateCondition checks if a condition is satisfied
func EvaluateCondition(cond Condition, state *MachineState, resp *types.HTTPResponse) bool {
	// Get the variable value
	var value string
	var exists bool

	switch cond.Variable {
	case "status", "status_code":
		if resp != nil {
			value = strconv.Itoa(resp.StatusCode)
			exists = true
		}
	case "body":
		if resp != nil {
			value = resp.Body
			exists = true
		}
	case "content_length":
		if resp != nil {
			value = strconv.Itoa(resp.ContentLength)
			exists = true
		}
	default:
		// Check state variables
		value, exists = state.GetVariable(cond.Variable)

		// Also check headers if not found in variables
		if !exists && resp != nil {
			if headerVal, ok := resp.Headers[cond.Variable]; ok {
				value = headerVal
				exists = true
			}
		}
	}

	// Evaluate based on operator
	switch cond.Operator {
	case "eq", "==", "equals":
		return value == cond.Value
	case "ne", "!=", "not_equals":
		return value != cond.Value
	case "contains":
		return strings.Contains(value, cond.Value)
	case "not_contains":
		return !strings.Contains(value, cond.Value)
	case "matches", "regex":
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case "not_matches", "not_regex":
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return true
		}
		return !re.MatchString(value)
	case "gt", ">":
		v, _ := strconv.ParseFloat(value, 64)
		c, _ := strconv.ParseFloat(cond.Value, 64)
		return v > c
	case "gte", ">=":
		v, _ := strconv.ParseFloat(value, 64)
		c, _ := strconv.ParseFloat(cond.Value, 64)
		return v >= c
	case "lt", "<":
		v, _ := strconv.ParseFloat(value, 64)
		c, _ := strconv.ParseFloat(cond.Value, 64)
		return v < c
	case "lte", "<=":
		v, _ := strconv.ParseFloat(value, 64)
		c, _ := strconv.ParseFloat(cond.Value, 64)
		return v <= c
	case "exists":
		return exists && value != ""
	case "not_exists", "empty":
		return !exists || value == ""
	case "starts_with":
		return strings.HasPrefix(value, cond.Value)
	case "ends_with":
		return strings.HasSuffix(value, cond.Value)
	default:
		// Unknown operator - default to equality check
		return value == cond.Value
	}
}

// EvaluateConditions checks all conditions and returns the next step if any match
func EvaluateConditions(conditions []Condition, state *MachineState, resp *types.HTTPResponse) string {
	for _, cond := range conditions {
		if EvaluateCondition(cond, state, resp) {
			return cond.NextStep
		}
	}
	return ""
}

// ExtractVariable extracts a value from response based on extractor definition
func ExtractVariable(extractor VariableExtractor, resp *types.HTTPResponse) (string, bool) {
	if resp == nil {
		return extractor.Default, extractor.Default != ""
	}

	var source string
	switch extractor.Source {
	case "body":
		source = resp.Body
	case "header":
		// Pattern should specify header name
		if headerVal, ok := resp.Headers[extractor.Pattern]; ok {
			return headerVal, true
		}
		// Try case-insensitive search
		for k, v := range resp.Headers {
			if strings.EqualFold(k, extractor.Pattern) {
				return v, true
			}
		}
		return extractor.Default, extractor.Default != ""
	case "cookie":
		// Extract from Set-Cookie header
		setCookie := resp.Headers["Set-Cookie"]
		if setCookie == "" {
			return extractor.Default, extractor.Default != ""
		}
		return extractCookieValue(setCookie, extractor.Pattern), true
	case "status":
		return strconv.Itoa(resp.StatusCode), true
	default:
		source = resp.Body
	}

	// Apply pattern extraction if specified
	if extractor.Pattern != "" {
		re, err := regexp.Compile(extractor.Pattern)
		if err != nil {
			return extractor.Default, extractor.Default != ""
		}

		matches := re.FindStringSubmatch(source)
		if len(matches) > 1 {
			return matches[1], true
		} else if len(matches) == 1 {
			return matches[0], true
		}
	}

	return extractor.Default, extractor.Default != ""
}

// ExtractVariables extracts all variables from a response
func ExtractVariables(extractors []VariableExtractor, resp *types.HTTPResponse) map[string]string {
	vars := make(map[string]string)
	for _, ext := range extractors {
		if value, ok := ExtractVariable(ext, resp); ok {
			vars[ext.Name] = value
		}
	}
	return vars
}

// extractCookieValue extracts a specific cookie value from Set-Cookie header
func extractCookieValue(setCookie, name string) string {
	// Parse Set-Cookie header
	// Format: name=value; attribute=value; ...
	parts := strings.Split(setCookie, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+"=") {
			return strings.TrimPrefix(part, name+"=")
		}
	}
	return ""
}

// ExtractCookiesFromResponse extracts all cookies from response headers
func ExtractCookiesFromResponse(resp *types.HTTPResponse) map[string]string {
	cookies := make(map[string]string)
	if resp == nil {
		return cookies
	}

	// Check Set-Cookie headers
	for name, value := range resp.Headers {
		if strings.EqualFold(name, "Set-Cookie") {
			// Parse cookie
			parts := strings.Split(value, ";")
			if len(parts) > 0 {
				cookiePart := strings.TrimSpace(parts[0])
				eqIdx := strings.Index(cookiePart, "=")
				if eqIdx > 0 {
					cookieName := cookiePart[:eqIdx]
					cookieValue := cookiePart[eqIdx+1:]
					cookies[cookieName] = cookieValue
				}
			}
		}
	}

	return cookies
}

// IsStatusSuccess checks if a status code is considered successful
func IsStatusSuccess(code int, expected []int) bool {
	if len(expected) == 0 {
		// Default: 2xx is success
		return code >= 200 && code < 300
	}
	for _, e := range expected {
		if code == e {
			return true
		}
	}
	return false
}

// DetermineNextStep determines the next step based on response and conditions
func DetermineNextStep(step *SequenceStep, state *MachineState, resp *types.HTTPResponse, success bool) string {
	// First check step-level conditions
	if len(step.Conditions) > 0 {
		if nextStep := EvaluateConditions(step.Conditions, state, resp); nextStep != "" {
			return nextStep
		}
	}

	// Fall back to on_success/on_failure
	if success {
		if step.OnSuccess != "" {
			return step.OnSuccess
		}
	} else {
		if step.OnFailure != "" {
			return step.OnFailure
		}
	}

	// Default to complete (no more steps)
	return "complete"
}
