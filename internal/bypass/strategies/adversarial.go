package strategies

import (
	"math/rand"
	"strings"
)

// AdversarialMutator applies adversarial ML evasion techniques
type AdversarialMutator struct {
	Homoglyphs     bool
	InvisibleChars bool
	BiDiOverride   bool
}

// NewAdversarialMutator creates a new adversarial mutator with all options enabled
func NewAdversarialMutator() *AdversarialMutator {
	return &AdversarialMutator{
		Homoglyphs:     true,
		InvisibleChars: true,
		BiDiOverride:   false, // Disabled by default as it can break payloads
	}
}

// Mutate applies adversarial mutations to a payload
func (a *AdversarialMutator) Mutate(payload string) []MutationResult {
	var results []MutationResult

	if a.Homoglyphs {
		results = append(results, MutationResult{
			Payload:     a.ApplyHomoglyphs(payload),
			Mutation:    "homoglyph_substitution",
			Description: "Substitute with visually similar Unicode characters",
		})
		results = append(results, MutationResult{
			Payload:     a.ApplyHomoglyphsAggressive(payload),
			Mutation:    "homoglyph_aggressive",
			Description: "Aggressive homoglyph substitution",
		})
		results = append(results, MutationResult{
			Payload:     a.ApplyCyrillicHomoglyphs(payload),
			Mutation:    "cyrillic_homoglyphs",
			Description: "Cyrillic character substitution",
		})
	}

	if a.InvisibleChars {
		results = append(results, MutationResult{
			Payload:     a.InsertZeroWidth(payload),
			Mutation:    "zero_width_chars",
			Description: "Insert zero-width characters",
		})
		results = append(results, MutationResult{
			Payload:     a.InsertZeroWidthJoiners(payload),
			Mutation:    "zero_width_joiners",
			Description: "Insert zero-width joiners",
		})
		results = append(results, MutationResult{
			Payload:     a.InsertSoftHyphens(payload),
			Mutation:    "soft_hyphens",
			Description: "Insert soft hyphens",
		})
		results = append(results, MutationResult{
			Payload:     a.InsertWordJoiners(payload),
			Mutation:    "word_joiners",
			Description: "Insert word joiners",
		})
	}

	if a.BiDiOverride {
		results = append(results, MutationResult{
			Payload:     a.ApplyBiDiOverride(payload),
			Mutation:    "bidi_override",
			Description: "Apply bidirectional text override",
		})
		results = append(results, MutationResult{
			Payload:     a.ApplyRightToLeft(payload),
			Mutation:    "rtl_override",
			Description: "Apply right-to-left override",
		})
	}

	return results
}

// Homoglyph mappings - visually similar characters
var homoglyphMap = map[rune][]rune{
	'a': {'а', 'ɑ', 'α', 'ａ'},           // Cyrillic а, Latin ɑ, Greek α, fullwidth a
	'A': {'А', 'Α', 'Ａ'},                // Cyrillic А, Greek Α, fullwidth A
	'b': {'Ь', 'ｂ'},                     // Cyrillic ь, fullwidth b
	'B': {'В', 'Β', 'Ｂ'},                // Cyrillic В, Greek Β, fullwidth B
	'c': {'с', 'ϲ', 'ⅽ', 'ｃ'},           // Cyrillic с, Greek ϲ, Roman numeral ⅽ, fullwidth c
	'C': {'С', 'Ϲ', 'Ⅽ', 'Ｃ'},           // Cyrillic С, Greek Ϲ, Roman numeral Ⅽ, fullwidth C
	'd': {'ԁ', 'ⅾ', 'ｄ'},               // Cyrillic ԁ, Roman numeral ⅾ, fullwidth d
	'D': {'Ⅾ', 'Ｄ'},                    // Roman numeral Ⅾ, fullwidth D
	'e': {'е', 'ё', 'ε', 'ｅ'},           // Cyrillic е, ё, Greek ε, fullwidth e
	'E': {'Е', 'Ε', 'Ｅ'},                // Cyrillic Е, Greek Ε, fullwidth E
	'g': {'ɡ', 'ｇ'},                    // Latin ɡ, fullwidth g
	'h': {'һ', 'ｈ'},                    // Cyrillic һ, fullwidth h
	'H': {'Η', 'Н', 'Ｈ'},                // Greek Η, Cyrillic Н, fullwidth H
	'i': {'і', 'ι', 'ⅰ', 'ｉ'},           // Cyrillic і, Greek ι, Roman numeral ⅰ, fullwidth i
	'I': {'І', 'Ι', 'Ⅰ', 'Ｉ'},           // Cyrillic І, Greek Ι, Roman numeral Ⅰ, fullwidth I
	'j': {'ј', 'ｊ'},                    // Cyrillic ј, fullwidth j
	'J': {'Ј', 'Ｊ'},                    // Cyrillic Ј, fullwidth J
	'k': {'κ', 'ｋ'},                    // Greek κ, fullwidth k
	'K': {'Κ', 'К', 'Ｋ'},                // Greek Κ, Cyrillic К, fullwidth K
	'l': {'ⅼ', 'ｌ', 'ı'},               // Roman numeral ⅼ, fullwidth l, Turkish dotless i
	'L': {'Ⅼ', 'Ｌ'},                    // Roman numeral Ⅼ, fullwidth L
	'm': {'ⅿ', 'ｍ'},                    // Roman numeral ⅿ, fullwidth m
	'M': {'Μ', 'М', 'Ⅿ', 'Ｍ'},           // Greek Μ, Cyrillic М, Roman numeral Ⅿ, fullwidth M
	'n': {'ո', 'ｎ'},                    // Armenian ո, fullwidth n
	'N': {'Ν', 'Ｎ'},                    // Greek Ν, fullwidth N
	'o': {'о', 'ο', 'σ', 'ｏ'},           // Cyrillic о, Greek ο, Greek σ, fullwidth o
	'O': {'О', 'Ο', 'Ｏ'},                // Cyrillic О, Greek Ο, fullwidth O
	'p': {'р', 'ρ', 'ｐ'},               // Cyrillic р, Greek ρ, fullwidth p
	'P': {'Р', 'Ρ', 'Ｐ'},                // Cyrillic Р, Greek Ρ, fullwidth P
	'q': {'ԛ', 'ｑ'},                    // Cyrillic ԛ, fullwidth q
	'r': {'ｒ'},                         // fullwidth r
	'R': {'Ｒ'},                         // fullwidth R
	's': {'ѕ', 'ｓ'},                    // Cyrillic ѕ, fullwidth s
	'S': {'Ѕ', 'Ｓ'},                    // Cyrillic Ѕ, fullwidth S
	't': {'ｔ'},                         // fullwidth t
	'T': {'Τ', 'Т', 'Ｔ'},                // Greek Τ, Cyrillic Т, fullwidth T
	'u': {'υ', 'ｕ'},                    // Greek υ, fullwidth u
	'U': {'Ｕ'},                         // fullwidth U
	'v': {'ν', 'ⅴ', 'ｖ'},               // Greek ν, Roman numeral ⅴ, fullwidth v
	'V': {'Ⅴ', 'Ｖ'},                    // Roman numeral Ⅴ, fullwidth V
	'w': {'ԝ', 'ｗ'},                    // Cyrillic ԝ, fullwidth w
	'W': {'Ｗ'},                         // fullwidth W
	'x': {'х', 'χ', 'ⅹ', 'ｘ'},           // Cyrillic х, Greek χ, Roman numeral ⅹ, fullwidth x
	'X': {'Χ', 'Х', 'Ⅹ', 'Ｘ'},           // Greek Χ, Cyrillic Х, Roman numeral Ⅹ, fullwidth X
	'y': {'у', 'γ', 'ｙ'},               // Cyrillic у, Greek γ, fullwidth y
	'Y': {'Υ', 'Ｙ'},                    // Greek Υ, fullwidth Y
	'z': {'ｚ'},                         // fullwidth z
	'Z': {'Ζ', 'Ｚ'},                    // Greek Ζ, fullwidth Z
	'0': {'О', 'Ο', '০', '٠', '۰', '０'}, // Various zeros
	'1': {'１', 'Ⅰ', 'ⅰ', 'ı'},          // fullwidth 1, Roman numerals, Turkish dotless i
}

// Invisible character codes
const (
	zeroWidthSpace      = '\u200B'
	zeroWidthNonJoiner  = '\u200C'
	zeroWidthJoiner     = '\u200D'
	wordJoiner          = '\u2060'
	softHyphen          = '\u00AD'
	leftToRightMark     = '\u200E'
	rightToLeftMark     = '\u200F'
	leftToRightOverride = '\u202D'
	rightToLeftOverride = '\u202E'
	popDirectional      = '\u202C'
)

// ApplyHomoglyphs randomly substitutes characters with homoglyphs
func (a *AdversarialMutator) ApplyHomoglyphs(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if homoglyphs, ok := homoglyphMap[r]; ok && rand.Float32() < 0.3 {
			// 30% chance to substitute
			result.WriteRune(homoglyphs[rand.Intn(len(homoglyphs))])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ApplyHomoglyphsAggressive substitutes all possible characters
func (a *AdversarialMutator) ApplyHomoglyphsAggressive(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if homoglyphs, ok := homoglyphMap[r]; ok {
			// Always substitute
			result.WriteRune(homoglyphs[0])
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ApplyCyrillicHomoglyphs specifically uses Cyrillic characters
func (a *AdversarialMutator) ApplyCyrillicHomoglyphs(payload string) string {
	cyrillicMap := map[rune]rune{
		'a': 'а', 'A': 'А',
		'c': 'с', 'C': 'С',
		'e': 'е', 'E': 'Е',
		'o': 'о', 'O': 'О',
		'p': 'р', 'P': 'Р',
		'x': 'х', 'X': 'Х',
		'y': 'у', 'Y': 'У',
	}

	var result strings.Builder
	for _, r := range payload {
		if cyrillic, ok := cyrillicMap[r]; ok {
			result.WriteRune(cyrillic)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// InsertZeroWidth inserts zero-width space characters
func (a *AdversarialMutator) InsertZeroWidth(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		// Insert zero-width space after certain characters
		if i > 0 && i < len(payload)-1 && isKeywordChar(r) {
			result.WriteRune(zeroWidthSpace)
		}
	}
	return result.String()
}

// InsertZeroWidthJoiners inserts zero-width joiner characters
func (a *AdversarialMutator) InsertZeroWidthJoiners(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		if i < len(payload)-1 {
			result.WriteRune(zeroWidthJoiner)
		}
	}
	return result.String()
}

// InsertSoftHyphens inserts soft hyphen characters
func (a *AdversarialMutator) InsertSoftHyphens(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		// Insert soft hyphen in the middle of words
		if i > 0 && i < len(payload)-1 && isAlphaNum(r) {
			result.WriteRune(softHyphen)
		}
	}
	return result.String()
}

// InsertWordJoiners inserts word joiner characters
func (a *AdversarialMutator) InsertWordJoiners(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		result.WriteRune(r)
		if i > 0 && i < len(payload)-1 && rand.Float32() < 0.5 {
			result.WriteRune(wordJoiner)
		}
	}
	return result.String()
}

// ApplyBiDiOverride wraps text in bidirectional override characters
func (a *AdversarialMutator) ApplyBiDiOverride(payload string) string {
	// This can visually reverse the display while keeping logical order
	return string(leftToRightOverride) + payload + string(popDirectional)
}

// ApplyRightToLeft applies right-to-left override
func (a *AdversarialMutator) ApplyRightToLeft(payload string) string {
	return string(rightToLeftOverride) + payload + string(popDirectional)
}

// isKeywordChar checks if a character is part of a keyword
func isKeywordChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// isAlphaNum checks if a character is alphanumeric
func isAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// CombiningCharacterAttack adds combining characters that may confuse parsers
func (a *AdversarialMutator) CombiningCharacterAttack(payload string) string {
	// Combining characters that attach to the previous character
	combiningChars := []rune{
		'\u0300', // Combining grave accent
		'\u0301', // Combining acute accent
		'\u0302', // Combining circumflex
		'\u0303', // Combining tilde
		'\u0304', // Combining macron
	}

	var result strings.Builder
	for _, r := range payload {
		result.WriteRune(r)
		if isAlphaNum(r) && rand.Float32() < 0.2 {
			result.WriteRune(combiningChars[rand.Intn(len(combiningChars))])
		}
	}
	return result.String()
}
