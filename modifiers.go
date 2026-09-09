package sigma

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
)

// modifierResult holds the parsed result of applying a modifier chain.
type modifierResult struct {
	operator          string   // Canonical operator for the condition
	allOf             bool     // True if list values should be AND'd (not OR'd)
	caseSensitive     bool     // True if matching must be case-sensitive
	fieldReference    bool     // True if values name other fields
	requiresExpansion bool     // True if placeholders need pipeline expansion
	values            []string // Transformed/expanded values
	errors            []string
}

// parseModifiers parses a field name with modifiers (e.g. "FieldName|contains|all")
// and returns the base field name plus modifier result for the given values.
func parseModifiers(fieldWithMods string, values []string) (field string, result modifierResult) {
	parts := strings.Split(fieldWithMods, "|")
	field = parts[0]
	modifiers := parts[1:]

	result.operator = "="
	result.values = values

	for _, modifier := range modifiers {
		switch strings.ToLower(modifier) {
		case "contains":
			result.operator = "contains"
		case "startswith":
			result.operator = "startswith"
		case "endswith":
			result.operator = "endswith"
		case "re":
			result.operator = "matches"
			result.caseSensitive = true
		case "cidr":
			result.operator = "cidrmatch"
		case "gt":
			result.operator = ">"
		case "gte":
			result.operator = ">="
		case "lt":
			result.operator = "<"
		case "lte":
			result.operator = "<="
		case "exists":
			result.operator = "exists"
		case "fieldref":
			result.fieldReference = true
		case "all":
			result.allOf = true
		case "base64":
			result.values = applyBase64(result.values)
		case "base64offset":
			result.values = applyBase64Offset(result.values)
		case "wide", "utf16le":
			result.values = applyUTF16LE(result.values)
		case "utf16":
			result.values = applyUTF16(result.values)
		case "utf16be":
			result.values = applyUTF16BE(result.values)
		case "windash":
			result.values = applyWindash(result.values)
		case "cased":
			result.caseSensitive = true
		case "expand":
			result.requiresExpansion = true
		case "i":
			if result.operator != "matches" {
				result.errors = append(result.errors, "regex flag modifier i requires re")
			} else {
				result.caseSensitive = false
			}
		case "m", "s":
			result.errors = append(result.errors, fmt.Sprintf("regex flag modifier %s is not supported", modifier))
		default:
			result.errors = append(result.errors, fmt.Sprintf("unsupported modifier %q", modifier))
		}
	}

	return field, result
}

// applyBase64 encodes each value as base64.
func applyBase64(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, base64.StdEncoding.EncodeToString([]byte(value)))
	}
	return out
}

// applyBase64Offset generates the three alignment variants defined by Sigma.
func applyBase64Offset(values []string) []string {
	out := make([]string, 0, len(values)*3)
	startOffsets := []int{0, 2, 3}
	for _, value := range values {
		for offset, start := range startOffsets {
			input := append(bytes.Repeat([]byte{' '}, offset), []byte(value)...)
			encoded := base64.StdEncoding.EncodeToString(input)
			end := len(encoded)
			switch (len(value) + offset) % 3 {
			case 1:
				end -= 3
			case 2:
				end -= 2
			}
			if start < end {
				out = append(out, encoded[start:end])
			}
		}
	}
	return out
}

func applyUTF16LE(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, encodeUTF16LE(value))
	}
	return out
}

func applyUTF16(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, "\xff\xfe"+encodeUTF16LE(value))
	}
	return out
}

func applyUTF16BE(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, encodeUTF16BE(value))
	}
	return out
}

func encodeUTF16LE(value string) string {
	encoded := utf16.Encode([]rune(value))
	var result strings.Builder
	for _, code := range encoded {
		result.WriteByte(byte(code & 0xff))
		result.WriteByte(byte(code >> 8))
	}
	return result.String()
}

func encodeUTF16BE(value string) string {
	encoded := utf16.Encode([]rune(value))
	var result strings.Builder
	for _, code := range encoded {
		result.WriteByte(byte(code >> 8))
		result.WriteByte(byte(code & 0xff))
	}
	return result.String()
}

// applyWindash generates dash/slash variants for command-line arguments.
func applyWindash(values []string) []string {
	out := make([]string, 0, len(values)*2)
	for _, value := range values {
		out = append(out, value)
		if strings.HasPrefix(value, "-") {
			out = append(out, "/"+value[1:])
		} else if strings.HasPrefix(value, "/") {
			out = append(out, "-"+value[1:])
		}
	}
	return out
}
