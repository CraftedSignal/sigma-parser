package sigma

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// modifierResult holds the parsed result of applying a modifier chain.
type modifierResult struct {
	operator string   // Canonical operator for the condition
	allOf    bool     // True if list values should be AND'd (not OR'd)
	values   []string // Transformed/expanded values
}

// parseModifiers parses a field name with modifiers (e.g. "FieldName|contains|all")
// and returns the base field name plus modifier result for the given values.
func parseModifiers(fieldWithMods string, values []string) (field string, result modifierResult) {
	parts := strings.Split(fieldWithMods, "|")
	field = parts[0]
	modifiers := parts[1:]

	result.operator = "="
	result.values = values

	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "contains":
			result.operator = "contains"
		case "startswith":
			result.operator = "startswith"
		case "endswith":
			result.operator = "endswith"
		case "re":
			result.operator = "matches"
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
			result.operator = "fieldref"
		case "all":
			result.allOf = true
		case "base64":
			result.values = applyBase64(result.values)
		case "base64offset":
			result.values = applyBase64Offset(result.values)
		case "wide", "utf16", "utf16le":
			result.values = applyUTF16LE(result.values)
		case "utf16be":
			result.values = applyUTF16BE(result.values)
		case "windash":
			result.values = applyWindash(result.values)
		case "expand":
			// Placeholder expansion — values pass through as-is.
			// Real expansion requires environment variable context.
		}
	}

	return field, result
}

// applyBase64 encodes each value as base64 and returns both original and encoded.
func applyBase64(values []string) []string {
	out := make([]string, 0, len(values)*2)
	for _, v := range values {
		out = append(out, v)
		out = append(out, base64.StdEncoding.EncodeToString([]byte(v)))
	}
	return out
}

// applyBase64Offset generates 3 offset variants per value.
// When a string is base64-encoded at different byte boundaries, the encoded
// output differs. This produces all 3 possible alignment variants.
func applyBase64Offset(values []string) []string {
	out := make([]string, 0, len(values)*4)
	for _, v := range values {
		out = append(out, v)
		b := []byte(v)
		// Offset 0: encode as-is, trim padding
		out = append(out, trimBase64Padding(base64.StdEncoding.EncodeToString(b)))
		// Offset 1: prepend 1 byte
		padded1 := append([]byte{0}, b...)
		enc1 := base64.StdEncoding.EncodeToString(padded1)
		if len(enc1) > 1 {
			out = append(out, trimBase64Padding(enc1[1:]))
		}
		// Offset 2: prepend 2 bytes
		padded2 := append([]byte{0, 0}, b...)
		enc2 := base64.StdEncoding.EncodeToString(padded2)
		if len(enc2) > 2 {
			out = append(out, trimBase64Padding(enc2[2:]))
		}
	}
	return out
}

func trimBase64Padding(s string) string {
	return strings.TrimRight(s, "=")
}

// applyUTF16LE encodes values as UTF-16LE hex-escaped strings.
func applyUTF16LE(values []string) []string {
	out := make([]string, 0, len(values)*2)
	for _, v := range values {
		out = append(out, v)
		encoded := encodeUTF16LE(v)
		if encoded != v {
			out = append(out, encoded)
		}
	}
	return out
}

// applyUTF16BE encodes values as UTF-16BE strings.
func applyUTF16BE(values []string) []string {
	out := make([]string, 0, len(values)*2)
	for _, v := range values {
		out = append(out, v)
		encoded := encodeUTF16BE(v)
		if encoded != v {
			out = append(out, encoded)
		}
	}
	return out
}

func encodeUTF16LE(s string) string {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	var buf strings.Builder
	for _, code := range u16 {
		buf.WriteByte(byte(code & 0xFF))
		buf.WriteByte(byte(code >> 8))
	}
	return buf.String()
}

func encodeUTF16BE(s string) string {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	var buf strings.Builder
	for _, code := range u16 {
		buf.WriteByte(byte(code >> 8))
		buf.WriteByte(byte(code & 0xFF))
	}
	return buf.String()
}

// applyWindash generates dash/slash variants for command-line arguments.
// For values starting with - it also adds / variant, and vice versa.
func applyWindash(values []string) []string {
	out := make([]string, 0, len(values)*2)
	for _, v := range values {
		out = append(out, v)
		if strings.HasPrefix(v, "-") {
			out = append(out, "/"+v[1:])
		} else if strings.HasPrefix(v, "/") {
			out = append(out, "-"+v[1:])
		}
	}
	return out
}
