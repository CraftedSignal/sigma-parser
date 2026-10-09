package sigma

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
)

// sigmaString is a Sigma detection string split into literal text and
// wildcards: `*` matches any run of characters and `?` exactly one. A
// backslash escapes `*`, `?` and itself; before any other character it is a
// literal backslash (Sigma rules specification, "Escape Character").
type sigmaString []stringPart

type stringPart struct {
	text     string
	wildcard rune // 0 for literal text, otherwise '*' or '?'
}

func parseSigmaString(raw string) sigmaString {
	var out sigmaString
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			out = append(out, stringPart{text: literal.String()})
			literal.Reset()
		}
	}
	escaped := false
	for _, r := range raw {
		switch {
		case escaped:
			if r != '*' && r != '?' && r != '\\' {
				literal.WriteByte('\\')
			}
			literal.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '*' || r == '?':
			flush()
			out = append(out, stringPart{wildcard: r})
		default:
			literal.WriteRune(r)
		}
	}
	if escaped {
		literal.WriteByte('\\')
	}
	flush()
	return out
}

// literalString is a string matched as written, as for non-string YAML values
// such as numbers, which carry no wildcards.
func literalString(text string) sigmaString {
	if text == "" {
		return nil
	}
	return sigmaString{{text: text}}
}

func (s sigmaString) hasWildcards() bool {
	for _, part := range s {
		if part.wildcard != 0 {
			return true
		}
	}
	return false
}

func (s sigmaString) literal() string {
	var b strings.Builder
	for _, part := range s {
		b.WriteString(part.text)
	}
	return b.String()
}

func (s sigmaString) withWildcardPrefix() sigmaString {
	if len(s) > 0 && s[0].wildcard == '*' {
		return s
	}
	return append(sigmaString{{wildcard: '*'}}, s...)
}

func (s sigmaString) withWildcardSuffix() sigmaString {
	if len(s) > 0 && s[len(s)-1].wildcard == '*' {
		return s
	}
	return append(append(sigmaString{}, s...), stringPart{wildcard: '*'})
}

// windashVariants are the characters the windash modifier treats as
// interchangeable for Windows command-line flags.
var windashVariants = []rune{'-', '/', '–', '—', '―'}

// windash expands every flag character that starts a word (a dash or slash
// not preceded by a word character and followed by one, like pySigma's
// \B[-/]\b) into each windash variant, returning all permutations.
func windash(s sigmaString) []sigmaString {
	out := []sigmaString{nil}
	for _, part := range s {
		variants := []stringPart{part}
		if part.wildcard == 0 {
			variants = variants[:0]
			for _, text := range windashTexts(part.text) {
				variants = append(variants, stringPart{text: text})
			}
		}
		next := make([]sigmaString, 0, len(out)*len(variants))
		for _, prefix := range out {
			for _, variant := range variants {
				next = append(next, append(append(sigmaString{}, prefix...), variant))
			}
		}
		out = next
	}
	return out
}

// windashTexts returns every permutation of a literal text's flag characters.
func windashTexts(text string) []string {
	runes := []rune(text)
	texts := []string{""}
	for i, r := range runes {
		if isWindashChar(r) && (i == 0 || !isWordRune(runes[i-1])) && i+1 < len(runes) && isWordRune(runes[i+1]) {
			next := make([]string, 0, len(texts)*len(windashVariants))
			for _, prefix := range texts {
				for _, variant := range windashVariants {
					next = append(next, prefix+string(variant))
				}
			}
			texts = next
			continue
		}
		for j := range texts {
			texts[j] += string(r)
		}
	}
	return texts
}

func isWindashChar(r rune) bool {
	for _, variant := range windashVariants {
		if r == variant {
			return true
		}
	}
	return false
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// Encoding transformations apply to literal text only; Sigma does not allow
// them on strings with wildcards.

func encodeUTF16LE(value string) string {
	var b strings.Builder
	for _, code := range utf16.Encode([]rune(value)) {
		b.WriteByte(byte(code & 0xff))
		b.WriteByte(byte(code >> 8))
	}
	return b.String()
}

func encodeUTF16BE(value string) string {
	var b strings.Builder
	for _, code := range utf16.Encode([]rune(value)) {
		b.WriteByte(byte(code >> 8))
		b.WriteByte(byte(code & 0xff))
	}
	return b.String()
}

// base64OffsetVariants returns the three shifted encodings that find a value
// at any byte offset inside base64 data.
func base64OffsetVariants(value string) []string {
	out := make([]string, 0, 3)
	for offset, start := range []int{0, 2, 3} {
		encoded := base64.StdEncoding.EncodeToString(append([]byte(strings.Repeat(" ", offset)), value...))
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
	return out
}

// stringMatch expresses a Sigma string as the simplest equivalent match: a
// literal with a position operator when wildcards only sit at the ends,
// otherwise an equivalent regular expression (`*` as `.*`, `?` as `.`).
// Literal `*` and `?` characters also take the regex form, so consumers that
// read those characters as wildcards in plain values cannot misread them.
func stringMatch(s sigmaString) (operator, value string) {
	start, end := 0, len(s)
	for start < end && s[start].wildcard == '*' {
		start++
	}
	for end > start && s[end-1].wildcard == '*' {
		end--
	}
	openStart, openEnd := start > 0, end < len(s)
	core := s[start:end]
	if !core.hasWildcards() && !strings.ContainsAny(core.literal(), "*?") {
		literal := core.literal()
		switch {
		case literal == "" && (openStart || openEnd):
			return "exists", "true"
		case openStart && openEnd:
			return "contains", literal
		case openStart:
			return "endswith", literal
		case openEnd:
			return "startswith", literal
		default:
			return "=", literal
		}
	}
	var re strings.Builder
	if !openStart {
		re.WriteString("^")
	}
	for _, part := range core {
		switch part.wildcard {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(part.text))
		}
	}
	if !openEnd {
		re.WriteString("$")
	}
	return "matches", re.String()
}
