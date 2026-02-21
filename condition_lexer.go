package sigma

import (
	"strings"
	"unicode"
)

// tokenType represents the type of a lexer token.
type tokenType int

const (
	tokIdent    tokenType = iota // identifier (detection item name)
	tokAnd                      // "and"
	tokOr                       // "or"
	tokNot                      // "not"
	tokLParen                   // "("
	tokRParen                   // ")"
	tokPipe                     // "|"
	tokNumber                   // integer literal
	tokGT                       // ">"
	tokGTE                      // ">="
	tokLT                       // "<"
	tokLTE                      // "<="
	tokEQ                       // "="
	tokOf                       // "of"
	tokNear                     // "near"
	tokBy                       // "by"
	tokStar                     // "*"
	tokComma                    // ","
	tokString                   // quoted string
	tokThem                     // "them"
	tokAll                      // "all" (as quantifier)
	tokEOF                      // end of input
)

// token represents a single lexer token.
type token struct {
	typ tokenType
	val string
	pos int
}

// conditionLexer tokenizes Sigma condition expressions.
type conditionLexer struct {
	input  string
	pos    int
	tokens []token
}

// newConditionLexer creates a lexer and tokenizes the input.
func newConditionLexer(input string) *conditionLexer {
	l := &conditionLexer{input: input}
	l.tokenize()
	return l
}

func (l *conditionLexer) tokenize() {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]

		// Skip whitespace
		if unicode.IsSpace(rune(ch)) {
			l.pos++
			continue
		}

		start := l.pos

		switch ch {
		case '(':
			l.tokens = append(l.tokens, token{tokLParen, "(", start})
			l.pos++
		case ')':
			l.tokens = append(l.tokens, token{tokRParen, ")", start})
			l.pos++
		case '|':
			l.tokens = append(l.tokens, token{tokPipe, "|", start})
			l.pos++
		case '*':
			l.tokens = append(l.tokens, token{tokStar, "*", start})
			l.pos++
		case ',':
			l.tokens = append(l.tokens, token{tokComma, ",", start})
			l.pos++
		case '=':
			l.tokens = append(l.tokens, token{tokEQ, "=", start})
			l.pos++
		case '>':
			if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
				l.tokens = append(l.tokens, token{tokGTE, ">=", start})
				l.pos += 2
			} else {
				l.tokens = append(l.tokens, token{tokGT, ">", start})
				l.pos++
			}
		case '<':
			if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
				l.tokens = append(l.tokens, token{tokLTE, "<=", start})
				l.pos += 2
			} else {
				l.tokens = append(l.tokens, token{tokLT, "<", start})
				l.pos++
			}
		case '"', '\'':
			l.readString(ch)
		default:
			if unicode.IsDigit(rune(ch)) {
				l.readNumber()
			} else if isIdentChar(rune(ch)) {
				l.readIdentOrKeyword()
			} else {
				// Skip unknown characters
				l.pos++
			}
		}
	}
	l.tokens = append(l.tokens, token{tokEOF, "", l.pos})
}

func (l *conditionLexer) readString(quote byte) {
	start := l.pos
	l.pos++ // skip opening quote
	for l.pos < len(l.input) && l.input[l.pos] != quote {
		if l.input[l.pos] == '\\' {
			l.pos++ // skip escape
		}
		l.pos++
	}
	if l.pos < len(l.input) {
		l.pos++ // skip closing quote
	}
	val := l.input[start+1 : l.pos-1]
	l.tokens = append(l.tokens, token{tokString, val, start})
}

func (l *conditionLexer) readNumber() {
	start := l.pos
	for l.pos < len(l.input) && unicode.IsDigit(rune(l.input[l.pos])) {
		l.pos++
	}
	l.tokens = append(l.tokens, token{tokNumber, l.input[start:l.pos], start})
}

func (l *conditionLexer) readIdentOrKeyword() {
	start := l.pos
	for l.pos < len(l.input) && isIdentChar(rune(l.input[l.pos])) {
		l.pos++
	}
	word := l.input[start:l.pos]
	lower := strings.ToLower(word)

	switch lower {
	case "and":
		l.tokens = append(l.tokens, token{tokAnd, word, start})
	case "or":
		l.tokens = append(l.tokens, token{tokOr, word, start})
	case "not":
		l.tokens = append(l.tokens, token{tokNot, word, start})
	case "of":
		l.tokens = append(l.tokens, token{tokOf, word, start})
	case "near":
		l.tokens = append(l.tokens, token{tokNear, word, start})
	case "by":
		l.tokens = append(l.tokens, token{tokBy, word, start})
	case "them":
		l.tokens = append(l.tokens, token{tokThem, word, start})
	case "all":
		l.tokens = append(l.tokens, token{tokAll, word, start})
	default:
		l.tokens = append(l.tokens, token{tokIdent, word, start})
	}
}

func isIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.'
}
