package sigma

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// tokenType represents the type of a lexer token.
type tokenType int

const (
	tokIdent  tokenType = iota // identifier (detection item name)
	tokAnd                     // "and"
	tokOr                      // "or"
	tokNot                     // "not"
	tokLParen                  // "("
	tokRParen                  // ")"
	tokPipe                    // "|"
	tokNumber                  // integer literal
	tokFloat                   // other number, such as 0.5 or 1e3
	tokGT                      // ">"
	tokGTE                     // ">="
	tokLT                      // "<"
	tokLTE                     // "<="
	tokEQ                      // "="
	tokOf                      // "of"
	tokNear                    // "near"
	tokBy                      // "by"
	tokStar                    // "*"
	tokComma                   // ","
	tokString                  // quoted string
	tokThem                    // "them"
	tokAll                     // "all" (as quantifier)
	tokEOF                     // end of input
)

// token represents a single lexer token.
type token struct {
	typ tokenType
	val string
	pos int
}

// conditionLexer tokenizes Sigma condition expressions.
type conditionLexer struct {
	budget *parseBudget
	input  string
	pos    int
	tokens []token
	errors []string // characters the condition grammar does not know
}

// newConditionLexer creates a lexer and tokenizes the input.
func newConditionLexer(input string, budgets ...*parseBudget) *conditionLexer {
	b := budgetFrom(budgets)
	b.step(len(input))
	l := &conditionLexer{input: input, budget: b}
	l.tokenize()
	return l
}

func (l *conditionLexer) tokenize() {
	for l.pos < len(l.input) {
		if l.budget != nil {
			l.budget.step(1)
			l.budget.node(1)
		}
		ch := l.input[l.pos]
		// Operators and digits are ASCII bytes; a letter may span several.
		r, width := utf8.DecodeRuneInString(l.input[l.pos:])

		// Skip whitespace
		if unicode.IsSpace(r) {
			l.pos += width
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
			} else if isIdentChar(r) {
				l.readIdentOrKeyword()
			} else {
				l.errors = append(l.errors, l.budget.formatError("unexpected character %q in condition", l.input[start:start+width]))
				l.pos += width
			}
		}
	}
	l.tokens = append(l.tokens, token{tokEOF, "", l.pos})
}

func (l *conditionLexer) readString(quote byte) {
	start := l.pos
	l.pos++ // skip opening quote
	for l.pos < len(l.input) && l.input[l.pos] != quote {
		if l.budget != nil {
			l.budget.step(1)
		}
		if l.input[l.pos] == '\\' {
			l.pos++ // skip escape
		}
		l.pos++
	}
	end := min(l.pos, len(l.input)) // an unterminated string runs to the end
	if l.pos < len(l.input) {
		l.pos++ // skip closing quote
	}
	val := l.input[start+1 : end]
	l.tokens = append(l.tokens, token{tokString, val, start})
}

// readNumber reads a word that starts with a digit whole: an integer, another
// number such as 0.5 or 1e3, or otherwise an identifier such as 1st or 4688_a.
func (l *conditionLexer) readNumber() {
	l.readIdentOrKeyword() // no keyword starts with a digit
	word := &l.tokens[len(l.tokens)-1]
	switch {
	case strings.Trim(word.val, "0123456789") == "":
		word.typ = tokNumber
	case numericTextRe.MatchString(word.val):
		word.typ = tokFloat
	}
}

func (l *conditionLexer) readIdentOrKeyword() {
	start := l.pos
	for l.pos < len(l.input) {
		r, width := utf8.DecodeRuneInString(l.input[l.pos:])
		if !isIdentChar(r) {
			break
		}
		if l.budget != nil {
			l.budget.step(1)
		}
		l.pos += width
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
