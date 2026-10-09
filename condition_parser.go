package sigma

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// condNode is the interface for condition AST nodes.
type condNode interface {
	condNode()
}

// condNodeRef references a named detection item.
type condNodeRef struct {
	name string
}

func (condNodeRef) condNode() {}

// condNodeAnd represents an AND expression.
type condNodeAnd struct {
	children []condNode
}

func (condNodeAnd) condNode() {}

// condNodeOr represents an OR expression.
type condNodeOr struct {
	children []condNode
}

func (condNodeOr) condNode() {}

// condNodeNot represents a NOT expression.
type condNodeNot struct {
	child condNode
}

func (condNodeNot) condNode() {}

// condNodeQuantifier represents "X of Y" expressions.
type condNodeQuantifier struct {
	quantifier string // "1", "all", or a number
	pattern    string // detection name pattern (may contain wildcards) or "them"
}

func (condNodeQuantifier) condNode() {}

// conditionParser is a recursive descent parser for Sigma condition expressions.
type conditionParser struct {
	tokens []token
	pos    int
	errors []string
}

// parseConditionExpr parses a condition expression string and returns the AST
// plus any aggregation expression (text after |).
func parseConditionExpr(condStr string) (condNode, string, []string) {
	lexer := newConditionLexer(condStr)
	p := &conditionParser{tokens: lexer.tokens}
	node := p.parseOr()
	if next := p.peek(); next.typ != tokEOF && next.typ != tokPipe {
		p.errors = append(p.errors, fmt.Sprintf("unexpected token after condition expression: %q", next.val))
	}

	// Check for aggregation after pipe
	var aggExpr string
	if p.peek().typ == tokPipe {
		p.advance() // consume |
		// Collect rest of tokens as aggregation expression
		start := p.peek().pos
		aggExpr = strings.TrimSpace(condStr[start:])
	}

	return node, aggExpr, p.errors
}

func (p *conditionParser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *conditionParser) advance() token {
	t := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

// parseOr: orExpr := andExpr ("or" andExpr)*
func (p *conditionParser) parseOr() condNode {
	left := p.parseAnd()
	children := []condNode{left}

	for p.peek().typ == tokOr {
		p.advance()
		children = append(children, p.parseAnd())
	}

	if len(children) == 1 {
		return children[0]
	}
	return condNodeOr{children: children}
}

// parseAnd: andExpr := notExpr ("and" notExpr)*
func (p *conditionParser) parseAnd() condNode {
	left := p.parseNot()
	children := []condNode{left}

	for p.peek().typ == tokAnd {
		p.advance()
		children = append(children, p.parseNot())
	}

	if len(children) == 1 {
		return children[0]
	}
	return condNodeAnd{children: children}
}

// parseNot: notExpr := "not" notExpr | atom
func (p *conditionParser) parseNot() condNode {
	if p.peek().typ == tokNot {
		p.advance()
		return condNodeNot{child: p.parseNot()}
	}
	return p.parseAtom()
}

// parseAtom: atom := "(" orExpr ")" | quantifier "of" pattern | identifier
func (p *conditionParser) parseAtom() condNode {
	t := p.peek()

	switch t.typ {
	case tokLParen:
		p.advance()
		node := p.parseOr()
		if p.peek().typ == tokRParen {
			p.advance()
		} else {
			p.errors = append(p.errors, "expected closing parenthesis")
		}
		return node

	case tokAll:
		// "all of ..."
		p.advance()
		if p.peek().typ == tokOf {
			p.advance()
			pattern := p.parsePattern()
			return condNodeQuantifier{quantifier: "all", pattern: pattern}
		}
		// If no "of", treat as identifier
		return condNodeRef{name: t.val}

	case tokNumber:
		// Could be "N of ..." quantifier
		num := t.val
		p.advance()
		if p.peek().typ == tokOf {
			p.advance()
			pattern := p.parsePattern()
			return condNodeQuantifier{quantifier: num, pattern: pattern}
		}
		// Just a number reference (unusual but handle)
		return condNodeRef{name: num}

	case tokIdent:
		p.advance()
		// "any of" is the same selector as "1 of"; any other word before "of"
		// is an identifier, and the dangling "of" fails the parse.
		if strings.EqualFold(t.val, "any") && p.peek().typ == tokOf {
			p.advance()
			return condNodeQuantifier{quantifier: "1", pattern: p.parsePattern()}
		}
		return condNodeRef{name: t.val}

	case tokEOF:
		p.errors = append(p.errors, "unexpected end of condition expression")
		return condNodeRef{name: ""}

	default:
		p.errors = append(p.errors, fmt.Sprintf("unexpected token: %q", t.val))
		p.advance()
		return condNodeRef{name: ""}
	}
}

// parsePattern parses the pattern after "of" — identifier, wildcard, or "them".
func (p *conditionParser) parsePattern() string {
	t := p.peek()
	switch t.typ {
	case tokThem:
		p.advance()
		return "them"
	case tokStar:
		p.advance()
		return "*"
	case tokIdent:
		p.advance()
		// Could be "selection*" (identifier with wildcard)
		if p.peek().typ == tokStar {
			p.advance()
			return t.val + "*"
		}
		return t.val
	default:
		p.errors = append(p.errors, fmt.Sprintf("expected pattern after 'of', got %q", t.val))
		return ""
	}
}

// evaluateAST walks the condition AST and emits Conditions by looking up
// detection items. The logicalOp and negated parameters are propagated down.
func evaluateAST(node condNode, items map[string]*detectionItem, negated bool) []Condition {
	switch n := node.(type) {
	case condNodeRef:
		item, ok := items[n.name]
		if !ok {
			return nil
		}
		conds := make([]Condition, len(item.conditions))
		copy(conds, item.conditions)
		if negated {
			for i := range conds {
				conds[i].Negated = !conds[i].Negated
			}
		}
		return conds

	case condNodeAnd:
		var result []Condition
		logicalOp := "AND"
		if negated {
			logicalOp = "OR"
		}
		for i, child := range n.children {
			childConds := evaluateAST(child, items, negated)
			if i > 0 && len(childConds) > 0 {
				childConds[0].LogicalOp = logicalOp
			}
			result = append(result, childConds...)
		}
		return result

	case condNodeOr:
		var result []Condition
		logicalOp := "OR"
		if negated {
			logicalOp = "AND"
		}
		for i, child := range n.children {
			childConds := evaluateAST(child, items, negated)
			if i > 0 && len(childConds) > 0 {
				childConds[0].LogicalOp = logicalOp
			}
			result = append(result, childConds...)
		}
		return result

	case condNodeNot:
		return evaluateAST(n.child, items, !negated)

	case condNodeQuantifier:
		return evaluateQuantifier(n, items, negated)

	default:
		return nil
	}
}

// evaluateQuantifier handles "X of Y" by glob-matching detection item names.
func evaluateQuantifier(q condNodeQuantifier, items map[string]*detectionItem, negated bool) []Condition {
	// Find matching detection items
	matchingNames := matchDetectionItems(q.pattern, items)

	if len(matchingNames) == 0 {
		return nil
	}

	isAll := q.quantifier == "all"

	var result []Condition
	for i, name := range matchingNames {
		item := items[name]
		conds := make([]Condition, len(item.conditions))
		copy(conds, item.conditions)

		if negated {
			for j := range conds {
				conds[j].Negated = !conds[j].Negated
			}
		}

		// Connect items: "all of" → AND, "1 of" / "N of" → OR.
		// Under NOT, apply De Morgan for the compatibility Conditions slice.
		if i > 0 && len(conds) > 0 {
			if isAll != negated {
				conds[0].LogicalOp = "AND"
			} else {
				conds[0].LogicalOp = "OR"
			}
		}

		result = append(result, conds...)
	}

	return result
}

// matchDetectionItems returns detection item names matching a pattern, sorted
// for determinism. Without the sort, map iteration order made quantifier
// evaluation ("N of selection_*", "all of them") non-deterministic, which
// could reorder — and in turn drop — extracted conditions across runs.
//
// Per the Sigma specification, `*` matches any characters at any position,
// and identifiers starting with `_` are excluded unless the pattern itself
// starts with `_`.
func matchDetectionItems(pattern string, items map[string]*detectionItem) []string {
	matcher := selectorPattern(pattern)
	var names []string
	for name := range items {
		if strings.HasPrefix(name, "_") && !strings.HasPrefix(pattern, "_") {
			continue
		}
		if matcher.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func selectorPattern(pattern string) *regexp.Regexp {
	if pattern == "them" {
		pattern = "*"
	}
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

// conditionReferenceErrors reports identifiers and selectors in a condition
// that match no search identifier. Sigma rejects such rules; dropping the
// reference would silently change what the rule matches.
func conditionReferenceErrors(node condNode, items map[string]*detectionItem) []string {
	switch n := node.(type) {
	case condNodeRef:
		if _, ok := items[n.name]; !ok && n.name != "" {
			return []string{fmt.Sprintf("condition references undefined search identifier %q", n.name)}
		}
	case condNodeQuantifier:
		if len(matchDetectionItems(n.pattern, items)) == 0 {
			return []string{fmt.Sprintf("condition selector %q of %q matches no search identifier", n.quantifier, n.pattern)}
		}
	case condNodeNot:
		return conditionReferenceErrors(n.child, items)
	case condNodeAnd:
		return childReferenceErrors(n.children, items)
	case condNodeOr:
		return childReferenceErrors(n.children, items)
	}
	return nil
}

func childReferenceErrors(children []condNode, items map[string]*detectionItem) []string {
	var errs []string
	for _, child := range children {
		errs = append(errs, conditionReferenceErrors(child, items)...)
	}
	return errs
}
