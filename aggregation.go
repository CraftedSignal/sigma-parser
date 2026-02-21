package sigma

import (
	"strconv"
	"strings"
)

// aggregation holds parsed aggregation data from a Sigma condition pipe expression.
type aggregation struct {
	function   string   // "count", "sum", "min", "max", "avg"
	field      string   // Field being aggregated (empty for count without args)
	groupBy    []string // Group-by fields
	comparison string   // ">", ">=", "<", "<=", "="
	threshold  string   // Threshold value
	isNear     bool     // True if this is a near aggregation
	nearItems  []string // Detection items for near
}

// parseAggregation parses an aggregation expression (text after | in condition).
// Examples:
//
//	count() > 5
//	count(fieldname) by src_ip > 10
//	sum(bytes) by host >= 1000
//	near selection1 and selection2
func parseAggregation(expr string, timeframe string) (*aggregation, []string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}

	// Check for "near" aggregation
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "near") {
		return parseNear(expr, timeframe)
	}

	return parseFunctionAggregation(expr)
}

// parseFunctionAggregation parses count/sum/min/max/avg aggregations.
func parseFunctionAggregation(expr string) (*aggregation, []string) {
	var errors []string
	agg := &aggregation{}

	// Tokenize for aggregation parsing
	lexer := newConditionLexer(expr)
	tokens := lexer.tokens
	pos := 0

	peek := func() token {
		if pos >= len(tokens) {
			return token{typ: tokEOF}
		}
		return tokens[pos]
	}
	advance := func() token {
		t := peek()
		if pos < len(tokens) {
			pos++
		}
		return t
	}

	// Parse function name
	t := advance()
	if t.typ != tokIdent {
		errors = append(errors, "expected aggregation function name")
		return nil, errors
	}

	funcName := strings.ToLower(t.val)
	switch funcName {
	case "count", "sum", "min", "max", "avg":
		agg.function = funcName
	default:
		errors = append(errors, "unknown aggregation function: "+t.val)
		return nil, errors
	}

	// Parse optional (field)
	if peek().typ == tokLParen {
		advance() // consume (
		if peek().typ != tokRParen {
			fieldTok := advance()
			agg.field = fieldTok.val
		}
		if peek().typ == tokRParen {
			advance() // consume )
		} else {
			errors = append(errors, "expected closing parenthesis in aggregation")
		}
	}

	// Parse optional "by field1, field2"
	if peek().typ == tokBy {
		advance() // consume "by"
		for {
			if peek().typ == tokIdent {
				agg.groupBy = append(agg.groupBy, advance().val)
			} else {
				break
			}
			if peek().typ == tokComma {
				advance()
			} else {
				break
			}
		}
	}

	// Parse comparison operator and threshold
	switch peek().typ {
	case tokGT:
		advance()
		agg.comparison = ">"
	case tokGTE:
		advance()
		agg.comparison = ">="
	case tokLT:
		advance()
		agg.comparison = "<"
	case tokLTE:
		advance()
		agg.comparison = "<="
	case tokEQ:
		advance()
		agg.comparison = "="
	}

	// Parse threshold value
	if peek().typ == tokNumber {
		agg.threshold = advance().val
	}

	return agg, errors
}

// parseNear parses "near" aggregation expressions.
// Example: near selection1 and selection2
func parseNear(expr string, _ string) (*aggregation, []string) {
	agg := &aggregation{isNear: true, function: "near"}

	// Strip "near" prefix
	rest := strings.TrimSpace(expr[4:])

	// Split on " and " (case-insensitive)
	parts := splitOnAnd(rest)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			agg.nearItems = append(agg.nearItems, p)
		}
	}

	return agg, nil
}

// splitOnAnd splits a string on " and " (case-insensitive).
func splitOnAnd(s string) []string {
	lower := strings.ToLower(s)
	var parts []string
	for {
		idx := strings.Index(lower, " and ")
		if idx < 0 {
			parts = append(parts, strings.TrimSpace(s))
			break
		}
		parts = append(parts, strings.TrimSpace(s[:idx]))
		s = s[idx+5:]
		lower = lower[idx+5:]
	}
	return parts
}

// toConditions converts an aggregation into Conditions and metadata.
func (a *aggregation) toConditions() ([]Condition, []string, []string) {
	if a == nil {
		return nil, nil, nil
	}

	var conditions []Condition
	var commands []string
	var groupBy []string

	if a.isNear {
		commands = append(commands, "near")
		// Near doesn't produce filterable conditions
		return conditions, groupBy, commands
	}

	commands = append(commands, a.function)
	groupBy = a.groupBy

	// Produce an aggregation condition
	if a.comparison != "" && a.threshold != "" {
		aggField := a.function
		if a.field != "" {
			aggField = a.function + "(" + a.field + ")"
		} else {
			aggField = a.function + "()"
		}

		conditions = append(conditions, Condition{
			Field:    aggField,
			Operator: a.comparison,
			Value:    a.threshold,
		})
	}

	return conditions, groupBy, commands
}

// parseTimeframe parses a Sigma timeframe string (e.g., "5m", "1h", "30s") into seconds.
func parseTimeframe(tf string) int {
	tf = strings.TrimSpace(tf)
	if tf == "" {
		return 0
	}

	// Split numeric prefix from unit suffix
	i := 0
	for i < len(tf) && (tf[i] >= '0' && tf[i] <= '9') {
		i++
	}
	if i == 0 {
		return 0
	}

	num, err := strconv.Atoi(tf[:i])
	if err != nil {
		return 0
	}

	unit := strings.ToLower(tf[i:])
	switch unit {
	case "s":
		return num
	case "m":
		return num * 60
	case "h":
		return num * 3600
	case "d":
		return num * 86400
	default:
		return num
	}
}
