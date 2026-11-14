package sigma

import (
	"strconv"
	"strings"
)

// groupORConditions merges consecutive OR conditions on the same field and operator
// into a single Condition with Alternatives. Ported from spl-parser.
func groupORConditions(conditions []Condition, budgets ...*parseBudget) []Condition {
	b := budgetFrom(budgets)
	b.node(len(conditions))
	if len(conditions) == 0 {
		return conditions
	}

	result := make([]Condition, 0, len(conditions))

	for i := 0; i < len(conditions); i++ {
		b.step(1)
		cond := conditions[i]

		// Look ahead for OR conditions on the same field
		if i+1 < len(conditions) && conditions[i+1].LogicalOp == "OR" && sameConditionGroup(cond, conditions[i+1]) {
			alternatives := conditionAlternatives(cond, b)

			j := i + 1
			for j < len(conditions) {
				b.step(1)
				next := conditions[j]
				if next.LogicalOp == "OR" && sameConditionGroup(cond, next) {
					alternatives = append(alternatives, conditionAlternatives(next, b)...)
					j++
				} else {
					break
				}
			}

			if len(alternatives) > 1 {
				b.node(len(alternatives))
				cond.Alternatives = deduplicateStrings(alternatives)
				result = append(result, cond)
				i = j - 1
				continue
			}
		}

		result = append(result, cond)
	}

	return result
}

// comparisonOperators are ordering operators for which OR-runs must NOT be
// folded into Alternatives: `f > a OR f > b` is not a membership test over
// {a, b}, so merging would silently drop a bound (and, because the merge is
// position-dependent, make extraction non-deterministic).
var comparisonOperators = map[string]bool{">": true, ">=": true, "<": true, "<=": true}

// conditionIdentity holds all non-operand leaf metadata. LogicalOp is a
// connection in the legacy flat projection, not part of a predicate's identity.
// Field casing retains the existing expression/flat caller policies.
type conditionIdentity struct {
	Field, Operator, ValueReference, DatePart, SourceField                   string
	Negated, CaseSensitive, Multiline, DotAll, RequiresExpansion, IsComputed bool
	PipeStage                                                                int
}

func metadataIdentity(c Condition) conditionIdentity {
	return conditionIdentity{Field: c.Field, Operator: c.Operator, ValueReference: c.ValueReference,
		DatePart: c.DatePart, SourceField: c.SourceField, Negated: c.Negated,
		CaseSensitive: c.CaseSensitive, Multiline: c.Multiline, DotAll: c.DotAll,
		RequiresExpansion: c.RequiresExpansion, IsComputed: c.IsComputed, PipeStage: c.PipeStage}
}

func sameConditionGroup(a, b Condition) bool {
	ak, aok := alternativeKey(a)
	bk, bok := alternativeKey(b)
	if !aok || !bok || !strings.EqualFold(ak.Field, bk.Field) {
		return false
	}
	ak.Field, bk.Field = "", ""
	return ak == bk
}

func conditionAlternatives(cond Condition, budgets ...*parseBudget) []string {
	b := budgetFrom(budgets)
	b.node(1 + len(cond.Alternatives))
	if len(cond.Alternatives) > 0 {
		return append([]string(nil), cond.Alternatives...)
	}
	return []string{cond.Value}
}

// deduplicateConditions removes duplicate conditions by field+operator+value.
func deduplicateConditions(conditions []Condition, budgets ...*parseBudget) []Condition {
	b := budgetFrom(budgets)
	b.node(2 * len(conditions))
	if len(conditions) == 0 {
		return conditions
	}

	seen := make(map[conditionKey]bool)
	result := make([]Condition, 0, len(conditions))

	for _, cond := range conditions {
		b.step(1)
		key := conditionDedupKey(cond, b)
		if !seen[key] {
			seen[key] = true
			result = append(result, cond)
		}
	}

	return result
}

type conditionKey struct {
	Metadata            conditionIdentity
	Value, Alternatives string
}

// Length-prefixed alternatives preserve embedded separators, including NUL.
func conditionDedupKey(cond Condition, budgets ...*parseBudget) conditionKey {
	b := budgetFrom(budgets)
	metadata := metadataIdentity(cond)
	b.step(len(cond.Field) + len(cond.Value) + len(cond.Operator) + len(cond.ValueReference) + len(cond.DatePart) + len(cond.SourceField) + 1)
	b.output(len(cond.Field)) // possible lowercase field copy
	metadata.Field = strings.ToLower(cond.Field)
	var alternatives strings.Builder
	for _, value := range cond.Alternatives {
		b.step(len(value) + 1)
		b.output(len(value) + 24) // decimal length, separator, and value before allocation
		alternatives.WriteString(strconv.Itoa(len(value)))
		alternatives.WriteByte(':')
		alternatives.WriteString(value)
	}
	return conditionKey{Metadata: metadata, Value: cond.Value, Alternatives: alternatives.String()}
}
