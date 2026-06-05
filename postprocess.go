package sigma

import "strings"

// groupORConditions merges consecutive OR conditions on the same field and operator
// into a single Condition with Alternatives. Ported from spl-parser.
func groupORConditions(conditions []Condition) []Condition {
	if len(conditions) == 0 {
		return conditions
	}

	result := make([]Condition, 0, len(conditions))

	for i := 0; i < len(conditions); i++ {
		cond := conditions[i]

		// Look ahead for OR conditions on the same field
		if i+1 < len(conditions) && conditions[i+1].LogicalOp == "OR" && sameConditionGroup(cond, conditions[i+1]) {
			alternatives := conditionAlternatives(cond)

			j := i + 1
			for j < len(conditions) {
				next := conditions[j]
				if next.LogicalOp == "OR" && sameConditionGroup(cond, next) {
					alternatives = append(alternatives, conditionAlternatives(next)...)
					j++
				} else {
					break
				}
			}

			if len(alternatives) > 1 {
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

func sameConditionGroup(a, b Condition) bool {
	return strings.EqualFold(a.Field, b.Field) &&
		a.Operator == b.Operator &&
		a.Negated == b.Negated &&
		a.CaseSensitive == b.CaseSensitive
}

func conditionAlternatives(cond Condition) []string {
	if len(cond.Alternatives) > 0 {
		return append([]string(nil), cond.Alternatives...)
	}
	return []string{cond.Value}
}

// deduplicateConditions removes duplicate conditions by field+operator+value.
func deduplicateConditions(conditions []Condition) []Condition {
	if len(conditions) == 0 {
		return conditions
	}

	seen := make(map[string]bool)
	result := make([]Condition, 0, len(conditions))

	for _, cond := range conditions {
		key := conditionDedupKey(cond)
		if !seen[key] {
			seen[key] = true
			result = append(result, cond)
		}
	}

	return result
}

func conditionDedupKey(cond Condition) string {
	return strings.ToLower(cond.Field) + "|" +
		cond.Operator + "|" +
		cond.Value + "|" +
		boolKey(cond.Negated) + "|" +
		boolKey(cond.CaseSensitive) + "|" +
		strings.Join(cond.Alternatives, "\x00")
}

func boolKey(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
