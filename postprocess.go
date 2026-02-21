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
		if i+1 < len(conditions) && conditions[i+1].LogicalOp == "OR" {
			fieldLower := strings.ToLower(cond.Field)
			alternatives := []string{cond.Value}
			// Include any existing alternatives from the first condition
			if len(cond.Alternatives) > 0 {
				alternatives = cond.Alternatives
			}

			j := i + 1
			for j < len(conditions) {
				next := conditions[j]
				if next.LogicalOp == "OR" && strings.ToLower(next.Field) == fieldLower && next.Operator == cond.Operator {
					if len(next.Alternatives) > 0 {
						alternatives = append(alternatives, next.Alternatives...)
					} else {
						alternatives = append(alternatives, next.Value)
					}
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

// deduplicateConditions removes duplicate conditions by field+operator+value.
func deduplicateConditions(conditions []Condition) []Condition {
	if len(conditions) == 0 {
		return conditions
	}

	seen := make(map[string]bool)
	result := make([]Condition, 0, len(conditions))

	for _, cond := range conditions {
		key := strings.ToLower(cond.Field) + "|" + cond.Operator + "|" + cond.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, cond)
		}
	}

	return result
}
