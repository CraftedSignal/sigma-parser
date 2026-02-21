package sigma

import "strings"

// deduplicateStrings removes duplicate strings while preserving order.
func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// IsStatisticalQuery returns true if the Sigma rule contains aggregation functions.
func IsStatisticalQuery(result *ParseResult) bool {
	for _, cmd := range result.Commands {
		switch strings.ToLower(cmd) {
		case "count", "sum", "min", "max", "avg", "near":
			return true
		}
	}
	return false
}

// HasUnmappedComputedFields always returns false for Sigma (no computed fields).
func HasUnmappedComputedFields(_ *ParseResult) bool {
	return false
}

// HasComplexWhereConditions checks if any conditions use complex operators.
func HasComplexWhereConditions(result *ParseResult) bool {
	for _, c := range result.Conditions {
		switch c.Operator {
		case "matches", "cidrmatch":
			return true
		}
	}
	return false
}

// FirstJoinOrSubsearchStage returns -1 for Sigma (no joins/subqueries).
func FirstJoinOrSubsearchStage(_ string) int {
	return -1
}
