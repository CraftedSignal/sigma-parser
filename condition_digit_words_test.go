package sigma

import (
	"strings"
	"testing"
)

// A word that starts with a digit is read whole, as pySigma and the Sigma 1
// reference parser read it: 1st and 4688_a are search identifiers, and an
// aggregation threshold keeps its fraction instead of being cut to its
// integer digits.
func TestConditionReadsWordsThatStartWithADigit(t *testing.T) {
	for _, tc := range []struct{ name, detection, want string }{
		{"identifier", "  1st: {A: 1}\n  sel: {B: 2}\n  condition: 1st and sel\n", "and: A B"},
		{"selector pattern", "  4688_a: {A: 1}\n  4688_b: {B: 2}\n  condition: 1 of 4688_*\n", "or: A B"},
	} {
		result := ExtractConditions("title: t\ndetection:\n" + tc.detection)
		if len(result.Errors) > 0 {
			t.Errorf("%s: unexpected errors %q", tc.name, result.Errors)
			continue
		}
		var fields []string
		for _, leaf := range expressionLeaves(result.Expression) {
			fields = append(fields, leaf.Field)
		}
		if got := string(result.Expression.Kind) + ": " + strings.Join(fields, " "); got != tc.want {
			t.Errorf("%s: expression %q, want %q", tc.name, got, tc.want)
		}
	}

	for _, value := range []string{"0.5", "1e3"} {
		threshold := ExtractConditions("title: t\ndetection:\n  sel: {A: 1}\n  condition: sel | avg(score) by host > " + value + "\n")
		if len(threshold.Errors) > 0 {
			t.Fatalf("avg(score) > %s: unexpected errors %q", value, threshold.Errors)
		}
		found := false
		for _, condition := range threshold.Conditions {
			if condition.Field == "avg(score)" {
				found = condition.Operator == ">" && condition.Value == value
			}
		}
		if !found {
			t.Fatalf("avg(score) > %s: conditions %+v", value, threshold.Conditions)
		}
	}

	// A quantifier is a whole number.
	fraction := ExtractConditions("title: t\ndetection:\n  sel_a: {A: 1}\n  sel_b: {B: 2}\n  condition: 2.5 of sel_*\n")
	if len(fraction.Errors) == 0 {
		t.Fatalf("2.5 of sel_* accepted without error: %+v", fraction.Expression)
	}
}
