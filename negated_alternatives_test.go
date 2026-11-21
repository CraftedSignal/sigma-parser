package sigma

import (
	"fmt"
	"strings"
	"testing"
)

// A negated condition with Alternatives means that none of them match: not s
// over A|contains: [x, y] is NOT (x OR y). NOT x OR NOT y, which is what
// not (a and b) flattens to, is a different rule and keeps two conditions.
func TestFlatConditionsKeepNegatedOrApart(t *testing.T) {
	const notXOrNotY = `!A contains "x" OR !A contains "y"`
	for _, tc := range []struct{ name, rule, want string }{
		{
			name: "not of an and",
			rule: "title: t\ndetection:\n  a: {A|contains: x}\n  b: {A|contains: y}\n  condition: not (a and b)\n",
			want: notXOrNotY,
		},
		{
			name: "not all of",
			rule: "title: t\ndetection:\n  f1: {A|contains: x}\n  f2: {A|contains: y}\n  condition: not all of f*\n",
			want: notXOrNotY,
		},
		{
			name: "collection of negated rules",
			rule: "title: t\ndetection:\n  a: {A|contains: x}\n  condition: not a\n---\ntitle: u\ndetection:\n  b: {A|contains: y}\n  condition: not b\n",
			want: notXOrNotY,
		},
		{
			name: "not of a value list",
			rule: "title: t\ndetection:\n  s:\n    A|contains: [x, y]\n  condition: not s\n",
			want: `!A contains "x" ["x" "y"]`,
		},
		{
			name: "or of values",
			rule: "title: t\ndetection:\n  a: {A|contains: x}\n  b: {A|contains: y}\n  condition: a or b\n",
			want: `A contains "x" ["x" "y"]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractConditions(tc.rule)
			if len(result.Errors) > 0 {
				t.Fatalf("unexpected errors: %v", result.Errors)
			}
			var terms []string
			for _, condition := range result.Conditions {
				term := fmt.Sprintf("%s %s %q", condition.Field, condition.Operator, condition.Value)
				if len(condition.Alternatives) > 0 {
					term += fmt.Sprintf(" %q", condition.Alternatives)
				}
				if condition.Negated {
					term = "!" + term
				}
				if condition.LogicalOp != "" {
					term = condition.LogicalOp + " " + term
				}
				terms = append(terms, term)
			}
			if got := strings.Join(terms, " "); got != tc.want {
				t.Fatalf("flat conditions %s, want %s", got, tc.want)
			}
		})
	}
}
