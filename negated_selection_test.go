package sigma

import (
	"strings"
	"testing"
)

// Negating a selection negates the AND of its fields, or the OR of its maps:
// NOT (B AND C) is NOT B OR NOT C. The flat Conditions link the negated
// fields as De Morgan's laws do, as they already did for the same logic
// written as not (fb and fc).
func TestFlatConditionsNegateSelectionsWithDeMorgan(t *testing.T) {
	for _, tc := range []struct{ name, detection, want string }{
		{
			name:      "negated map",
			detection: "  sel: {A: 1}\n  filter: {B: 2, C: 3}\n  condition: sel and not filter\n",
			want:      "A AND !B OR !C",
		},
		{
			name:      "same logic over one-field selections",
			detection: "  sel: {A: 1}\n  fb: {B: 2}\n  fc: {C: 3}\n  condition: sel and not (fb and fc)\n",
			want:      "A AND !B OR !C",
		},
		{
			name:      "negated list of maps",
			detection: "  filter:\n    - {B: 2, C: 3}\n    - {D: 4}\n  condition: not filter\n",
			want:      "!B OR !C AND !D",
		},
		{
			name:      "negated 1 of selector",
			detection: "  sel: {A: 1}\n  filter_a: {B: 2, C: 3}\n  filter_b: {D: 4}\n  condition: sel and not 1 of filter_*\n",
			want:      "A AND !B OR !C AND !D",
		},
		{
			name:      "negated all of selector",
			detection: "  sel: {A: 1}\n  filter_a: {B: 2, C: 3}\n  filter_b: {D: 4}\n  condition: sel and not all of filter_*\n",
			want:      "A AND !B OR !C OR !D",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractConditions("title: t\nlogsource: {product: windows}\ndetection:\n" + tc.detection)
			if len(result.Errors) > 0 {
				t.Fatalf("unexpected errors: %v", result.Errors)
			}
			var terms []string
			for _, condition := range result.Conditions {
				term := condition.Field
				if condition.Negated {
					term = "!" + term
				}
				if condition.LogicalOp != "" {
					term = condition.LogicalOp + " " + term
				}
				terms = append(terms, term)
			}
			if got := strings.Join(terms, " "); got != tc.want {
				t.Fatalf("flat conditions %q, want %q", got, tc.want)
			}
		})
	}
}
