package sigma

import (
	"strings"
	"testing"
)

// A selector pattern takes * anywhere (Sigma rules specification, Condition:
// "Matching is done with * wildcards (any number of characters) at arbitrary
// positions in the pattern"). Like pySigma's identifier_pattern, a pattern is
// one word: a space ends it.
func TestSelectorPatternTakesWildcardsAnywhere(t *testing.T) {
	const detection = "title: t\ndetection:\n  sel_a_x: {A: 1}\n  sel_b_x: {B: 2}\n  sel_b_y: {C: 3}\n  a_filter: {D: 4}\n  condition: "
	for condition, want := range map[string]string{
		"1 of sel_*_x":                  "or: A B",
		"1 of *_x":                      "or: A B",
		"all of *b*":                    "and: B C",
		"all of sel_b*":                 "and: B C",
		"sel_a_x and not 1 of *_filter": "and: A D",
	} {
		result := ExtractConditions(detection + condition + "\n")
		if len(result.Errors) > 0 {
			t.Errorf("%s: unexpected errors %q", condition, result.Errors)
			continue
		}
		var fields []string
		for _, leaf := range expressionLeaves(result.Expression) {
			fields = append(fields, leaf.Field)
		}
		if got := string(result.Expression.Kind) + ": " + strings.Join(fields, " "); got != want {
			t.Errorf("%s: expression %q, want %q", condition, got, want)
		}
	}

	if spaced := ExtractConditions(detection + "1 of sel_ *_x\n"); len(spaced.Errors) == 0 {
		t.Errorf("1 of sel_ *_x: a pattern with a space accepted as %+v", spaced.Expression)
	}
}
