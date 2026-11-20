package sigma

import (
	"strings"
	"testing"
)

// A condition that ends inside a quoted string is an error. A quote as the
// last character used to panic, and the recovered panic replaced the whole
// result, title and logsource included.
func TestConditionEndingInAQuoteIsAnError(t *testing.T) {
	for _, condition := range []string{`"sel '"`, `"sel 'x"`, `"sel '\\"`} {
		result := ExtractConditions("title: t\nlogsource: {product: windows}\ndetection:\n  sel: {A: 1}\n  condition: " + condition + "\n")
		if errors := strings.Join(result.Errors, "; "); errors == "" || strings.Contains(errors, "panic") {
			t.Errorf("condition %s: errors %q", condition, result.Errors)
		}
		if result.Title != "t" || result.LogSource == nil {
			t.Errorf("condition %s: lost the rule's metadata: title %q, logsource %v", condition, result.Title, result.LogSource)
		}
	}
}

// An aggregation that ends after its opening parenthesis is an error. It used
// to panic, and in ExtractFile the recovered panic lost every other rule of
// the file.
func TestAggregationEndingAfterParenthesisIsAnError(t *testing.T) {
	file := ExtractFile("title: good\ndetection:\n  sel: {A: 1}\n  condition: sel\n---\ntitle: bad\ndetection:\n  sel: {A: 1}\n  condition: sel | count(\n")
	if len(file.Errors) != 1 || file.Errors[0] != `rule "bad": expected closing parenthesis in aggregation` {
		t.Fatalf("errors %q", file.Errors)
	}
	if len(file.Rules) != 2 || file.Rules[0].Title != "good" || len(file.Rules[0].Errors) > 0 || len(expressionLeaves(file.Rules[0].Expression)) != 1 {
		t.Fatalf("the good rule was not kept: %d rules", len(file.Rules))
	}
}
