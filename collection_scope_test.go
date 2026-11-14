package sigma

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Selectors belong to their rule's detection block, including in collections:
// https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html#condition
// Merging detection maps before resolving selectors changes the rule's truth table.
func TestCollectionQuantifiersStayWithinRule(t *testing.T) {
	for _, condition := range []string{"all of them", "all of *", "all of selection*", "1 of them", "2 of selection*", "not (all of them)", "[all of them, selection]"} {
		for _, count := range []int{2, 3} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/docs%d/reverse%t", condition, count, reverse), func(t *testing.T) {
					docs := []string{fmt.Sprintf("detection:\n  selection: {A: x}\n  selection_extra: {C: z}\n  _private: {Hidden: secret}\n  condition: %s\n", condition), "detection:\n  selection: {B: y}\n  _private: {Hidden: other}\n  condition: selection\n"}
					if count == 3 {
						docs = append(docs, "detection:\n  selection: {D: w}\n  condition: all of *\n")
					}
					if reverse {
						for i, j := 0, len(docs)-1; i < j; i, j = i+1, j-1 {
							docs[i], docs[j] = docs[j], docs[i]
						}
					}
					input := strings.Join(docs, "---\n")
					file := ExtractFile(input)
					if len(file.Errors) > 0 || len(file.Rules) != count {
						t.Fatalf("oracle: %+v", file)
					}
					want := &Expression{Kind: ExpressionOr}
					for _, rule := range file.Rules {
						if len(rule.Errors) > 0 {
							t.Fatal(rule.Errors)
						}
						want.Children = append(want.Children, rule.Expression)
					}
					got := ExtractConditions(input)
					if len(got.Errors) > 0 {
						t.Fatal(got.Errors)
					}
					if !reflect.DeepEqual(got.Expression, want) {
						t.Errorf("collection AST differs from OR of independent rules: got %#v, want %#v", got.Expression, want)
					}
					// All 16 assignments include events matching only the first or last rule.
					for bits := 0; bits < 16; bits++ {
						event := map[string]bool{"A": bits&1 != 0, "B": bits&2 != 0, "C": bits&4 != 0, "D": bits&8 != 0}
						if actual, expected := collectionScopeMatches(got.Expression, event), collectionScopeMatches(want, event); actual != expected {
							t.Fatalf("event %v: match=%t, want %t", event, actual, expected)
						}
					}
				})
			}
		}
	}
}

func collectionScopeMatches(expr *Expression, event map[string]bool) bool {
	if expr == nil {
		return false
	}
	if expr.Kind == ExpressionCondition {
		return event[expr.Condition.Field]
	}
	matches := 0
	for _, child := range expr.Children {
		if collectionScopeMatches(child, event) {
			matches++
		}
	}
	switch expr.Kind {
	case ExpressionAnd:
		return matches == len(expr.Children)
	case ExpressionOr:
		return matches > 0
	case ExpressionNot:
		return matches == 0
	case ExpressionThreshold:
		return matches >= expr.Threshold
	}
	return false
}

func TestCollectionSemanticSelectorsAreNamespaced(t *testing.T) {
	input := "detection:\n  selection: {A: x}\n  _private: {Hidden: secret}\n  condition: all of them\n---\ndetection:\n  selection: {B: y}\n  _private: {Hidden: other}\n  condition: all of _*\n"
	result := AnalyzeQuery(input)
	if len(result.Errors) > 0 {
		t.Fatal(result.Errors)
	}
	expected := &SemanticConditionExpression{Operator: "or", Children: []*SemanticConditionExpression{
		{Operator: "quantifier", Quantifier: "all", Pattern: "rule1_*"},
		{Operator: "quantifier", Quantifier: "all", Pattern: "_rule2_*"},
	}}
	if !reflect.DeepEqual(result.ConditionExpression, expected) {
		t.Errorf("condition expression = %#v, want %#v", result.ConditionExpression, expected)
	}
	var names []string
	for _, detection := range result.Detections {
		names = append(names, detection.Name)
	}
	if want := []string{"_rule1_private", "rule1_selection", "_rule2_private", "rule2_selection"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestCollectionQuantifierLiteralExpression(t *testing.T) {
	input := "detection:\n  selection: {A: x}\n  condition: all of them\n---\ndetection:\n  selection: {B: y}\n  condition: selection\n"
	result := ExtractConditions(input)
	want := &Expression{Kind: ExpressionOr, Children: []*Expression{
		{Kind: ExpressionCondition, Condition: &Condition{Field: "A", Operator: "=", Value: "x"}},
		{Kind: ExpressionCondition, Condition: &Condition{Field: "B", Operator: "=", Value: "y"}},
	}}
	if len(result.Errors) > 0 {
		t.Fatal(result.Errors)
	}
	if !reflect.DeepEqual(result.Expression, want) {
		t.Fatalf("got %+v, want literal OR(A=x, B=y)", result.Expression)
	}
	if wantConditions := []Condition{{Field: "A", Operator: "=", Value: "x"}, {Field: "B", Operator: "=", Value: "y", LogicalOp: "OR"}}; !reflect.DeepEqual(result.Conditions, wantConditions) {
		t.Fatalf("conditions = %+v, want %+v", result.Conditions, wantConditions)
	}
}
