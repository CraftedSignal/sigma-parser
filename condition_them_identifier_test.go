package sigma

import (
	"reflect"
	"testing"
)

func TestConditionThemIdentifier(t *testing.T) {
	const selections = "title: t\ndetection:\n  them: {Image: cmd.exe}\n  other: {Other: x}\n  condition: "
	t.Run("bare exact reference", func(t *testing.T) {
		result := ExtractConditions(selections + "them\n")
		want := Condition{Field: "Image", Operator: "=", Value: "cmd.exe"}
		if len(result.Errors) != 0 || !reflect.DeepEqual(result.Conditions, []Condition{want}) {
			t.Fatalf("expected exact them selection: errors=%v conditions=%+v", result.Errors, result.Conditions)
		}
		if !reflect.DeepEqual(result.Expression, &Expression{Kind: ExpressionCondition, Condition: &want}) {
			t.Fatalf("wrong exact-reference expression: %+v", result.Expression)
		}
	})
	t.Run("quantified expansion", func(t *testing.T) {
		result := ExtractConditions(selections + "1 of them\n")
		if len(result.Errors) != 0 {
			t.Fatalf("unexpected errors: %v", result.Errors)
		}
		if len(result.Conditions) != 2 || result.Conditions[0].Field != "Other" || result.Conditions[0].Value != "x" || result.Conditions[1].Field != "Image" || result.Conditions[1].Value != "cmd.exe" || result.Conditions[1].LogicalOp != "OR" {
			t.Fatalf("expected both selections: %+v", result.Conditions)
		}
		if result.Expression == nil || result.Expression.Kind != ExpressionOr || len(result.Expression.Children) != 2 {
			t.Fatalf("expected two-child OR: %+v", result.Expression)
		}
	})
	t.Run("undefined reference", func(t *testing.T) {
		result := ExtractConditions("title: t\ndetection:\n  other: {Other: x}\n  condition: them\n")
		want := []string{`condition references undefined search identifier "them"`}
		if !reflect.DeepEqual(result.Errors, want) {
			t.Fatalf("errors=%v, want %v", result.Errors, want)
		}
	})
}
