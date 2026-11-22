package sigma

import (
	"fmt"
	"reflect"
	"testing"
)

func TestConditionContextualKeywords(t *testing.T) {
	leaf := func(field string) *Expression {
		return &Expression{Kind: ExpressionCondition, Condition: &Condition{Field: field, Operator: "=", Value: "v"}}
	}
	group := func(kind ExpressionKind, children ...*Expression) *Expression {
		return &Expression{Kind: kind, Children: children}
	}
	const names = "  of: {Of: v}\n  and: {And: v}\n  or: {Or: v}\n  not: {Not: v}\n  x: {X: v}\n  y: {Y: v}\n"
	const selections = "  sel_a: {A: v}\n  sel_b: {B: v}\n"
	for _, tc := range []struct {
		condition, detection string
		want                 *Expression
	}{
		{"of", names, leaf("Of")},
		{"and", names, leaf("And")},
		{"or", names, leaf("Or")},
		{"not", names, leaf("Not")},
		{"and and or", names, group(ExpressionAnd, leaf("And"), leaf("Or"))},
		{"not not", names, group(ExpressionNot, leaf("Not"))},
		{"not and", names, group(ExpressionNot, leaf("And"))},
		{"(not) and x", names, group(ExpressionAnd, leaf("Not"), leaf("X"))},
		{"x or y and not of", names, group(ExpressionOr, leaf("X"), group(ExpressionAnd, leaf("Y"), group(ExpressionNot, leaf("Of"))))},
		{"all of sel_*", selections, group(ExpressionAnd, leaf("A"), leaf("B"))},
		{"1 of them", selections, group(ExpressionOr, leaf("A"), leaf("B"))},
		{"not | count() by host > 1", names, leaf("Not")},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			result := ExtractConditions("title: t\ndetection:\n" + tc.detection + "  condition: " + tc.condition + "\n")
			if len(result.Errors) != 0 || !reflect.DeepEqual(result.Expression, tc.want) {
				t.Fatalf("errors=%v expression=%#v, want %#v", result.Errors, result.Expression, tc.want)
			}
			if tc.condition == "not | count() by host > 1" {
				if !reflect.DeepEqual(result.GroupByFields, []string{"host"}) || !reflect.DeepEqual(result.Commands, []string{"count"}) || len(result.Conditions) != 2 || result.Conditions[1].Field != "count()" || result.Conditions[1].Operator != ">" || result.Conditions[1].Value != "1" {
					t.Fatalf("wrong aggregation: %+v", result)
				}
			}
		})
	}
	for _, name := range []string{"of", "and", "or", "not"} {
		t.Run("undefined_"+name, func(t *testing.T) {
			result := ExtractConditions("title: t\ndetection:\n  x: {X: v}\n  condition: " + name + "\n")
			want := []string{fmt.Sprintf("condition references undefined search identifier %q", name)}
			if !reflect.DeepEqual(result.Errors, want) {
				t.Fatalf("errors=%v, want %v", result.Errors, want)
			}
		})
	}
	t.Run("malformed operator sequence", func(t *testing.T) {
		result := ExtractConditions("title: t\ndetection:\n" + names + "  condition: not and x\n")
		if len(result.Errors) == 0 {
			t.Fatalf("malformed condition accepted: %+v", result)
		}
	})
}
