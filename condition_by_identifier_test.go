package sigma

import (
	"reflect"
	"testing"
)

func TestConditionByIdentifier(t *testing.T) {
	for _, tc := range []struct {
		name, condition   string
		composed, grouped bool
	}{
		{name: "direct", condition: "by"},
		{name: "selector equivalent", condition: "1 of by"},
		{name: "AND NOT", condition: "by and not filter", composed: true},
		{name: "aggregation grouping", condition: "selection | count() by host > 1", grouped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractConditions("title: t\ndetection:\n  by: {Image: cmd.exe}\n  filter: {User: SYSTEM}\n  selection: {Image: cmd.exe}\n  condition: " + tc.condition + "\n")
			if len(result.Errors) != 0 {
				t.Fatalf("unexpected errors: %v", result.Errors)
			}
			expr := result.Expression
			if tc.composed {
				if expr == nil || expr.Kind != ExpressionAnd || len(expr.Children) != 2 {
					t.Fatalf("expected two-child AND: %+v", expr)
				}
				not := expr.Children[1]
				if not.Kind != ExpressionNot || len(not.Children) != 1 || not.Children[0].Condition == nil || not.Children[0].Condition.Field != "User" || not.Children[0].Condition.Value != "SYSTEM" {
					t.Fatalf("expected NOT User=SYSTEM: %+v", not)
				}
				if len(result.Conditions) != 2 || !result.Conditions[1].Negated || result.Conditions[1].LogicalOp != "AND" {
					t.Fatalf("wrong composed conditions: %+v", result.Conditions)
				}
				expr = expr.Children[0]
			}
			if expr == nil || expr.Kind != ExpressionCondition || expr.Condition == nil || expr.Condition.Field != "Image" || expr.Condition.Operator != "=" || expr.Condition.Value != "cmd.exe" {
				t.Fatalf("expected selected Image=cmd.exe: %+v", expr)
			}
			if tc.grouped {
				if !reflect.DeepEqual(result.GroupByFields, []string{"host"}) || !reflect.DeepEqual(result.Commands, []string{"count"}) {
					t.Fatalf("wrong aggregation metadata: groups=%v commands=%v", result.GroupByFields, result.Commands)
				}
				if len(result.Conditions) != 2 || result.Conditions[1].Field != "count()" || result.Conditions[1].Operator != ">" || result.Conditions[1].Value != "1" {
					t.Fatalf("wrong aggregation conditions: %+v", result.Conditions)
				}
			} else if !tc.composed && (len(result.Conditions) != 1 || !reflect.DeepEqual(result.Conditions[0], *expr.Condition)) {
				t.Fatalf("wrong selected conditions: %+v", result.Conditions)
			}
		})
	}
}
