package sigma

import (
	"fmt"
	"reflect"
	"testing"
)

func TestConditionExponentShapedIdentifiers(t *testing.T) {
	for _, name := range []string{"1e3", "1E3", "1e-3"} {
		for _, selector := range []bool{false, true} {
			condition := name
			if selector {
				condition = "1 of " + name + "*"
			}
			t.Run(condition, func(t *testing.T) {
				rule := fmt.Sprintf("title: t\ndetection:\n  '%s': {Image: cmd.exe}\n  other: {Image: other.exe}\n  condition: '%s'\n", name, condition)
				result := ExtractConditions(rule)
				if len(result.Errors) != 0 {
					t.Fatalf("unexpected errors: %v", result.Errors)
				}
				if len(result.Conditions) != 1 || result.Conditions[0].Field != "Image" || result.Conditions[0].Operator != "=" || result.Conditions[0].Value != "cmd.exe" {
					t.Fatalf("wrong selected conditions: %+v", result.Conditions)
				}
				if result.Expression == nil || result.Expression.Kind != ExpressionCondition || result.Expression.Condition == nil || !reflect.DeepEqual(*result.Expression.Condition, result.Conditions[0]) {
					t.Fatalf("wrong selected expression: %+v", result.Expression)
				}
			})
		}
	}
	for _, condition := range []string{"1.5", "1e+3", "1 of 1.5*", "1 of 1e+3*", "1e3 of sel_*"} {
		t.Run("invalid_"+condition, func(t *testing.T) {
			rule := fmt.Sprintf("title: t\ndetection:\n  '1.5': {Image: cmd.exe}\n  '1e+3': {Image: cmd.exe}\n  sel_a: {Image: cmd.exe}\n  condition: '%s'\n", condition)
			if result := ExtractConditions(rule); len(result.Errors) == 0 {
				t.Fatalf("invalid condition accepted: %+v", result)
			}
		})
	}
}
