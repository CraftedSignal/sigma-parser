package sigma

import (
	"reflect"
	"testing"
)

func TestExpressionPreservesCrossFieldOr(t *testing.T) {
	result := ExtractConditions(`
title: Cross-field OR
logsource:
  category: process_creation
detection:
  image_selection:
    Image|endswith: '\cmd.exe'
  command_selection:
    CommandLine|contains: whoami
  condition: image_selection or command_selection
`)
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if result.Expression == nil || result.Expression.Kind != ExpressionOr || len(result.Expression.Children) != 2 {
		t.Fatalf("expected two-child OR expression, got %#v", result.Expression)
	}
}

func TestExpressionPreservesNestedBooleanGroups(t *testing.T) {
	result := ExtractConditions(`
title: Nested expression
logsource:
  category: process_creation
detection:
  first:
    Image|endswith: '\cmd.exe'
  second:
    CommandLine|contains: whoami
  filter:
    User: SYSTEM
  condition: (first or second) and not filter
`)
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	expression := result.Expression
	if expression == nil || expression.Kind != ExpressionAnd || len(expression.Children) != 2 {
		t.Fatalf("expected top-level AND expression, got %#v", expression)
	}
	if expression.Children[0].Kind != ExpressionOr {
		t.Fatalf("expected first child to be OR, got %#v", expression.Children[0])
	}
	if expression.Children[1].Kind != ExpressionNot {
		t.Fatalf("expected second child to be NOT, got %#v", expression.Children[1])
	}
}

func TestExpressionPreservesNumericQuantifier(t *testing.T) {
	result := ExtractConditions(`
title: Threshold expression
logsource:
  category: process_creation
detection:
  selection_one:
    Image: one.exe
  selection_two:
    Image: two.exe
  selection_three:
    Image: three.exe
  condition: 2 of selection_*
`)
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if result.Expression == nil || result.Expression.Kind != ExpressionThreshold || result.Expression.Threshold != 2 {
		t.Fatalf("expected threshold expression, got %#v", result.Expression)
	}
}

func TestExpressionRejectsImpossibleThreshold(t *testing.T) {
	result := ExtractConditions(`
title: Invalid threshold
detection:
  selection:
    Image:
      - cmd.exe
      - powershell.exe
  condition: 3 of selection
`)
	if len(result.Errors) == 0 {
		t.Fatal("expected impossible threshold to be rejected")
	}
}

func TestExpressionCountsValuesOfSingleSelectionThreshold(t *testing.T) {
	result := ExtractConditions(`
title: Two evasive PowerShell flags
detection:
  selection_image:
    Image|endswith: '\powershell.exe'
  flags:
    CommandLine|contains:
      - '-NoProfile'
      - '-EncodedCommand'
      - '-NoProfile'
      - '-NonInteractive'
  condition: selection_image and 2 of flags
`)
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if result.Expression == nil || result.Expression.Kind != ExpressionAnd || len(result.Expression.Children) != 2 {
		t.Fatalf("expected image AND flag threshold, got %#v", result.Expression)
	}
	threshold := result.Expression.Children[1]
	if threshold.Kind != ExpressionThreshold || threshold.Threshold != 2 {
		t.Fatalf("expected 2-of threshold, got %#v", threshold)
	}
	var values []string
	for _, child := range threshold.Children {
		if child.Kind != ExpressionCondition || child.Condition.Field != "CommandLine" || child.Condition.Operator != "contains" || len(child.Condition.Alternatives) != 0 {
			t.Fatalf("expected one contains condition per value, got %#v", child)
		}
		values = append(values, child.Condition.Value)
	}
	if want := []string{"-NoProfile", "-EncodedCommand", "-NonInteractive"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("threshold values = %v, want %v", values, want)
	}
}

func TestExpressionWildcardThresholdStillCountsSelections(t *testing.T) {
	result := ExtractConditions(`
title: Wildcard threshold over one selection
detection:
  selection_flags:
    CommandLine|contains:
      - '-NoProfile'
      - '-EncodedCommand'
  condition: 2 of selection_*
`)
	if len(result.Errors) == 0 {
		t.Fatal("expected 2 of a wildcard matching one selection to be rejected")
	}
}
