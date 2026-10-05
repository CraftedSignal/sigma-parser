package sigma

import "testing"

func TestAnalyzeQueryPreservesSelectorSemanticsAndModifiers(t *testing.T) {
	semantic := AnalyzeQuery(`
title: Sigma Semantic Rule
status: test
level: high
tags:
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith|cased:
      - '\cmd.exe'
      - '\powershell.exe'
  selection_command:
    CommandLine|contains|all:
      - '-enc'
      - 'IEX'
  filter:
    ParentImage|fieldref: Image
  condition: (1 of selection_* and not filter) or all of them
`)
	if semantic == nil {
		t.Fatal("expected semantic rule")
	}
	if len(semantic.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", semantic.Errors)
	}
	if semantic.Title != "Sigma Semantic Rule" || semantic.Level != "high" {
		t.Fatalf("metadata not preserved: %+v", semantic)
	}
	if semantic.LogSource == nil || semantic.LogSource.Category != "process_creation" || semantic.LogSource.Product != "windows" {
		t.Fatalf("logsource not preserved: %+v", semantic.LogSource)
	}
	if len(semantic.Tags) != 1 || semantic.Tags[0] != "attack.t1059" {
		t.Fatalf("tags not preserved: %+v", semantic.Tags)
	}

	expression := semantic.ConditionExpression
	if expression == nil || expression.Operator != "or" || len(expression.Children) != 2 {
		t.Fatalf("expected top-level OR condition expression, got %#v", expression)
	}
	left := expression.Children[0]
	if left.Operator != "and" || len(left.Children) != 2 {
		t.Fatalf("expected left AND group, got %#v", left)
	}
	oneOf := left.Children[0]
	if oneOf.Operator != "quantifier" || oneOf.Quantifier != "1" || oneOf.Pattern != "selection_*" {
		t.Fatalf("expected 1 of selection_* quantifier, got %#v", oneOf)
	}
	notFilter := left.Children[1]
	if notFilter.Operator != "not" || len(notFilter.Children) != 1 || notFilter.Children[0].Selector != "filter" {
		t.Fatalf("expected not filter selector, got %#v", notFilter)
	}
	allThem := expression.Children[1]
	if allThem.Operator != "quantifier" || allThem.Quantifier != "all" || allThem.Pattern != "them" {
		t.Fatalf("expected all of them quantifier, got %#v", allThem)
	}

	image := findSemanticDetection(t, semantic, "selection_image")
	if len(image.Conditions) != 1 {
		t.Fatalf("expected grouped image alternatives, got %+v", image.Conditions)
	}
	if image.Conditions[0].Operator != "endswith" || !image.Conditions[0].CaseSensitive {
		t.Fatalf("expected cased endswith condition, got %+v", image.Conditions[0])
	}
	if got := image.Conditions[0].Alternatives; len(got) != 2 || got[0] != `\cmd.exe` || got[1] != `\powershell.exe` {
		t.Fatalf("alternatives not preserved: %+v", got)
	}

	command := findSemanticDetection(t, semantic, "selection_command")
	if len(command.Conditions) != 2 || command.Conditions[1].LogicalOp != "AND" {
		t.Fatalf("expected contains|all to become AND conditions, got %+v", command.Conditions)
	}

	filter := findSemanticDetection(t, semantic, "filter")
	if len(filter.Conditions) != 1 || filter.Conditions[0].ValueReference != "Image" {
		t.Fatalf("expected fieldref to be preserved, got %+v", filter.Conditions)
	}
}

func TestSemanticInternalExtractionClonesExtractedResultAndExpression(t *testing.T) {
	expressionCondition := Condition{
		Field:        "Image",
		Operator:     "endswith",
		Value:        `\cmd.exe`,
		Alternatives: []string{`\cmd.exe`, `\powershell.exe`},
	}
	result := &ParseResult{
		Conditions: []Condition{{
			Field:        "CommandLine",
			Operator:     "contains",
			Value:        "-enc",
			Alternatives: []string{"-enc", "IEX"},
		}},
		Expression: &Expression{
			Kind:      ExpressionThreshold,
			Threshold: 2,
			Children: []*Expression{{
				Kind:      ExpressionCondition,
				Condition: &expressionCondition,
			}, nil},
		},
		GroupByFields:  []string{"User"},
		ComputedFields: map[string]string{"x": "y"},
		Commands:       []string{"count"},
		Joins: []JoinInfo{{
			Type:          "unused",
			JoinFields:    []string{"User"},
			Options:       map[string]string{"side": "left"},
			Subsearch:     "selection",
			PipeStage:     1,
			IsAppend:      true,
			ExposedFields: []string{"User"},
		}},
		Errors:    []string{"warning"},
		LogSource: &LogSource{Category: "process_creation", Product: "windows", Service: "sysmon"},
		Level:     "medium",
		Status:    "test",
		Title:     "Clone Rule",
		Tags:      []string{"attack.t1059"},
		Timeframe: "5m",
	}

	semantic := semanticFromExtraction(result)
	if semantic == nil {
		t.Fatal("expected semantic result")
	}

	result.Conditions[0].Value = "mutated"
	result.Conditions[0].Alternatives[0] = "mutated"
	expressionCondition.Value = "mutated"
	expressionCondition.Alternatives[0] = "mutated"
	result.GroupByFields[0] = "mutated"
	result.ComputedFields["x"] = "mutated"
	result.Commands[0] = "mutated"
	result.Joins[0].JoinFields[0] = "mutated"
	result.Joins[0].Options["side"] = "mutated"
	result.Joins[0].ExposedFields[0] = "mutated"
	result.Errors[0] = "mutated"
	result.LogSource.Category = "mutated"
	result.Tags[0] = "mutated"

	if semantic.Conditions[0].Value != "-enc" || semantic.Conditions[0].Alternatives[0] != "-enc" {
		t.Fatalf("conditions were aliased: %+v", semantic.Conditions)
	}
	if semantic.Expression.Kind != ExpressionThreshold || semantic.Expression.Threshold != 2 {
		t.Fatalf("threshold expression not preserved: %#v", semantic.Expression)
	}
	if semantic.Expression.Children[0].Condition.Value != `\cmd.exe` || semantic.Expression.Children[0].Condition.Alternatives[0] != `\cmd.exe` {
		t.Fatalf("expression condition was aliased: %+v", semantic.Expression.Children[0].Condition)
	}
	if semantic.GroupByFields[0] != "User" || semantic.ComputedFields["x"] != "y" || semantic.Commands[0] != "count" {
		t.Fatalf("common metadata was aliased: %+v", semantic)
	}
	if semantic.Joins[0].JoinFields[0] != "User" || semantic.Joins[0].Options["side"] != "left" || semantic.Joins[0].ExposedFields[0] != "User" {
		t.Fatalf("join metadata was aliased: %+v", semantic.Joins)
	}
	if semantic.Errors[0] != "warning" || semantic.LogSource.Category != "process_creation" || semantic.Tags[0] != "attack.t1059" {
		t.Fatalf("sigma metadata was aliased: %+v", semantic)
	}
}

func TestSemanticInternalExtractionNilAndEmptyInternal(t *testing.T) {
	if got := semanticFromExtraction(nil); got != nil {
		t.Fatalf("expected nil semantic result, got %+v", got)
	}
	semantic := semanticFromExtraction(&ParseResult{})
	if semantic == nil {
		t.Fatal("expected empty semantic result")
	}
	if semantic.Conditions != nil || semantic.Expression != nil || semantic.LogSource != nil || semantic.Joins != nil {
		t.Fatalf("empty result should not synthesize semantic data: %+v", semantic)
	}
}

func TestAnalyzeQueryInvalidYAMLStillReturnsSemanticErrors(t *testing.T) {
	semantic := AnalyzeQuery("detection: [")
	if semantic == nil {
		t.Fatal("expected semantic result with errors")
	}
	if len(semantic.Errors) == 0 {
		t.Fatalf("expected parse errors, got %+v", semantic)
	}
	if semantic.ConditionExpression != nil || len(semantic.Detections) != 0 {
		t.Fatalf("invalid YAML should not have selector details: %+v", semantic)
	}
}

func TestSemanticConditionExpressionEdges(t *testing.T) {
	if got := semanticConditionExpressionFromCondNode(nil); got != nil {
		t.Fatalf("expected nil node to convert to nil, got %#v", got)
	}
	if got := semanticConditionExpressionFromCondNode(unknownCondNode{}); got != nil {
		t.Fatalf("expected unknown node to convert to nil, got %#v", got)
	}
	if got := semanticConditionExpressionFromCondNode(condNodeNot{child: unknownCondNode{}}); got != nil {
		t.Fatalf("expected not unknown node to convert to nil, got %#v", got)
	}
	if got := semanticConditionExpressionGroup("and", nil); got != nil {
		t.Fatalf("expected empty group to convert to nil, got %#v", got)
	}
	single := semanticConditionExpressionGroup("and", []condNode{condNodeRef{name: "selection"}})
	if single == nil || single.Operator != "ref" || single.Selector != "selection" {
		t.Fatalf("expected single-child group to collapse to ref, got %#v", single)
	}
}

func TestSemanticDetectionEdges(t *testing.T) {
	if got := semanticDetectionsFromItems(nil); got != nil {
		t.Fatalf("expected nil detections for nil map, got %+v", got)
	}
	items := map[string]*detectionItem{
		"missing": nil,
		"keyword": {
			name:      "keyword",
			isKeyword: true,
			conditions: []Condition{{
				Operator: "keyword",
				Value:    "mimikatz",
			}},
		},
	}
	got := semanticDetectionsFromItems(items)
	if len(got) != 1 || got[0].Name != "keyword" || !got[0].Keyword {
		t.Fatalf("nil detection item not skipped or keyword not preserved: %+v", got)
	}
}

type unknownCondNode struct{}

func (unknownCondNode) condNode() {}

func findSemanticDetection(t *testing.T, semantic *SemanticQuery, name string) SemanticDetection {
	t.Helper()
	for _, detection := range semantic.Detections {
		if detection.Name == name {
			return detection
		}
	}
	t.Fatalf("missing detection %q in %+v", name, semantic.Detections)
	return SemanticDetection{}
}
