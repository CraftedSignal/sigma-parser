package sigma

import (
	"strings"
	"testing"
	"time"
)

func TestConditionNodeMarkersAndLexerEscapedStrings(t *testing.T) {
	condNodeRef{}.condNode()
	condNodeAnd{}.condNode()
	condNodeOr{}.condNode()
	condNodeNot{}.condNode()
	condNodeQuantifier{}.condNode()

	lexer := newConditionLexer(`"a\"b" 'c\\d'`)
	if len(lexer.tokens) < 3 {
		t.Fatalf("expected two string tokens and EOF, got %#v", lexer.tokens)
	}
	if lexer.tokens[0].typ != tokString || lexer.tokens[0].val != `a\"b` {
		t.Fatalf("expected escaped double-quoted token, got %#v", lexer.tokens[0])
	}
	if lexer.tokens[1].typ != tokString || lexer.tokens[1].val != `c\\d` {
		t.Fatalf("expected escaped single-quoted token, got %#v", lexer.tokens[1])
	}
}

func TestConditionParserEdgeBranches(t *testing.T) {
	for _, input := range []string{"(", "1 of", ","} {
		if _, _, errs := parseConditionExpr(input); len(errs) == 0 {
			t.Fatalf("expected parse error for %q", input)
		}
	}
	if _, _, errs := parseConditionExpr("@"); len(errs) == 0 {
		t.Fatal("expected skipped illegal character to produce empty-expression error")
	}
	if _, _, errs := parseConditionExpr("selection of them"); len(errs) == 0 {
		t.Fatal("expected invalid identifier-of syntax to leave trailing tokens")
	}
	parser := &conditionParser{}
	if tok := parser.peek(); tok.typ != tokEOF {
		t.Fatalf("empty parser should peek EOF, got %#v", tok)
	}

	node, _, errs := parseConditionExpr("all")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if ref, ok := node.(condNodeRef); !ok || ref.name != "all" {
		t.Fatalf("expected bare all to remain a reference, got %#v", node)
	}

	node, _, errs = parseConditionExpr("7")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if ref, ok := node.(condNodeRef); !ok || ref.name != "7" {
		t.Fatalf("expected bare number to remain a reference, got %#v", node)
	}
}

func TestConditionParserCanonicalOfQuantifiers(t *testing.T) {
	tests := []struct {
		input      string
		quantifier string
		pattern    string
	}{
		{"all of them", "all", "them"},
		{"1 of selection_*", "1", "selection_*"},
	}
	for _, tt := range tests {
		node, _, errs := parseConditionExpr(tt.input)
		if len(errs) != 0 {
			t.Fatalf("%s: unexpected errors: %v", tt.input, errs)
		}
		q, ok := node.(condNodeQuantifier)
		if !ok {
			t.Fatalf("%s: expected quantifier, got %T", tt.input, node)
		}
		if q.quantifier != tt.quantifier || q.pattern != tt.pattern {
			t.Fatalf("%s: got %q of %q", tt.input, q.quantifier, q.pattern)
		}
	}
}

func TestEvaluateAndExpressionFallbackEdges(t *testing.T) {
	item := func(name string, condition Condition) *detectionItem {
		return &detectionItem{name: name, expr: leafExpression(condition), conditions: []Condition{condition}}
	}
	items := map[string]*detectionItem{
		"sel_one": item("sel_one", Condition{Field: "Image", Operator: "=", Value: "a"}),
		"sel_two": item("sel_two", Condition{Field: "CommandLine", Operator: "contains", Value: "b"}),
		"_hidden": item("_hidden", Condition{Field: "User", Operator: "=", Value: "c"}),
	}
	if got := evaluateAST(condNodeQuantifier{quantifier: "1", pattern: "missing_*"}, items, false); got != nil {
		t.Fatalf("expected no matches for missing quantifier, got %+v", got)
	}
	if got := evaluateAST(condNodeRef{name: "missing"}, items, false); got != nil {
		t.Fatalf("expected missing ref to evaluate nil, got %+v", got)
	}
	if got := evaluateAST(nil, items, false); got != nil {
		t.Fatalf("expected nil fallback evaluation, got %+v", got)
	}
	negated := evaluateAST(condNodeQuantifier{quantifier: "all", pattern: "sel_*"}, items, true)
	if len(negated) != 2 || !negated[0].Negated || !negated[1].Negated || negated[1].LogicalOp != "OR" {
		t.Fatalf("expected negated all-of conditions joined by OR, got %+v", negated)
	}

	// Selector patterns match * anywhere and skip _ identifiers unless the
	// pattern itself starts with _ (Sigma rules specification, Condition).
	for pattern, want := range map[string][]string{
		"*two":  {"sel_two"},
		"sel_*": {"sel_one", "sel_two"},
		"s*_o*": {"sel_one"},
		"them":  {"sel_one", "sel_two"},
		"_*":    {"_hidden"},
		"other": nil,
	} {
		if got := matchDetectionItems(pattern, items); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("pattern %q matched %v, want %v", pattern, got, want)
		}
	}

	if expr := buildExpression(condNodeRef{name: "missing"}, items); expr != nil {
		t.Fatalf("expected missing expression to be nil, got %#v", expr)
	}
	if expr := buildExpression(condNodeQuantifier{quantifier: "many", pattern: "sel_*"}, items); expr == nil || expr.Kind != ExpressionOr {
		t.Fatalf("invalid quantifier should degrade to OR expression, got %#v", expr)
	}
	emptyItems := map[string]*detectionItem{"empty": {name: "empty"}}
	if expr := buildExpression(condNodeQuantifier{quantifier: "1", pattern: "empty"}, emptyItems); expr != nil {
		t.Fatalf("quantifier over empty selections should be nil, got %#v", expr)
	}
	if expr := buildExpression(condNodeNot{child: condNodeRef{name: "missing"}}, items); expr != nil {
		t.Fatalf("expected missing negated expression to be nil, got %#v", expr)
	}
	if expr := buildExpression(nil, items); expr != nil {
		t.Fatalf("unknown expression node should be nil, got %#v", expr)
	}
	if errs := conditionReferenceErrors(condNodeAnd{children: []condNode{condNodeRef{name: "missing"}, condNodeQuantifier{quantifier: "1", pattern: "filter_*"}}}, items); len(errs) != 2 {
		t.Fatalf("expected undefined reference and empty selector errors, got %v", errs)
	}
	if expr := compactExpression(ExpressionAnd, nil); expr != nil {
		t.Fatalf("empty compact expression should be nil, got %#v", expr)
	}
	single := &Expression{Kind: ExpressionCondition, Condition: &Condition{Field: "Image"}}
	if expr := compactExpression(ExpressionAnd, []*Expression{single}); expr != single {
		t.Fatalf("single compact expression should be returned unchanged, got %#v", expr)
	}
	if errs := validateExpression(nil); len(errs) != 0 {
		t.Fatalf("nil expression should have no validation errors, got %v", errs)
	}
}

func TestDetectionConditionParsingEdges(t *testing.T) {
	if node, _, _, errs := parseDetectionCondition(42); node != nil || len(errs) == 0 {
		t.Fatalf("expected unsupported condition type diagnostic, node=%#v errors=%v", node, errs)
	}

	node, _, multiple, errs := parseDetectionCondition([]any{"selection"})
	if len(errs) != 0 || node == nil || multiple {
		t.Fatalf("single condition list should parse without multiple flag, node=%#v multiple=%v errors=%v", node, multiple, errs)
	}
	node, _, multiple, errs = parseDetectionCondition([]any{})
	if len(errs) != 0 || node != nil || multiple {
		t.Fatalf("empty condition list should be empty without multiple flag, node=%#v multiple=%v errors=%v", node, multiple, errs)
	}
}

func TestDetectionResolutionEdgeBranches(t *testing.T) {
	if item, errs := resolveDetectionEntry("empty", nil); item == nil || item.name != "empty" || len(errs) == 0 {
		t.Fatalf("expected empty detection diagnostic, item=%#v errors=%v", item, errs)
	}
	// A plain value searches the whole event, as a keyword.
	item, errs := resolveDetectionEntry("plain", 4688)
	if len(errs) != 0 || !item.isKeyword || len(item.conditions) != 1 || item.conditions[0].Operator != "keyword" || item.conditions[0].Value != "4688" {
		t.Fatalf("plain value should be a keyword, item=%+v errors=%v", item, errs)
	}

	if expr, isKeyword, errs := resolveList(nil); expr != nil || isKeyword || len(errs) != 0 {
		t.Fatalf("empty list should be non-keyword empty, expr=%#v keyword=%v errors=%v", expr, isKeyword, errs)
	}
	expr, isKeyword, errs := resolveList([]any{orderedMap{{key: "Image", value: "cmd.exe"}}, "not-a-map"})
	if len(expressionLeaves(expr)) != 1 || isKeyword || len(errs) == 0 {
		t.Fatalf("mixed map list should preserve valid maps and report invalid item, expr=%#v keyword=%v errors=%v", expr, isKeyword, errs)
	}
	expr, isKeyword, errs = resolveList([]any{"mimikatz", "sekurlsa"})
	if len(errs) != 0 || !isKeyword || len(expressionLeaves(expr)) != 1 || len(expressionLeaves(expr)[0].Alternatives) != 2 {
		t.Fatalf("keyword list should be one keyword condition with alternatives, expr=%#v errors=%v", expr, errs)
	}

	for value, want := range map[any]string{int64(42): "42", 7: "7", 2.0: "2", 1.5: "1.5", true: "true", false: "false"} {
		leaves := expressionLeaves(mustFieldExpression(t, "Field", value))
		if len(leaves) != 1 || leaves[0].Value != want {
			t.Fatalf("value %#v should match as %q, got %+v", value, want, leaves)
		}
	}
	if values := conditionValues(expressionLeaves(mustFieldExpression(t, "Field", []any{"a", 2, true}))[0]); strings.Join(values, ",") != "a,2,true" {
		t.Fatalf("expected mixed list values, got %v", values)
	}

	mapExpr, _, errs := resolveFieldMap(orderedMap{{key: "A", value: "1"}, {key: "B", value: "2"}})
	if len(errs) != 0 || mapExpr.Kind != ExpressionAnd || len(mapExpr.Children) != 2 || mapExpr.Children[0].Condition.Field != "A" {
		t.Fatalf("expected map fields ANDed in authored order, expr=%#v errors=%v", mapExpr, errs)
	}
	if leaves := expressionLeaves(mustFieldExpression(t, "Field|exists", []any{})); len(leaves) != 1 || leaves[0].Operator != "exists" || leaves[0].Value != "false" {
		t.Fatalf("empty exists modifier list should coerce like null, got %+v", leaves)
	}
	if leaves := expressionLeaves(mustFieldExpression(t, "Field|exists", []any{"no"})); len(leaves) != 1 || leaves[0].Value != "false" {
		t.Fatalf("exists no should become false, got %+v", leaves)
	}
	if _, _, errs := fieldExpression("Field|unknown", "value"); len(errs) == 0 {
		t.Fatal("unsupported modifier should return diagnostics")
	}
}

func TestModifierDiagnosticAndEncodingEdges(t *testing.T) {
	if leaves := expressionLeaves(mustFieldExpression(t, "CommandLine|utf16", "A")); leaves[0].Value != "\xff\xfeA\x00" {
		t.Fatalf("expected UTF-16 with BOM, got %v", []byte(leaves[0].Value))
	}
	for _, field := range []string{"CommandLine|i", "CommandLine|unknown"} {
		if _, _, errs := fieldExpression(field, "value"); len(errs) == 0 {
			t.Fatalf("expected modifier diagnostic for %s", field)
		}
	}
	// The regex m and s flags and multi-value field references are valid
	// Sigma (modifiers appendix v2.1.0).
	for field, value := range map[string]any{"CommandLine|re|m": "^a", "CommandLine|re|s": "a.b", "Field|fieldref": []any{"A", "B"}} {
		if _, _, errs := fieldExpression(field, value); len(errs) != 0 {
			t.Fatalf("%s should be valid, got %v", field, errs)
		}
	}
}

func TestAggregationAndHelperEdges(t *testing.T) {
	if IsStatisticalQuery(nil) {
		t.Fatal("nil parse result should not be statistical")
	}
	if HasComplexWhereConditions(nil) {
		t.Fatal("nil parse result should not have complex conditions")
	}
	if HasUnmappedComputedFields(nil) {
		t.Fatal("Sigma should never report unmapped computed fields")
	}
	if agg, errs := parseAggregation("5 > 1", ""); agg != nil || len(errs) == 0 {
		t.Fatalf("expected aggregation function-name error, agg=%#v errors=%v", agg, errs)
	}
	if _, errs := parseAggregation("count(field > 1", ""); len(errs) == 0 {
		t.Fatal("expected aggregation closing-parenthesis diagnostic")
	}
	if _, errs := parseAggregation("count() by , > 1", ""); len(errs) != 0 {
		t.Fatalf("empty group-by list should stop parsing without error, got %v", errs)
	}
	agg, errs := parseAggregation("unknown() > 1", "")
	if agg != nil || len(errs) == 0 {
		t.Fatalf("unknown aggregation should return nil with errors, agg=%#v errors=%v", agg, errs)
	}
	if conds, groupBy, commands := (*aggregation)(nil).toConditions(); conds != nil || groupBy != nil || commands != nil {
		t.Fatalf("nil aggregation should produce no metadata, got %v %v %v", conds, groupBy, commands)
	}
	countOnly := &aggregation{function: "count"}
	if conds, groupBy, commands := countOnly.toConditions(); len(conds) != 0 || len(groupBy) != 0 || len(commands) != 1 || commands[0] != "count" {
		t.Fatalf("aggregation without threshold should only report command, got conds=%+v groupBy=%v commands=%v", conds, groupBy, commands)
	}
	if seconds := parseTimeframe("nonsense"); seconds != 0 {
		t.Fatalf("expected invalid timeframe to be 0, got %d", seconds)
	}
	if seconds := parseTimeframe(strings.Repeat("9", 1000) + "s"); seconds != 0 {
		t.Fatalf("expected overflowing timeframe to be 0, got %d", seconds)
	}

	result := &ParseResult{Conditions: []Condition{{Operator: "matches"}}}
	if !HasComplexWhereConditions(result) {
		t.Fatal("expected regex condition to be complex")
	}
	result.Conditions[0].Operator = "cidrmatch"
	if !HasComplexWhereConditions(result) {
		t.Fatal("expected CIDR condition to be complex")
	}
	result.Conditions[0].Operator = "="
	if HasComplexWhereConditions(result) {
		t.Fatal("plain equality should not be complex")
	}
	if HasUnmappedComputedFields(result) {
		t.Fatal("Sigma should not report unmapped computed fields")
	}
	if FirstJoinOrSubsearchStage("selection") != -1 {
		t.Fatal("Sigma has no join or subsearch stages")
	}
	if ClassifyFieldProvenance(result, "Image") != ProvenanceMain {
		t.Fatal("Sigma fields should classify as main provenance")
	}

	errResult := ExtractConditions("not: yaml: :")
	if errResult == nil || len(errResult.Errors) == 0 || errResult.ComputedFields == nil {
		t.Fatalf("invalid YAML should return errors and initialized metadata, got %#v", errResult)
	}
	if !strings.Contains(strings.Join(errResult.Errors, " "), "YAML") {
		t.Fatalf("expected YAML parse diagnostic, got %v", errResult.Errors)
	}

	grouped := groupORConditions([]Condition{
		{Field: "count()", Operator: ">", Value: "1"},
		{Field: "count()", Operator: ">", Value: "2", LogicalOp: "OR"},
		{Field: "Image", Operator: "=", Value: "a", CaseSensitive: true},
		{Field: "image", Operator: "=", Value: "b", LogicalOp: "OR", CaseSensitive: false},
	})
	if len(grouped) != 4 {
		t.Fatalf("comparisons or case-sensitive mismatches must not be grouped, got %+v", grouped)
	}
	if got := groupORConditions(nil); got != nil {
		t.Fatalf("nil group input should remain nil, got %+v", got)
	}
	if got := deduplicateConditions(nil); got != nil {
		t.Fatalf("nil dedup input should remain nil, got %+v", got)
	}
}

func TestExtractConditionsRecoveryAndEmptyConditionEdges(t *testing.T) {
	oldHook := extractHook
	oldMaxParseTime := maxParseTime
	defer func() {
		extractHook = oldHook
		maxParseTime = oldMaxParseTime
	}()

	extractHook = func(string) {
		panic("forced panic")
	}
	panicResult := ExtractConditions("title: panic")
	if panicResult == nil || len(panicResult.Errors) == 0 || !strings.Contains(panicResult.Errors[0], "panic") {
		t.Fatalf("expected panic recovery result, got %#v", panicResult)
	}

	extractHook = func(string) {
		time.Sleep(10 * time.Millisecond)
	}
	maxParseTime = time.Nanosecond
	timeoutResult := ExtractConditions("title: timeout")
	if timeoutResult == nil || len(timeoutResult.Errors) == 0 || !strings.Contains(timeoutResult.Errors[0], "timed out") {
		t.Fatalf("expected timeout recovery result, got %#v", timeoutResult)
	}

	extractHook = nil
	maxParseTime = oldMaxParseTime
	emptyResult := ExtractConditions(`
title: Empty Condition List
detection:
    selection:
        field: value
    condition: []
`)
	if emptyResult == nil || len(emptyResult.Errors) == 0 || !strings.Contains(strings.Join(emptyResult.Errors, " "), "empty condition expression") {
		t.Fatalf("expected empty condition diagnostic, got %#v", emptyResult)
	}

	badAggResult := ExtractConditions(`
title: Bad Aggregation
detection:
    selection:
        field: value
    condition:
        - selection | unknown() > 1
        - selection
`)
	if badAggResult == nil {
		t.Fatal("expected parse result")
	}
	foundUnknown := false
	for _, err := range badAggResult.Errors {
		if strings.Contains(err, "unknown aggregation function") {
			foundUnknown = true
			break
		}
	}
	if !foundUnknown {
		t.Fatalf("expected unknown aggregation diagnostic, got %v", badAggResult.Errors)
	}
}
