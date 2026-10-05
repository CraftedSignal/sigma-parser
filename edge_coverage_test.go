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
	items := map[string]*detectionItem{
		"sel_one": {conditions: []Condition{{Field: "Image", Operator: "=", Value: "a"}}},
		"sel_two": {conditions: []Condition{{Field: "CommandLine", Operator: "contains", Value: "b"}}},
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

	if !globMatch("*two", "sel_two") || globMatch("*two", "sel_one") || globMatch("sel_*", "other") {
		t.Fatal("glob matching did not preserve prefix/suffix semantics")
	}
	if !globMatch("sel_one", "sel_one") || globMatch("sel_one", "sel_two") {
		t.Fatal("exact glob matching did not preserve equality semantics")
	}

	if expr := buildExpression(condNodeRef{name: "missing"}, items); expr != nil {
		t.Fatalf("expected missing expression to be nil, got %#v", expr)
	}
	if expr := buildExpression(condNodeQuantifier{quantifier: "many", pattern: "sel_*"}, items); expr == nil || expr.Kind != ExpressionOr {
		t.Fatalf("invalid quantifier should degrade to OR expression, got %#v", expr)
	}
	emptyItems := map[string]*detectionItem{
		"empty": {conditions: nil},
	}
	if expr := buildExpression(condNodeQuantifier{quantifier: "1", pattern: "empty"}, emptyItems); expr != nil {
		t.Fatalf("quantifier over empty selections should be nil, got %#v", expr)
	}
	if expr := buildExpression(condNodeNot{child: condNodeRef{name: "missing"}}, items); expr != nil {
		t.Fatalf("expected missing negated expression to be nil, got %#v", expr)
	}
	if expr := buildExpression(nil, items); expr != nil {
		t.Fatalf("unknown expression node should be nil, got %#v", expr)
	}
	if expr := expressionFromConditions(nil); expr != nil {
		t.Fatalf("empty condition expression should be nil, got %#v", expr)
	}
	expr := expressionFromConditions([]Condition{
		{Field: "Image", Operator: "=", Value: "cmd.exe"},
		{Field: "CommandLine", Operator: "contains", Value: "whoami", LogicalOp: "OR"},
	})
	if expr == nil || expr.Kind != ExpressionOr || len(expr.Children) != 2 {
		t.Fatalf("expected OR expression from condition logical op, got %#v", expr)
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
	item, errs := resolveDetectionEntry("bad", 123)
	if item == nil || item.name != "bad" || len(errs) == 0 {
		t.Fatalf("expected unsupported detection entry diagnostic, item=%#v errors=%v", item, errs)
	}

	conds, isKeyword, errs := resolveList(nil)
	if conds != nil || isKeyword || len(errs) != 0 {
		t.Fatalf("empty list should be non-keyword empty, conds=%v keyword=%v errors=%v", conds, isKeyword, errs)
	}

	conds, isKeyword, errs = resolveList([]any{map[string]any{"Image": "cmd.exe"}, "not-a-map"})
	if len(conds) != 1 || isKeyword || len(errs) == 0 {
		t.Fatalf("mixed map list should preserve valid maps and report invalid item, conds=%+v keyword=%v errors=%v", conds, isKeyword, errs)
	}

	conds, isKeyword, errs = resolveKeywordList(nil)
	if conds != nil || !isKeyword || len(errs) != 0 {
		t.Fatalf("empty keyword list should stay keyword metadata, conds=%v keyword=%v errors=%v", conds, isKeyword, errs)
	}

	if values, isNull := coerceToStringSlice(int64(42)); isNull || values[0] != "42" {
		t.Fatalf("expected int64 coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(7); isNull || values[0] != "7" {
		t.Fatalf("expected int coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(2.0); isNull || values[0] != "2" {
		t.Fatalf("expected integer float coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(1.5); isNull || values[0] != "1.5" {
		t.Fatalf("expected float coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(true); isNull || values[0] != "true" {
		t.Fatalf("expected true coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(false); isNull || values[0] != "false" {
		t.Fatalf("expected bool coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice([]any{"a", 2, true}); isNull || strings.Join(values, ",") != "a,2,true" {
		t.Fatalf("expected mixed list coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice(struct{ Name string }{"x"}); isNull || values[0] != "{x}" {
		t.Fatalf("expected default coercion, got values=%v null=%v", values, isNull)
	}
	if values, isNull := coerceToStringSlice([]any{nil}); !isNull || values != nil {
		t.Fatalf("all-null list should coerce to null, got values=%v null=%v", values, isNull)
	}

	fieldConds, errs := resolveFieldMap(map[string]any{
		"A": "1",
		"B": "2",
	})
	if len(errs) != 0 || len(fieldConds) != 2 || fieldConds[1].LogicalOp != "AND" {
		t.Fatalf("expected map fields joined by AND, conds=%+v errors=%v", fieldConds, errs)
	}
	conds, errs = resolveFieldValue("Field|exists", []any{})
	if len(errs) != 0 || len(conds) != 1 || conds[0].Operator != "exists" || conds[0].Value != "false" {
		t.Fatalf("empty exists modifier list should coerce like null, conds=%+v errors=%v", conds, errs)
	}
	conds, errs = resolveFieldValue("Field|exists", []any{"no"})
	if len(errs) != 0 || len(conds) != 1 || conds[0].Value != "false" {
		t.Fatalf("exists no should become false, conds=%+v errors=%v", conds, errs)
	}
	conds, errs = resolveFieldValue("Field", "*")
	if len(errs) != 0 || len(conds) != 1 || conds[0].Operator != "exists" || conds[0].Value != "true" {
		t.Fatalf("bare wildcard should become exists true, conds=%+v errors=%v", conds, errs)
	}
	conds, errs = resolveFieldValue("Field|unknown", "value")
	if len(conds) != 0 || len(errs) == 0 {
		t.Fatalf("unsupported modifier should return diagnostics, conds=%+v errors=%v", conds, errs)
	}
}

func TestModifierDiagnosticAndEncodingEdges(t *testing.T) {
	_, utf16Result := parseModifiers("CommandLine|utf16", []string{"A"})
	if len(utf16Result.values) != 1 || utf16Result.values[0] != "\xff\xfeA\x00" {
		t.Fatalf("expected UTF-16 with BOM, got %v", []byte(utf16Result.values[0]))
	}

	for _, field := range []string{"CommandLine|i", "CommandLine|re|m", "CommandLine|re|s", "CommandLine|unknown"} {
		_, result := parseModifiers(field, []string{"value"})
		if len(result.errors) == 0 {
			t.Fatalf("expected modifier diagnostic for %s", field)
		}
	}

	conds, errs := resolveFieldValue("Field|fieldref", []any{"A", "B"})
	if len(conds) != 0 || len(errs) == 0 {
		t.Fatalf("expected fieldref multi-value diagnostic, conds=%+v errors=%v", conds, errs)
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
