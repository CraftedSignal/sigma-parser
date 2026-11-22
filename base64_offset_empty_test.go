package sigma

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestBase64OffsetReferenceSlices(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"", []string{"", "", ""}},
		{"a", []string{"Y", "", "h"}},
		{"ab", []string{"YW", "Fi", "hY"}},
		{"abcdef", []string{"YWJjZGVm", "FiY2RlZ", "hYmNkZW"}},
		{"test", []string{"dGVzd", "Rlc3", "0ZXN0"}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := base64OffsetVariants(tc.input); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("offset slices = %q, want reference slices %q", got, tc.want)
			}
		})
	}
}

func offsetRule(field, value, condition string) string {
	return "title: Empty offset regression\nlogsource: {product: test}\ndetection:\n  selection:\n    Gate: ok\n    " + field + ": " + value + "\n  condition: " + condition + "\n"
}

// offsetShape checks the complete grouping and typed string conditions without
// requiring a particular redundant representation of one identical alternative.
func offsetShape(e *Expression) string {
	if e == nil {
		return "nil"
	}
	if e.Kind == ExpressionCondition {
		c := e.Condition
		if c == nil {
			return "missing condition"
		}
		return fmt.Sprintf("%s %s %q", c.Field, c.Operator, conditionValues(*c))
	}
	var children []string
	for _, child := range e.Children {
		children = append(children, offsetShape(child))
	}
	return string(e.Kind) + "(" + strings.Join(children, ",") + ")"
}

func TestBase64OffsetPublicEmptyAndShort(t *testing.T) {
	for _, tc := range []struct {
		name, field, value, condition, fieldShape string
		fieldNot, selectionNot, all               bool
	}{
		{name: "empty", field: "Field|base64offset", value: "''", fieldShape: `Field = [""]`},
		{name: "short", field: "Field|base64offset", value: "'a'", fieldShape: `Field = ["Y" "" "h"]`},
		{name: "list", field: "Field|base64offset", value: "['', 'test']", fieldShape: `Field = ["" "dGVzd" "Rlc3" "0ZXN0"]`},
		{name: "duplicate empty", field: "Field|base64offset", value: "['', '']", fieldShape: `Field = [""]`},
		{name: "all", field: "Field|base64offset|all", value: "['', 'test']", fieldShape: `and(Field = [""],Field = ["dGVzd" "Rlc3" "0ZXN0"])`, all: true},
		{name: "negated selection", field: "Field|base64offset", value: "''", condition: "not selection", fieldShape: `Field = [""]`, selectionNot: true},
		{name: "neq list", field: "Field|base64offset|neq", value: "['', 'test']", fieldShape: `not(Field = ["" "dGVzd" "Rlc3" "0ZXN0"])`, fieldNot: true},
		{name: "repeated selection clone", field: "Field|base64offset", value: "''", condition: "selection and selection", fieldShape: `Field = [""]`},
		{name: "plain empty control", field: "Field", value: "''", fieldShape: `Field = [""]`},
		{name: "base64 empty control", field: "Field|base64", value: "''", fieldShape: `Field = [""]`},
		{name: "windash chain", field: "Field|base64offset|windash", value: "''", fieldShape: `Field = [""]`},
		{name: "later encoding", field: "Field|base64offset|base64", value: "'a'", fieldShape: `Field = ["WQ==" "" "aA=="]`},
		{name: "encoding empty", field: "Field|base64offset|utf16le|base64", value: "''", fieldShape: `Field = [""]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			condition := tc.condition
			if condition == "" {
				condition = "selection"
			}
			rule := offsetRule(tc.field, tc.value, condition)
			parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
			if len(parsed.Errors)+len(semantic.Errors) != 0 {
				t.Fatalf("errors: %v / %v", parsed.Errors, semantic.Errors)
			}
			selection := `and(Gate = ["ok"],` + tc.fieldShape + ")"
			want := selection
			if tc.selectionNot {
				want = "not(" + selection + ")"
			} else if condition == "selection and selection" {
				want = "and(" + selection + "," + selection + ")"
			}
			for name, tree := range map[string]*Expression{"parse": parsed.Expression, "semantic": semanticModifierExpression(semantic.Expression)} {
				if got := offsetShape(tree); got != want {
					t.Errorf("%s tree = %s, want %s", name, got, want)
				}
				for _, c := range expressionLeaves(tree) {
					if c.NumberText != "" || c.NullTest || c.ValueReference != "" || c.RequiresExpansion || c.CaseSensitive {
						t.Errorf("%s changed string metadata: %+v", name, c)
					}
				}
			}
			if !reflect.DeepEqual(parsed.Conditions, semantic.Conditions) {
				t.Fatal("public flat carriers differ")
			}
			// Flat metadata must keep both fields and the whole-selection/field
			// negations, while the authoritative tree above proves grouping.
			wantCount := 2
			if tc.all {
				wantCount = 3
			}
			if len(parsed.Conditions) != wantCount || parsed.Conditions[0].Field != "Gate" || parsed.Conditions[0].Value != "ok" || parsed.Conditions[0].Negated != tc.selectionNot {
				t.Fatalf("flat Gate/Field inventory = %+v", parsed.Conditions)
			}
			leaves := expressionLeaves(parsed.Expression)
			for i, c := range parsed.Conditions[1:] {
				wantOp := "AND"
				if tc.selectionNot {
					wantOp = "OR"
				}
				if c.Field != "Field" || c.Negated != (tc.selectionNot || tc.fieldNot) || c.LogicalOp != wantOp {
					t.Errorf("flat Field metadata = %+v", c)
				}
				if c.Operator != leaves[i+1].Operator || !reflect.DeepEqual(conditionValues(c), conditionValues(leaves[i+1])) {
					t.Errorf("flat Field lost the proved tree values: %+v / %+v", c, leaves[i+1])
				}
			}
			if len(semantic.Detections) != 1 || semantic.Detections[0].Name != "selection" {
				t.Fatalf("missing detection inventory: %+v", semantic.Detections)
			}
			wantInventory := append([]Condition(nil), parsed.Conditions...)
			if tc.selectionNot {
				for i := range wantInventory {
					wantInventory[i].Negated = false
					if i > 0 {
						wantInventory[i].LogicalOp = "AND"
					}
				}
			}
			if !reflect.DeepEqual(semantic.Detections[0].Conditions, wantInventory) {
				t.Errorf("detection inventory = %+v; want %+v", semantic.Detections[0].Conditions, wantInventory)
			}
		})
	}
}

func TestBase64OffsetEmptyPositionProjection(t *testing.T) {
	// This pins the existing wildcard-only projection; it is not a backend
	// missing/null truth claim.
	for _, position := range []string{"contains", "startswith", "endswith"} {
		for _, encoding := range []string{"", "base64offset|"} {
			rule := offsetRule("Field|"+encoding+position, "''", "selection")
			parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
			if len(parsed.Errors)+len(semantic.Errors) != 0 {
				t.Fatalf("errors: %v / %v", parsed.Errors, semantic.Errors)
			}
			for name, tree := range map[string]*Expression{"parse": parsed.Expression, "semantic": semanticModifierExpression(semantic.Expression)} {
				leaves := expressionLeaves(tree)
				if tree == nil || tree.Kind != ExpressionAnd || len(leaves) < 2 || leaves[0].Field != "Gate" {
					t.Fatalf("%s lost AND Field: %s", name, offsetShape(tree))
				}
				for _, c := range leaves[1:] {
					if c.Field != "Field" || c.Operator != "exists" || c.Value != "true" || c.NullTest {
						t.Errorf("%s projection = %+v", name, c)
					}
				}
			}
		}
	}
}

func TestBase64OffsetEmptySharedBudgetBoundaries(t *testing.T) {
	rule := offsetRule("Field|base64offset|windash|base64", "['', 'a']", "selection and selection")
	for _, semantic := range []bool{false, true} {
		t.Run(fmt.Sprint(semantic), func(t *testing.T) {
			var used parseBudget
			type result struct {
				conditions                  []Condition
				hasExpression, hasDetection bool
				errors                      []string
			}
			run := func(limits parseLimits) result {
				return guardedWithLimits(context.Background(), rule, limits, func(b *parseBudget) result {
					var got result
					if semantic {
						r := analyzeQuery(rule, b)
						got = result{r.Conditions, r.Expression != nil, len(r.Detections) > 0, r.Errors}
					} else {
						r := extractConditionsInternal(rule, b)
						got = result{r.Conditions, r.Expression != nil, false, r.Errors}
					}
					used = *b
					return got
				}, func(message string) result { return result{errors: []string{message}} })
			}
			if baseline := run(defaultParseLimits()); len(baseline.errors) > 0 || len(baseline.conditions) < 2 || !baseline.hasExpression {
				t.Fatalf("invalid baseline: %+v", baseline)
			}
			for _, tc := range []struct {
				name string
				used int
				set  func(*parseLimits, int)
			}{
				{"variants", used.variants, func(l *parseLimits, n int) { l.variants = n }},
				{"output bytes", used.outputBytes, func(l *parseLimits, n int) { l.outputBytes = n }},
				{"conditions", used.conditions, func(l *parseLimits, n int) { l.conditions = n }},
				{"nodes", used.nodes, func(l *parseLimits, n int) { l.nodes = n }},
				{"work", used.work, func(l *parseLimits, n int) { l.work = n }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if tc.used <= 0 {
						t.Fatal("missing budget charge")
					}
					limits := defaultParseLimits()
					tc.set(&limits, tc.used)
					if got := run(limits); len(got.errors) > 0 {
						t.Fatalf("exact budget rejected: %v", got.errors)
					}
					tc.set(&limits, tc.used-1)
					got := run(limits)
					if !strings.Contains(strings.Join(got.errors, " "), tc.name) || len(got.conditions) != 0 || got.hasExpression || got.hasDetection {
						t.Fatalf("one-short budget not atomic: %+v", got)
					}
				})
			}
		})
	}
}

func TestBase64OffsetEmptyCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rule := offsetRule("Field|base64offset", "''", "selection")
	parsed, semantic := ExtractConditionsContext(ctx, rule), AnalyzeQueryContext(ctx, rule)
	if len(parsed.Conditions) != 0 || parsed.Expression != nil || !strings.Contains(strings.Join(parsed.Errors, " "), "context canceled") {
		t.Fatalf("canceled extraction returned partial semantics: %+v", parsed)
	}
	if len(semantic.Conditions) != 0 || semantic.Expression != nil || len(semantic.Detections) != 0 || !strings.Contains(strings.Join(semantic.Errors, " "), "context canceled") {
		t.Fatalf("canceled analysis returned partial semantics: %+v", semantic)
	}
}
