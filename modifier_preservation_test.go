package sigma

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func modifierRule(detections, condition string) string {
	return "title: Modifier preservation\nlogsource: {category: process_creation}\ndetection:\n" + detections + "  condition: " + condition + "\n"
}

func TestPublicNullOrigin(t *testing.T) {
	for _, tc := range []struct {
		entry, condition      string
		wantNull, wantNegated bool
	}{
		{"Field: null", "sel", true, false},
		{"Field: ''", "sel", false, false},
		{"Field|exists: false", "sel", false, false},
		{"Field: null", "not sel", true, true},
		{"Field|neq: null", "sel", true, true},
	} {
		rule := modifierRule("  sel: {"+tc.entry+"}\n", tc.condition)
		parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
		if len(parsed.Errors)+len(semantic.Errors) != 0 {
			t.Fatalf("%s: %v / %v", tc.entry, parsed.Errors, semantic.Errors)
		}
		for name, conditions := range map[string][]Condition{"parse": parsed.Conditions, "semantic": semantic.Conditions} {
			if len(conditions) != 1 || conditions[0].NullTest != tc.wantNull || conditions[0].Negated != tc.wantNegated {
				t.Errorf("%s %s flat: %+v", name, tc.entry, conditions)
			}
		}
		for name, expression := range map[string]*Expression{"parse": parsed.Expression, "semantic": semanticModifierExpression(semantic.Expression)} {
			leaves := expressionLeaves(expression)
			if len(leaves) != 1 || leaves[0].NullTest != tc.wantNull {
				t.Errorf("%s %s expression: %+v", name, tc.entry, leaves)
			}
			if tc.wantNegated && (expression == nil || expression.Kind != ExpressionNot) {
				t.Errorf("%s %s lost whole-entry NOT: %#v", name, tc.entry, expression)
			}
		}
		if tc.wantNull {
			if parsed.Conditions[0].Operator != "exists" || parsed.Conditions[0].Value != "false" {
				t.Errorf("legacy null fields changed: %+v", parsed.Conditions[0])
			}
		}
		encoded, err := json.Marshal(parsed.Conditions[0])
		if err != nil || strings.Contains(string(encoded), "null_test") != tc.wantNull {
			t.Errorf("null origin JSON = %s, %v", encoded, err)
		}
	}
}

func TestNullOriginSurvivesCloneAndDedup(t *testing.T) {
	null := Condition{Field: "Field", Operator: "exists", Value: "false", NullTest: true}
	absent := Condition{Field: "Field", Operator: "exists", Value: "false"}
	cloned := cloneExpression(&Expression{Kind: ExpressionCondition, Condition: &null})
	if cloned.Condition == nil || !cloned.Condition.NullTest {
		t.Fatalf("clone lost authored null: %#v", cloned)
	}
	if semanticClone := cloneSemanticCondition(null); !semanticClone.NullTest {
		t.Fatalf("semantic clone lost authored null: %+v", semanticClone)
	}
	if got := deduplicateConditions([]Condition{null, absent, null}); len(got) != 2 || !got[0].NullTest || got[1].NullTest {
		t.Fatalf("null and absence collapsed: %+v", got)
	}
	rule := modifierRule("  a: {Field: null}\n  b: {Field|exists: false}\n", "a and b")
	for name, conditions := range map[string][]Condition{"parse": ExtractConditions(rule).Conditions, "semantic": AnalyzeQuery(rule).Conditions} {
		if len(conditions) != 2 || !conditions[0].NullTest || conditions[1].NullTest {
			t.Errorf("%s flat null/absence distinction: %+v", name, conditions)
		}
	}
}

func TestPublicEmptyDetectionFormsDiagnose(t *testing.T) {
	for _, detection := range []string{
		"  sel: []\n", "  sel: {}\n", "  sel: [{}, {Field: x}]\n", "  sel: {Field: []}\n", "  sel: {Field|contains: []}\n",
	} {
		rule := modifierRule(detection, "sel")
		parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
		if len(parsed.Errors) == 0 || len(semantic.Errors) == 0 {
			t.Errorf("%s: missing empty-form errors: %v / %v", detection, parsed.Errors, semantic.Errors)
		}
		if strings.Contains(detection, "{Field: x}") {
			if len(expressionLeaves(parsed.Expression)) != 1 || len(expressionLeaves(semanticModifierExpression(semantic.Expression))) != 1 {
				t.Errorf("valid map sibling was lost: %s", detection)
			}
		} else if parsed.Expression != nil || semantic.Expression != nil {
			t.Errorf("empty form invented a predicate: %s", detection)
		}
	}
}

func semanticModifierExpression(e *SemanticExpression) *Expression {
	if e == nil {
		return nil
	}
	out := &Expression{Kind: e.Kind, Condition: e.Condition, Threshold: e.Threshold}
	for _, child := range e.Children {
		out.Children = append(out.Children, semanticModifierExpression(child))
	}
	return out
}

func TestPublicFlatModifierIdentity(t *testing.T) {
	cases := []struct {
		name, a, b, op string
		wantA, wantB   Condition
	}{
		{"multiline OR", "Field|re: '^a$'", "Field|re|m: '^b$'", "or", Condition{Field: "Field", Operator: "matches", Value: "^a$", CaseSensitive: true}, Condition{Field: "Field", Operator: "matches", Value: "^b$", CaseSensitive: true, Multiline: true}},
		{"dotall OR", "Field|re: a.b", "Field|re|s: c.d", "or", Condition{Field: "Field", Operator: "matches", Value: "a.b", CaseSensitive: true}, Condition{Field: "Field", Operator: "matches", Value: "c.d", CaseSensitive: true, DotAll: true}},
		{"reference OR literal", "Field|fieldref: Other", "Field: Literal", "or", Condition{Field: "Field", Operator: "=", Value: "Other", ValueReference: "Other"}, Condition{Field: "Field", Operator: "=", Value: "Literal"}},
		{"reference AND literal", "Field|fieldref: Other", "Field: Other", "and", Condition{Field: "Field", Operator: "=", Value: "Other", ValueReference: "Other"}, Condition{Field: "Field", Operator: "=", Value: "Other"}},
		{"expansion", "Field: '%X%'", "Field|expand: '%X%'", "and", Condition{Field: "Field", Operator: "=", Value: "%X%"}, Condition{Field: "Field", Operator: "=", Value: "%X%", RequiresExpansion: true}},
		{"date part", "Field|hour: 5", "Field|minute: 5", "and", Condition{Field: "Field", Operator: "=", Value: "5", DatePart: "hour"}, Condition{Field: "Field", Operator: "=", Value: "5", DatePart: "minute"}},
		{"multiline AND", "Field|re: '^x$'", "Field|re|m: '^x$'", "and", Condition{Field: "Field", Operator: "matches", Value: "^x$", CaseSensitive: true}, Condition{Field: "Field", Operator: "matches", Value: "^x$", CaseSensitive: true, Multiline: true}},
		{"case control", "Field: x", "Field|cased: x", "and", Condition{Field: "Field", Operator: "=", Value: "x"}, Condition{Field: "Field", Operator: "=", Value: "x", CaseSensitive: true}},
	}
	for _, tc := range cases {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%v", tc.name, reverse), func(t *testing.T) {
				a, b, wantA, wantB := tc.a, tc.b, tc.wantA, tc.wantB
				if reverse {
					a, b, wantA, wantB = b, a, wantB, wantA
				}
				rule := modifierRule("  a: {"+a+"}\n  b: {"+b+"}\n", "a "+tc.op+" b")
				parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
				if len(parsed.Errors)+len(semantic.Errors) > 0 {
					t.Fatalf("errors: %v / %v", parsed.Errors, semantic.Errors)
				}
				wantB.LogicalOp = map[string]string{"or": "OR", "and": "AND"}[tc.op]
				want := []Condition{wantA, wantB}
				for name, got := range map[string][]Condition{"parse": parsed.Conditions, "semantic": semantic.Conditions} {
					if !reflect.DeepEqual(got, want) {
						t.Errorf("%s flat = %+v; want %+v", name, got, want)
					}
				}
				if !reflect.DeepEqual(parsed.Expression, semanticModifierExpression(semantic.Expression)) {
					t.Error("resolved API expressions differ")
				}
			})
		}
	}
}

func TestConditionIdentityHasNoDelimiterCollisions(t *testing.T) {
	cases := [][]Condition{
		{{Field: "a|b", Operator: "=", Value: "c"}, {Field: "a", Operator: "b|=", Value: "c"}},
		{{Field: "F", Operator: "=", Value: "a", Alternatives: []string{"a\x00b", "c"}}, {Field: "F", Operator: "=", Value: "a", Alternatives: []string{"a", "b\x00c"}}},
	}
	for _, conditions := range cases {
		if got := deduplicateConditions(conditions); len(got) != 2 {
			t.Errorf("distinct conditions collapsed: %+v", conditions)
		}
	}
}

func TestPublicModifierInputTypes(t *testing.T) {
	invalid := []string{
		"Field: ['', null]", "Field: [null]", "Field|exists: null", "Field|re: null", "Field|contains: null", "Field|base64: null", "Field|fieldref: null", "Field|hour: null", "Field|cased: null", "Field|cased|neq: null",
		"Field|exists: 'yes'", "Field|exists: 'true'", "Field|exists: 'no'", "Field|exists: 1", "'|exists': true",
		"Field|contains|all: alpha", "Field|all: null", "Field|all: 42",
		"Field|re: 42", "Field|re: false", "Field|base64: 42", "Field|base64: false", "Field|fieldref: 42",
		"Field|re: ['42', 42]", "Field|base64: ['false', false]", "Field|fieldref: ['42', 42]", "Field|exists: [true, 'true']",
		"Field|windash: 42", "Field|wide: false", "Field|utf16: 42", "Field|utf16be: false", "Field|base64offset: 42", "Field|cidr: 42", "Field|expand: 42",
		"Field|fieldref: 'Other*'", "Field|fieldref: 'Other?'", "Field|fieldref: 'Other\\\\*'",
	}
	for _, entry := range invalid {
		t.Run(entry, func(t *testing.T) {
			rule := modifierRule("  sel: {"+entry+"}\n", "sel")
			parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
			if len(parsed.Errors) == 0 || len(semantic.Errors) == 0 {
				t.Fatalf("expected authored input error; parse=%+v semantic=%+v", parsed, semantic)
			}
			if parsed.Expression != nil || semantic.Expression != nil {
				t.Fatal("invalid single entry invented a predicate")
			}
		})
	}
	valid := []struct{ entry, operator, value, reference string }{
		{"Field|exists: true", "exists", "true", ""}, {"Field|exists: false", "exists", "false", ""},
		{"Field|re: '42'", "matches", "42", ""}, {"Field|base64: '42'", "=", "NDI=", ""}, {"Field|fieldref: '42'", "=", "42", "42"},
		{"Field: 42", "=", "42", ""}, {"Field|contains: 42", "contains", "42", ""}, {"Field|startswith: 42", "startswith", "42", ""}, {"Field|endswith: 42", "endswith", "42", ""}, {"Field|cased: 42", "=", "42", ""},
		{"Field|contains|all: [alpha]", "contains", "alpha", ""}, {"Field|all|contains: [alpha, alpha]", "contains", "alpha", ""},
		{"Field|fieldref: 'Other\\*'", "=", "Other*", "Other*"}, {"Field|fieldref: 'Other\\?'", "=", "Other?", "Other?"}, {"Field|fieldref: 'Other\\\\Name'", "=", "Other\\Name", "Other\\Name"},
	}
	for _, tc := range valid {
		t.Run(tc.entry, func(t *testing.T) {
			rule := modifierRule("  sel: {"+tc.entry+"}\n", "sel")
			parsed, semantic := ExtractConditions(rule), AnalyzeQuery(rule)
			if len(parsed.Errors)+len(semantic.Errors) > 0 {
				t.Fatalf("valid input errors: %v / %v", parsed.Errors, semantic.Errors)
			}
			for name, e := range map[string]*Expression{"parse": parsed.Expression, "semantic": semanticModifierExpression(semantic.Expression)} {
				leaves := expressionLeaves(e)
				if len(leaves) != 1 || leaves[0].Operator != tc.operator || leaves[0].Value != tc.value || leaves[0].ValueReference != tc.reference {
					t.Errorf("%s = %+v", name, leaves)
				}
			}
		})
	}
}
