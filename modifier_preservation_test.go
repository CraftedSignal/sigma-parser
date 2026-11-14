package sigma

import (
	"fmt"
	"reflect"
	"testing"
)

func modifierRule(detections, condition string) string {
	return "title: Modifier preservation\nlogsource: {category: process_creation}\ndetection:\n" + detections + "  condition: " + condition + "\n"
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
