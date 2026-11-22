package sigma

import (
	"reflect"
	"strings"
	"testing"
)

// Literal trees follow Sigma's recursive detection-list OR semantics; each map
// member remains an AND. Mixing members must not change their authored order.
func TestWave6bMixedDetectionLists(t *testing.T) {
	leaf := func(field, operator, value string) *Expression {
		return &Expression{Kind: ExpressionCondition, Condition: &Condition{Field: field, Operator: operator, Value: value}}
	}
	keyword := leaf("", "keyword", "evil")
	image := leaf("Image", "=", "cmd.exe")
	user := leaf("User", "=", "SYSTEM")
	mapFirst := &Expression{Kind: ExpressionOr, Children: []*Expression{
		{Kind: ExpressionAnd, Children: []*Expression{image, user}}, keyword,
	}}
	for _, tc := range []struct {
		name, detection, condition string
		want                       *Expression
		fields                     []string
		negated, invalid           bool
	}{
		{"keyword first", "    - evil\n    - Image: cmd.exe\n", "selection", &Expression{Kind: ExpressionOr, Children: []*Expression{keyword, image}}, []string{"", "Image"}, false, false},
		{"map first", "    - Image: cmd.exe\n      User: SYSTEM\n    - evil\n", "selection", mapFirst, []string{"Image", "User", ""}, false, false},
		{"not mixed", "    - Image: cmd.exe\n      User: SYSTEM\n    - evil\n", "not selection", &Expression{Kind: ExpressionNot, Children: []*Expression{mapFirst}}, []string{"Image", "User", ""}, true, false},
		{"nested field invalid", "    Image: [evil, {User: SYSTEM}]\n", "selection", nil, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := "title: Mixed detection list\nlogsource:\n  product: windows\ndetection:\n  selection:\n" + tc.detection + "  condition: " + tc.condition + "\n"
			p, s := ExtractConditions(rule), AnalyzeQuery(rule)
			if tc.invalid {
				if len(p.Errors) == 0 || len(s.Errors) == 0 {
					t.Fatal("nested field-value map was accepted")
				}
				for _, conditions := range [][]Condition{p.Conditions, s.Conditions} {
					for _, c := range conditions {
						if strings.Contains(c.Value, "map[") {
							t.Fatalf("fabricated nested mapping value: %+v", c)
						}
					}
				}
				return
			}
			if len(p.Errors) != 0 || len(s.Errors) != 0 {
				t.Fatalf("valid mixed list rejected: extract=%v analyze=%v", p.Errors, s.Errors)
			}
			if !reflect.DeepEqual(p.Expression, tc.want) {
				t.Errorf("mixed list lost exact OR/AND/NOT tree: got=%+v want=%+v", p.Expression, tc.want)
			}
			if len(s.Detections) != 1 || s.Detections[0].Keyword {
				t.Errorf("mixed detection incorrectly marked keyword-only: %+v", s.Detections)
			}
			if !reflect.DeepEqual(p.Conditions, s.Conditions) || len(p.Conditions) != len(tc.fields) {
				t.Fatalf("semantic flat predicates lost members: extract=%+v analyze=%+v", p.Conditions, s.Conditions)
			}
			for i, c := range p.Conditions {
				if c.Field != tc.fields[i] || c.Negated != tc.negated {
					t.Errorf("flat predicate order/negation%d: %+v", i, c)
				}
			}
		})
	}
}
