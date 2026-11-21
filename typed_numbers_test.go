package sigma

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTypedNumbersPreserveAuthoredRoles(t *testing.T) {
	for _, tc := range []struct {
		name, entry, condition string
		numbers                []string
		kind                   ExpressionKind
	}{
		{"number", "x: 42", "sel", []string{"42"}, ExpressionCondition},
		{"string", "x: '42'", "sel", []string{""}, ExpressionCondition},
		{"mixed", "x: [42, '42']", "sel", []string{"42", ""}, ExpressionOr},
		{"repeated", "x: [42, 42.0, 4.2e1]", "sel", []string{"42"}, ExpressionCondition},
		{"all", "x|all: [42, '42']", "sel", []string{"42", ""}, ExpressionAnd},
		{"not", "x: [42, '42']", "not sel", []string{"42", ""}, ExpressionNot},
		{"threshold", "x: [42, '42']", "2 of sel", []string{"42", ""}, ExpressionThreshold},
		{"large", "x: [9007199254740992, 9007199254740993]", "sel", []string{"9007199254740992", "9007199254740993"}, ExpressionOr},
		{"decimal", "x: 9007199254740993.000000000000000001", "sel", []string{"9007199254740993000000000000000001e-18"}, ExpressionCondition},
		{"alias", "x: [&n 42, *n, '42']", "sel", []string{"42", ""}, ExpressionOr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := "detection:\n  sel:\n    " + tc.entry + "\n  condition: " + tc.condition + "\n"
			parsed := ExtractConditions(rule)
			if len(parsed.Errors) > 0 {
				t.Fatalf("errors: %v", parsed.Errors)
			}
			if parsed.Expression == nil || parsed.Expression.Kind != tc.kind {
				t.Fatalf("expression = %+v, want %s", parsed.Expression, tc.kind)
			}
			leaves := expressionLeaves(parsed.Expression)
			if len(leaves) != len(tc.numbers) || len(parsed.Conditions) != len(tc.numbers) {
				t.Fatalf("leaves=%+v flat=%+v want %d typed leaves", leaves, parsed.Conditions, len(tc.numbers))
			}
			semantic := AnalyzeQuery(rule)
			if len(semantic.Errors) > 0 || len(semantic.Conditions) != len(tc.numbers) || len(semantic.Detections) != 1 {
				t.Fatalf("semantic: %+v", semantic)
			}
			for i, want := range tc.numbers {
				for name, conditions := range map[string][]Condition{"expression": leaves, "flat": parsed.Conditions, "semantic": semantic.Conditions, "detection": semantic.Detections[0].Conditions} {
					if got := conditions[i].NumberText; got != want || len(conditions[i].Alternatives) != 0 {
						t.Errorf("%s[%d]=%+v number=%q want %q", name, i, conditions[i], got, want)
					}
				}
			}
			if tc.kind == ExpressionThreshold && (parsed.Expression.Threshold != 2 || len(parsed.Expression.Children) != 2) {
				t.Fatalf("threshold lost typed units: %+v", parsed.Expression)
			}
		})
	}
}

func TestTypedNumbersRejectNonfiniteWithoutPartial(t *testing.T) {
	for _, value := range []string{".inf", "-.Inf", ".NaN", "!!float invalid", "!!int ' +-42'", "!!int '+-42'", "!!int '++42'"} {
		rule := "detection:\n  sel: {good: value, x: " + value + "}\n  condition: sel\n"
		p, s, f := ExtractConditions(rule), AnalyzeQuery(rule), ExtractFile(rule)
		if len(p.Errors) == 0 || p.Expression != nil || len(p.Conditions) != 0 || len(s.Errors) == 0 || s.Expression != nil || len(s.Detections) != 0 || len(f.Errors) == 0 || len(f.Rules) != 0 {
			t.Fatalf("%s returned partial/accepted: parse=%+v semantic=%+v file=%+v", value, p, s, f)
		}
	}
}

func TestTypedNumberCopyBudget(t *testing.T) {
	c := Condition{Field: "x", Operator: "=", Value: "42", NumberText: "42"}
	for _, allowance := range []int{6, 5} {
		limits := defaultParseLimits()
		limits.outputBytes = allowance
		got := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string { b.copyCondition(c); return "accepted" }, func(s string) string { return s })
		if allowance == 6 && got != "accepted" || allowance == 5 && !strings.Contains(got, "output bytes") {
			t.Fatalf("allowance %d: %s", allowance, got)
		}
	}
}

// Hand-authored numeric fixture expectations preserve each OR operand and order.
func assertNumericORLeaves(t *testing.T, r *ParseResult, field string, want, numbers []string) {
	t.Helper()
	var got []Condition
	for _, c := range expressionLeaves(r.Expression) {
		if c.Field == field {
			got = append(got, c)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%s: %d numeric leaves, want %d", field, len(got), len(want))
	}
	for i, c := range got {
		if c.Operator != "=" || c.Value != want[i] || c.NumberText != numbers[i] || len(c.Alternatives) != 0 {
			t.Errorf("%s[%d]=%+v want numeric equality %s", field, i, c, want[i])
		}
	}
	// The selection field itself remains an OR, rather than independent ANDs.
	var find func(*Expression) bool
	find = func(e *Expression) bool {
		if e == nil {
			return false
		}
		if e.Kind == ExpressionOr && len(e.Children) == len(want) {
			matches := true
			for _, child := range e.Children {
				matches = matches && child.Kind == ExpressionCondition && child.Condition != nil && child.Condition.Field == field
			}
			if matches {
				return true
			}
		}
		for _, child := range e.Children {
			if find(child) {
				return true
			}
		}
		return false
	}
	if !find(r.Expression) {
		t.Errorf("%s lost its OR grouping", field)
	}
}

func TestTypedNumberSourceFormsAndModifierRoles(t *testing.T) {
	for _, tc := range []struct {
		entry, number, value, operator, ref string
		null                                bool
	}{
		{"x: 0x2a", "42", "42", "=", "", false},
		{"x: 0o52", "42", "42", "=", "", false},
		{"x: 052", "42", "42", "=", "", false},
		{"x: 0b101010", "42", "42", "=", "", false},
		{"x: +4_2", "42", "42", "=", "", false},
		{"x: !!float '42.0'", "42", "42", "=", "", false},
		{"x: !!int '42'", "42", "42", "=", "", false},
		{"x: !!str 42", "", "42", "=", "", false},
		{"x: 1e1000000", "", "1e1000000", "=", "", false},
		{"x: -0.0", "0", "-0", "=", "", false},
		{"x: -1.2500e+2", "-125", "-125", "=", "", false},
		{"x: 0.00000000000000000001", "1e-20", "0.00000000000000000001", "=", "", false},
		{"x: 1.25e-2", "125e-4", "0.0125", "=", "", false},
		{"x: !!float 1e1000000", "1e1000000", "1e1000000", "=", "", false},
		{"x|gt: 42", "42", "42", ">", "", false},
		{"x|gt: '42'", "", "42", ">", "", false},
		{"x|hour: 5", "5", "5", "=", "", false},
		{"x|contains: 42", "", "42", "contains", "", false},
		{"x|base64: '42'", "", "NDI=", "=", "", false},
		{"x|fieldref: '42'", "", "42", "=", "42", false},
		{"x: true", "", "true", "=", "", false},
		{"x|exists: true", "", "true", "exists", "", false},
		{"x: null", "", "false", "exists", "", true},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			rule := "title: 42\nlogsource: {service: 42}\ndetection:\n  sel: {" + tc.entry + "}\n  condition: sel\n"
			p := ExtractConditions(rule)
			if len(p.Errors) > 0 || len(p.Conditions) != 1 {
				t.Fatalf("%+v", p)
			}
			c := p.Conditions[0]
			if c.NumberText != tc.number || c.Value != tc.value || c.Operator != tc.operator || c.ValueReference != tc.ref || c.NullTest != tc.null {
				t.Fatalf("got %+v", c)
			}
			if p.Title != "42" || p.LogSource == nil || p.LogSource.Service != "42" {
				t.Fatalf("numeric metadata changed: %+v", p)
			}
		})
	}
	for _, entry := range []string{"x|base64: 42", "x|fieldref: 42", "x|exists: 42", "x|re: 42", "x|expand: 42", "x|gt: true", "x|gt: null"} {
		p := ExtractConditions("detection:\n  sel: {" + entry + "}\n  condition: sel\n")
		if len(p.Errors) == 0 {
			t.Errorf("accepted invalid modifier role %s: %+v", entry, p)
		}
	}
}

func TestTypedNumberCopiesAndIdentity(t *testing.T) {
	rule := "anchor: &n 42\ndetection:\n  a: {x: *n}\n  b: {x: '42'}\n  condition: a and b and a\n"
	p, s := ExtractConditions(rule), AnalyzeQuery(rule)
	if len(p.Errors)+len(s.Errors) > 0 || len(p.Conditions) != 2 || len(s.Conditions) != 2 {
		t.Fatalf("parse=%+v semantic=%+v", p, s)
	}
	leaves := expressionLeaves(p.Expression)
	if len(leaves) != 3 || leaves[0].NumberText != "42" || leaves[1].NumberText != "" || leaves[2].NumberText != "42" {
		t.Fatalf("repeated refs=%+v", leaves)
	}
	// Detached public projections carry independent condition structs.
	p.Conditions[0].NumberText = "7"
	p.Expression.Children[0].Condition.NumberText = "8"
	if p.Expression.Children[2].Condition.NumberText != "42" || s.Conditions[0].NumberText != "42" || s.Expression.Children[0].Condition.NumberText != "42" || s.Detections[0].Conditions[0].NumberText != "42" {
		t.Fatal("numeric mutation escaped its projection")
	}
	a := Condition{Field: "x", Operator: "=", Value: "42", NumberText: "42"}
	equivalent := a
	equivalent.Value = "42.000"
	if len(deduplicateConditions([]Condition{a, equivalent})) != 1 {
		t.Fatal("legacy formatting displaced exact numeric identity")
	}
	b := a
	b.NumberText = ""
	if len(deduplicateConditions([]Condition{a, b, a})) != 2 || len(groupORConditions([]Condition{a, {Field: "x", Operator: "=", Value: "42", LogicalOp: "OR"}})) != 2 {
		t.Fatal("mixed numeric/string flat identity collapsed")
	}
}

func TestTypedNumberReservationsBeforeCopies(t *testing.T) {
	// canonicalDecimal("42") scans 3 + 2 + 2 work units and reserves two
	// two-byte text bounds. One-short work stops before the final copy reserve.
	for _, allowance := range []int{7, 6} {
		limits := defaultParseLimits()
		limits.work = allowance
		var output int
		got := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string {
			defer func() { output = b.outputBytes }()
			return canonicalDecimal("42", b)
		}, func(s string) string { return s })
		if allowance == 7 && (got != "42" || output != 4) || allowance == 6 && (!strings.Contains(got, "work") || output != 2) {
			t.Fatalf("work=%d got=%s output=%d", allowance, got, output)
		}
	}
	c := Condition{Field: "x", Operator: "=", Value: "42", NumberText: "42"}
	for _, allowance := range []int{12, 11} {
		limits := defaultParseLimits()
		limits.outputBytes = allowance
		got := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string { b.copyCondition(c); b.copyCondition(c); return "accepted" }, func(s string) string { return s })
		if allowance == 12 && got != "accepted" || allowance == 11 && !strings.Contains(got, "output bytes") {
			t.Fatalf("shared copy allowance=%d: %s", allowance, got)
		}
	}
}

func TestTypedNumberSharedSemanticCopiesAndCancellation(t *testing.T) {
	c := Condition{Field: "x", Operator: "=", Value: "42", NumberText: "42"}
	for _, allowance := range []int{12, 11} {
		limits := defaultParseLimits()
		limits.outputBytes = allowance
		got := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string {
			e := cloneExpression(leafExpression(c), b)
			s := semanticExpressionFromParseExpression(e, b)
			return s.Condition.NumberText
		}, func(s string) string { return s })
		if allowance == 12 && got != "42" || allowance == 11 && !strings.Contains(got, "output bytes") {
			t.Fatalf("shared parse+semantic copy %d: %s", allowance, got)
		}
	}
	// Every repeated selector/alias and semantic enrichment uses the request's
	// original budget; these low caps must never return a partial public model.
	rule := "detection:\n  a: &a {x: [42, '42']}\n  b: *a\n  condition: a and b and a\n"
	for _, tc := range []struct {
		name   string
		adjust func(*parseLimits)
	}{
		{"input bytes", func(l *parseLimits) { l.inputBytes = 16 }},
		{"work", func(l *parseLimits) { l.work = 20 }},
		{"output bytes", func(l *parseLimits) { l.outputBytes = 12 }},
		{"decoded bytes", func(l *parseLimits) { l.decodedBytes = 8 }},
		{"depth", func(l *parseLimits) { l.depth = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := defaultParseLimits()
			tc.adjust(&limits)
			s := guardedWithLimits(context.Background(), rule, limits, func(b *parseBudget) *SemanticQuery { return analyzeQuery(rule, b) }, func(s string) *SemanticQuery { return &SemanticQuery{Errors: []string{s}} })
			if !strings.Contains(strings.Join(s.Errors, " "), tc.name) || s.Expression != nil || len(s.Conditions) != 0 || len(s.Detections) != 0 {
				t.Fatalf("partial numeric model: %+v", s)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := AnalyzeQueryContext(ctx, rule)
	if !strings.Contains(strings.Join(s.Errors, " "), "context canceled") || s.Expression != nil || len(s.Conditions) != 0 || len(s.Detections) != 0 {
		t.Fatalf("canceled typed query=%+v", s)
	}
}

func TestTypedNumberLargeExponentRemainsCompactAndBudgeted(t *testing.T) {
	// Exact exponent addition must carry across digits without expanding the
	// magnitude into a decimal string with that many zeroes.
	rule := "detection:\n  a: {x: !!float 10e999999999999999999999999}\n  condition: a\n"
	p := ExtractConditions(rule)
	if len(p.Errors) > 0 || len(p.Conditions) != 1 || p.Conditions[0].NumberText != "1e1000000000000000000000000" {
		t.Fatalf("compact carry: %+v", p)
	}
	limits := defaultParseLimits()
	limits.work = 30
	p = extractWithTestLimits(rule, limits)
	if !strings.Contains(strings.Join(p.Errors, " "), "work") || p.Expression != nil || len(p.Conditions) != 0 {
		t.Fatalf("exponent escaped budget: %+v", p)
	}
}

func TestTypedNumericKeywordsKeepTextualRole(t *testing.T) {
	p := ExtractConditions("detection:\n  a: [42, '42']\n  condition: a\n")
	if len(p.Errors) > 0 || len(p.Conditions) != 1 {
		t.Fatalf("keyword text dedup: %+v", p)
	}
	c := p.Conditions[0]
	if c.NumberText != "" || c.Operator != "keyword" || c.Value != "42" || len(c.Alternatives) != 0 {
		t.Fatalf("numeric keyword acquired a numeric equality operand: %+v", c)
	}
}

func TestTypedNonfiniteTextualRoles(t *testing.T) {
	for _, v := range []struct{ yaml, text string }{{".inf", "+Inf"}, {"-.Inf", "-Inf"}, {".NaN", "NaN"}} {
		for _, role := range []struct{ field, operator string }{{"", "keyword"}, {"x|contains", "contains"}, {"x|startswith", "startswith"}, {"x|endswith", "endswith"}} {
			for _, alias := range []bool{false, true} {
				t.Run(v.yaml+"/"+role.operator+"/alias="+strconv.FormatBool(alias), func(t *testing.T) {
					prefix, operand := "", v.yaml
					if alias {
						prefix = "anchor: &n " + v.yaml + "\n"
						operand = "*n"
					}
					selection := operand
					if role.field != "" {
						selection = "{" + role.field + ": " + operand + "}"
					}
					rule := prefix + "detection:\n  a: " + selection + "\n  condition: a\n"
					p, s, f := ExtractConditions(rule), AnalyzeQuery(rule), ExtractFile(rule)
					if len(p.Errors)+len(s.Errors)+len(f.Errors) > 0 || len(p.Conditions) != 1 || len(s.Conditions) != 1 || len(s.Detections) != 1 || len(f.Rules) != 1 {
						t.Fatalf("textual nonfinite rejected: parse=%+v semantic=%+v file=%+v", p, s, f)
					}
					field := "x"
					if role.field == "" {
						field = ""
					}
					for name, conditions := range map[string][]Condition{"flat": p.Conditions, "expression": expressionLeaves(p.Expression), "semantic": s.Conditions, "semantic expression": expressionLeaves(semanticModifierExpression(s.Expression)), "detection": s.Detections[0].Conditions, "file": f.Rules[0].Conditions} {
						if len(conditions) != 1 {
							t.Fatalf("%s: %+v", name, conditions)
						}
						c := conditions[0]
						if c.Field != field || c.Operator != role.operator || c.Value != v.text || c.NumberText != "" || len(c.Alternatives) != 0 {
							t.Errorf("%s=%+v want textual %s %q", name, c, role.operator, v.text)
						}
					}
				})
			}
		}
	}
	// Preserve legacy alternatives and formatted text; quoted spelling stays
	// authored text and must not become numeric provenance.
	p := ExtractConditions("detection:\n  a: [.inf, '.inf']\n  condition: a\n")
	if len(p.Errors) > 0 || len(p.Conditions) != 1 || p.Conditions[0].NumberText != "" || !reflect.DeepEqual(p.Conditions[0].Alternatives, []string{"+Inf", ".inf"}) {
		t.Fatalf("keyword alternatives: %+v", p)
	}
}

func TestTypedNonfiniteNumericRolesRejectWholeQuery(t *testing.T) {
	for _, v := range []string{".inf", "-.Inf", ".NaN"} {
		for _, field := range []string{"x", "x|gt", "x|hour", "x|neq"} {
			rule := "anchor: &n " + v + "\ndetection:\n  good: {ok: value}\n  bad: {" + field + ": *n}\n  condition: good or bad\n"
			p, s, f := ExtractConditions(rule), AnalyzeQuery(rule), ExtractFile(rule)
			if len(p.Errors) == 0 || p.Expression != nil || len(p.Conditions) != 0 || len(s.Errors) == 0 || s.Expression != nil || len(s.Conditions) != 0 || len(s.Detections) != 0 || len(f.Errors) == 0 || len(f.Rules) != 0 {
				t.Fatalf("nonfinite numeric role leaked a partial model: %s %s parse=%+v semantic=%+v file=%+v", field, v, p, s, f)
			}
		}
	}
	// These modifiers require authored strings, including regex transformations;
	// allowing a numeric nonfinite through them would invent new semantics.
	for _, field := range []string{"x|re", "x|re|i|contains", "x|base64", "x|fieldref", "x|exists", "x|expand", "x|cidr"} {
		p := ExtractConditions("detection:\n  a: {" + field + ": .inf}\n  condition: a\n")
		if len(p.Errors) == 0 {
			t.Errorf("nonfinite bypassed authored-role validation: %s %+v", field, p)
		}
	}
	p := ExtractConditions("detection:\n  a: {x|re: '.inf', y: '.NaN'}\n  condition: a\n")
	if len(p.Errors) > 0 || len(p.Conditions) != 2 || p.Conditions[0].Operator != "matches" || p.Conditions[0].Value != ".inf" || p.Conditions[0].NumberText != "" || p.Conditions[1].Value != ".NaN" || p.Conditions[1].NumberText != "" {
		t.Fatalf("quoted nonfinite text changed: %+v", p)
	}
}

func TestTypedNonfiniteFormattingReservation(t *testing.T) {
	// Valid exceptional YAML floats have at most four formatted text bytes.
	// The complete bound is reserved before the new owned legacy text is built.
	for _, allowance := range []int{4, 3} {
		limits := defaultParseLimits()
		limits.outputBytes = allowance
		got := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string {
			n, err := decodeNumber(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: ".inf"}, b)
			if err != nil {
				return err.Error()
			}
			return n.legacy
		}, func(s string) string { return s })
		if allowance == 4 && got != "+Inf" || allowance == 3 && !strings.Contains(got, "output bytes") {
			t.Fatalf("nonfinite owner reserve %d: %s", allowance, got)
		}
	}
}
