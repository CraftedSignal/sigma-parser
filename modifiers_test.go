package sigma

import (
	"reflect"
	"testing"
)

// expressionLeaves lists the conditions of an expression in order.
func expressionLeaves(expression *Expression) []Condition {
	if expression == nil {
		return nil
	}
	if expression.Kind == ExpressionCondition {
		return []Condition{*expression.Condition}
	}
	var out []Condition
	for _, child := range expression.Children {
		out = append(out, expressionLeaves(child)...)
	}
	return out
}

func conditionValues(condition Condition) []string {
	if len(condition.Alternatives) > 0 {
		return condition.Alternatives
	}
	return []string{condition.Value}
}

func mustFieldExpression(t *testing.T, fieldWithMods string, value any) *Expression {
	t.Helper()
	expr, _, errs := fieldExpression(fieldWithMods, value)
	if len(errs) > 0 {
		t.Fatalf("%s: unexpected errors %v", fieldWithMods, errs)
	}
	return expr
}

func TestFieldModifiersProduceSpecConditions(t *testing.T) {
	cases := []struct {
		name          string
		field         string
		value         any
		operator      string
		values        []string
		caseSensitive bool
	}{
		{"plain value is an exact match", "Image", `C:\Windows\cmd.exe`, "=", []string{`C:\Windows\cmd.exe`}, false},
		{"contains", "CommandLine|contains", "mimikatz", "contains", []string{"mimikatz"}, false},
		{"startswith", "Image|startswith", `C:\Windows\`, "startswith", []string{`C:\Windows\`}, false},
		{"endswith", "Image|endswith", ".exe", "endswith", []string{".exe"}, false},
		{"modifier names are case-insensitive", "Image|ENDSWITH", ".exe", "endswith", []string{".exe"}, false},
		{"regex is case-sensitive by default", "CommandLine|re", `\d{3}`, "matches", []string{`\d{3}`}, true},
		{"regex i flag", "CommandLine|re|i", "abc", "matches", []string{"abc"}, false},
		{"ignorecase alias", "CommandLine|re|ignorecase", "abc", "matches", []string{"abc"}, false},
		{"cidr", "DestinationIp|cidr", "10.0.0.0/8", "cidrmatch", []string{"10.0.0.0/8"}, false},
		{"ipv6 cidr", "DestinationIp|cidr", "fe80::/10", "cidrmatch", []string{"fe80::/10"}, false},
		{"gt", "EventID|gt", 10, ">", []string{"10"}, false},
		{"gte", "EventID|gte", 10, ">=", []string{"10"}, false},
		{"lt", "EventID|lt", 10, "<", []string{"10"}, false},
		{"lte", "EventID|lte", 10.5, "<=", []string{"10.5"}, false},
		{"exists true", "FieldName|exists", true, "exists", []string{"true"}, false},
		{"exists false", "FieldName|exists", false, "exists", []string{"false"}, false},
		{"cased", "Image|cased|endswith", `\CMD.exe`, "endswith", []string{`\CMD.exe`}, true},
		{"list values are alternatives", "Image|endswith", []any{`\a.exe`, `\b.exe`}, "endswith", []string{`\a.exe`, `\b.exe`}, false},
		{"numbers match as written", "EventID", []any{4688, 1}, "=", []string{"4688", "1"}, false},
		{"base64", "CommandLine|base64", "test", "=", []string{"dGVzdA=="}, false},
		{"base64 then contains", "CommandLine|base64|contains", "test", "contains", []string{"dGVzdA=="}, false},
		{"base64offset", "CommandLine|base64offset|contains", "test", "contains", []string{"dGVzd", "Rlc3", "0ZXN0"}, false},
		{"wide is utf16le", "CommandLine|wide", "test", "=", []string{"t\x00e\x00s\x00t\x00"}, false},
		{"utf16be", "CommandLine|utf16be", "A", "=", []string{"\x00A"}, false},
		{"utf16 adds a byte order mark", "CommandLine|utf16", "A", "=", []string{"\xff\xfeA\x00"}, false},
		{"utf16le then base64offset", "CommandLine|utf16le|base64offset|contains", "ping", "contains", []string{"cABpAG4AZw", "AAaQBuAGcA", "wAGkAbgBnA"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaves := expressionLeaves(mustFieldExpression(t, tc.field, tc.value))
			if len(leaves) != 1 {
				t.Fatalf("expected one condition, got %+v", leaves)
			}
			got := leaves[0]
			if got.Operator != tc.operator || got.CaseSensitive != tc.caseSensitive || !reflect.DeepEqual(conditionValues(got), tc.values) {
				t.Fatalf("got operator=%q values=%q cased=%v, want %q %q %v", got.Operator, conditionValues(got), got.CaseSensitive, tc.operator, tc.values, tc.caseSensitive)
			}
		})
	}
}

func TestWildcardsAndEscapesFollowTheSpec(t *testing.T) {
	cases := []struct {
		name     string
		field    string
		value    string
		operator string
		want     string
	}{
		{"leading wildcard is endswith", "Image", `*\cmd.exe`, "endswith", `\cmd.exe`},
		{"trailing wildcard is startswith", "Image", `C:\Program Files*`, "startswith", `C:\Program Files`},
		{"backslash star is an escaped literal star", "Image", `C:\Windows\*`, "matches", `^C:\\Windows\*$`},
		{"wildcards on both ends are contains", "CommandLine", `*whoami*`, "contains", `whoami`},
		{"inner wildcard is a regex", "CommandLine|contains", `cmd*/c`, "matches", `cmd.*/c`},
		{"single wildcard is a regex", "Image", `prog?.exe`, "matches", `^prog.\.exe$`},
		{"escaped wildcard is a literal star", "CommandLine|contains", `a\*b`, "matches", `a\*b`},
		{"double backslash is one backslash", "Image|startswith", `\\\\server\\share`, "startswith", `\\server\share`},
		{"backslash before a letter is literal", "Image", `C:\Windows\x.exe`, "=", `C:\Windows\x.exe`},
		{"escaped backslash before a wildcard", "Image", `C:\\*`, "startswith", `C:\`},
		{"bare wildcard tests existence", "User", `*`, "exists", "true"},
		{"empty string is an exact empty match", "User", ``, "=", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaves := expressionLeaves(mustFieldExpression(t, tc.field, tc.value))
			if len(leaves) != 1 || leaves[0].Operator != tc.operator || leaves[0].Value != tc.want {
				t.Fatalf("got %+v, want operator %q value %q", leaves, tc.operator, tc.want)
			}
		})
	}
}

func TestWindashExpandsWordStartFlagsLikePySigma(t *testing.T) {
	leaves := expressionLeaves(mustFieldExpression(t, "CommandLine|windash|contains", " -exec bypass"))
	want := []string{" -exec bypass", " /exec bypass", " –exec bypass", " —exec bypass", " ―exec bypass"}
	if len(leaves) != 1 || !reflect.DeepEqual(conditionValues(leaves[0]), want) {
		t.Fatalf("got %+v, want values %q", leaves, want)
	}

	// A dash inside a word is not a flag and stays as written.
	leaves = expressionLeaves(mustFieldExpression(t, "CommandLine|windash|contains", "x-forwarded"))
	if values := conditionValues(leaves[0]); len(values) != 1 || values[0] != "x-forwarded" {
		t.Fatalf("expected an in-word dash to stay, got %q", values)
	}

	// Every flag of a value expands: two flags give 5 x 5 variants.
	leaves = expressionLeaves(mustFieldExpression(t, "CommandLine|windash|contains", "-a -b"))
	if values := conditionValues(leaves[0]); len(values) != 25 {
		t.Fatalf("expected 25 permutations, got %d: %q", len(values), values)
	}
}

func TestAllLinksValuesNotTheirExpansions(t *testing.T) {
	expr := mustFieldExpression(t, "CommandLine|windash|contains|all", []any{" -a ", " -b "})
	if expr.Kind != ExpressionAnd || len(expr.Children) != 2 {
		t.Fatalf("expected an AND of the two values, got %#v", expr)
	}
	for i, flag := range []string{"a", "b"} {
		values := conditionValues(*expr.Children[i].Condition)
		if len(values) != 5 || values[0] != " -"+flag+" " || values[1] != " /"+flag+" " {
			t.Fatalf("value %d should OR its windash variants, got %q", i, values)
		}
	}
}

func TestNeqNegatesTheWholeEntry(t *testing.T) {
	expr := mustFieldExpression(t, "User|neq", []any{"SYSTEM", "LOCAL SERVICE"})
	if expr.Kind != ExpressionNot || expr.Children[0].Kind != ExpressionCondition {
		t.Fatalf("expected NOT around the value list, got %#v", expr)
	}
	if values := conditionValues(*expr.Children[0].Condition); !reflect.DeepEqual(values, []string{"SYSTEM", "LOCAL SERVICE"}) {
		t.Fatalf("expected both values under the negation, got %q", values)
	}
	flat := flattenExpression(expr, false)
	if len(flat) != 1 || !flat[0].Negated {
		t.Fatalf("flat view should negate the condition, got %+v", flat)
	}
}

func TestRegexFlagsAndTimeModifiers(t *testing.T) {
	leaves := expressionLeaves(mustFieldExpression(t, "Payload|re|m|s|i", "^a.b$"))
	if c := leaves[0]; !c.Multiline || !c.DotAll || c.CaseSensitive {
		t.Fatalf("expected m, s and i flags, got %+v", c)
	}
	leaves = expressionLeaves(mustFieldExpression(t, "Payload|re|multiline|dotall", "a"))
	if c := leaves[0]; !c.Multiline || !c.DotAll || !c.CaseSensitive {
		t.Fatalf("expected multiline and dotall aliases, got %+v", c)
	}
	leaves = expressionLeaves(mustFieldExpression(t, "Payload|re|startswith", "a|b"))
	if leaves[0].Value != "^(?:a|b)" {
		t.Fatalf("startswith should anchor the regex start, got %q", leaves[0].Value)
	}

	leaves = expressionLeaves(mustFieldExpression(t, "LogonTime|hour", []any{22, 23}))
	if c := leaves[0]; c.DatePart != "hour" || c.Operator != "=" || !reflect.DeepEqual(conditionValues(c), []string{"22", "23"}) {
		t.Fatalf("expected hour equality alternatives, got %+v", c)
	}
	leaves = expressionLeaves(mustFieldExpression(t, "LogonTime|hour|gte", 22))
	if c := leaves[0]; c.DatePart != "hour" || c.Operator != ">=" || c.Value != "22" {
		t.Fatalf("expected an hour comparison, got %+v", c)
	}
}

func TestFieldReferences(t *testing.T) {
	leaves := expressionLeaves(mustFieldExpression(t, "SubjectUserName|fieldref", []any{"TargetUserName", "UserName"}))
	if len(leaves) != 2 || leaves[0].ValueReference != "TargetUserName" || leaves[1].ValueReference != "UserName" || leaves[0].Operator != "=" {
		t.Fatalf("expected one equality reference per field, got %+v", leaves)
	}
	for _, field := range []string{"Image|fieldref|endswith", "Image|endswith|fieldref"} {
		leaves = expressionLeaves(mustFieldExpression(t, field, "OriginalFileName"))
		if leaves[0].Operator != "endswith" || leaves[0].ValueReference != "OriginalFileName" {
			t.Fatalf("%s: expected an endswith field reference, got %+v", field, leaves[0])
		}
	}
}

func TestNullTestsAbsence(t *testing.T) {
	for _, value := range []any{nil, []any{}} {
		leaves := expressionLeaves(mustFieldExpression(t, "PasswordLastSet", value))
		if len(leaves) != 1 || leaves[0].Operator != "exists" || leaves[0].Value != "false" {
			t.Fatalf("null should test absence, got %+v", leaves)
		}
	}
	// A null in a value list ORs an absence test, as pySigma does.
	expr := mustFieldExpression(t, "ParentImage|endswith", []any{`\explorer.exe`, nil})
	leaves := expressionLeaves(expr)
	if expr.Kind != ExpressionOr || len(leaves) != 2 || leaves[0].Operator != "endswith" || leaves[1].Operator != "exists" || leaves[1].Value != "false" {
		t.Fatalf("expected value OR absent, got %#v", expr)
	}
}

func TestInvalidModifierChainsAreRejected(t *testing.T) {
	cases := map[string]any{
		"CommandLine|contains~":           "x",
		"CommandLine|i":                   "x",
		"CommandLine|re|cased":            "x",
		"CommandLine|contains|re":         "x",
		"DestinationIp|contains|cidr":     "10.0.0.0/8",
		"DestinationIp|cidr":              "not-a-network",
		"EventID|gt":                      "ten",
		"EventID|contains|gt":             10,
		"LogonTime|hour":                  "late",
		"FieldName|exists":                "maybe",
		"CommandLine|contains|base64":     "x",
		"CommandLine|base64":              "a*b",
		"CommandLine|re|windash":          "x",
		"CommandLine|fieldref|contains|x": "y",
		"ProcessId|fieldref|contains|gt":  "ParentProcessId",
	}
	for field, value := range cases {
		if expr, _, errs := fieldExpression(field, value); len(errs) == 0 {
			t.Errorf("%s: %v should be rejected, got %#v", field, value, expr)
		}
	}
}
