package sigma

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const correlationFieldListRule = `title: Event
name: event_rule
id: 122929f4-2d8d-401d-bdc9-89a02e602f62
logsource:
    category: process_creation
detection:
    selection:
        EventID: 1
    condition: selection
`

func correlationFieldListDocument(field string) string {
	return correlationFieldListRule + `---
title: Correlation
name: counted
correlation:
    type: value_count
    rules: [event_rule]
    group-by: [Host]
    timespan: 1h
    condition:
        field: ` + field + `
        gte: 2
`
}

func TestCorrelationFieldListsSingletonIdentity(t *testing.T) {
	scalar := ExtractFile(correlationFieldListDocument("User"))
	if len(scalar.Errors) != 0 || len(scalar.Correlations) != 1 {
		t.Fatalf("scalar control: %+v", scalar)
	}
	c := scalar.Correlations[0]
	if c.Field != "User" || c.Type != CorrelationValueCount || c.Timespan != "1h" ||
		!reflect.DeepEqual(c.GroupBy, []string{"Host"}) ||
		!reflect.DeepEqual(c.Conditions, []CorrelationCondition{{Operator: "gte", Value: 2}}) ||
		len(c.Rules) != 1 || c.Rules[0].Name != "event_rule" || c.Rules[0].Rule == nil ||
		len(c.Rules[0].Rule.Conditions) != 1 || c.Rules[0].Rule.Conditions[0].NumberText != "1" {
		t.Fatalf("scalar identity/reference control: %+v", c)
	}
	for _, field := range []string{"[User]", "&single [User]"} {
		t.Run(field, func(t *testing.T) {
			got := ExtractFile(correlationFieldListDocument(field))
			if !reflect.DeepEqual(got, scalar) {
				t.Fatalf("singleton must retain the entire scalar public object: got %+v, scalar %+v", got, scalar)
			}
		})
	}
	alias := strings.Replace(correlationFieldListDocument("*fields"), "group-by: [Host]", "group-by: &fields [User]", 1)
	aliasScalar := strings.Replace(correlationFieldListDocument("User"), "group-by: [Host]", "group-by: [User]", 1)
	if got, want := ExtractFile(alias), ExtractFile(aliasScalar); !reflect.DeepEqual(got, want) || len(got.Errors) != 0 {
		t.Fatalf("singleton alias changed public identity: got %+v want %+v", got, want)
	}
	literal := ExtractFile(correlationFieldListDocument("'[User Workstation]'"))
	if len(literal.Errors) != 0 || len(literal.Correlations) != 1 || literal.Correlations[0].Field != "[User Workstation]" {
		t.Fatalf("literal bracket spelling changed: %+v", literal)
	}
}

func TestCorrelationFieldListsUnsupportedAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		unsupported bool
	}{
		{"two fields", "[User, Workstation]", true},
		{"duplicate fields", "[User, User]", true},
		{"empty list", "[]", false},
		{"empty name", "['']", false},
		{"empty second name", "[User, '']", false},
		{"number", "[User, 12]", false},
		{"boolean", "[true]", false},
		{"null", "[null]", false},
		{"nested list", "[[User]]", false},
		{"map", "[{name: User}]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := ExtractFile(correlationFieldListDocument(tc.field))
			joined := strings.Join(file.Errors, " ")
			if len(file.Errors) == 0 || len(file.Rules) != 0 || len(file.Correlations) != 0 || !strings.Contains(joined, "condition.field") {
				t.Fatalf("field-shape failure must be explicit and atomic: %+v", file)
			}
			if tc.unsupported && !strings.Contains(joined, "multi-field value_count condition.field is unsupported") {
				t.Fatalf("valid multi-field role needs its unsupported diagnostic, got %q", file.Errors)
			}
			if strings.Contains(joined, "needs a field") {
				t.Fatalf("rejected field list produced a misleading missing-field diagnostic: %q", file.Errors)
			}
		})
	}
}

func TestCorrelationFieldListsErrorsCannotBeErased(t *testing.T) {
	input := correlationFieldListDocument("[User, Workstation]")
	for _, tc := range []struct{ name, source string }{
		{"later duplicate field", strings.Replace(input, "        gte: 2", "        field: User\n        gte: 2", 1)},
		{"separate legacy field", strings.Replace(input, "    condition:", "    field: User\n    condition:", 1)},
		{"alias list", strings.Replace(strings.Replace(input, "group-by: [Host]", "group-by: &fields [User, Workstation]", 1), "field: [User, Workstation]", "field: *fields", 1)},
		{"referenced correlation", input + `---
title: Outer
correlation:
    type: temporal
    rules: [counted]
    group-by: [Host]
    timespan: 1h
`},
		{"unrelated independent rule", input + "---\n" + strings.Replace(correlationFieldListRule, "event_rule", "other_rule", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := ExtractFile(tc.source)
			if !strings.Contains(strings.Join(file.Errors, " "), "multi-field value_count condition.field is unsupported") || len(file.Rules) != 0 || len(file.Correlations) != 0 {
				t.Fatalf("field-list error was erased or partial output escaped: %+v", file)
			}
		})
	}
}

func TestCorrelationFieldListsReferenceAndUnrelatedControls(t *testing.T) {
	withAlias := strings.Replace(correlationFieldListDocument("[User]"), "    group-by: [Host]", "    group-by: [peer]\n    aliases:\n        peer:\n            event_rule: Host", 1)
	byID := strings.Replace(withAlias, "rules: [event_rule]", "rules: [122929f4-2d8d-401d-bdc9-89a02e602f62]", 1)
	for _, source := range []string{withAlias, byID} {
		got := ExtractFile(source)
		if len(got.Errors) != 0 || len(got.Correlations) != 1 || got.Correlations[0].Field != "User" ||
			!reflect.DeepEqual(got.Correlations[0].GroupByFor("event_rule"), []string{"Host"}) {
			t.Fatalf("singleton damaged reference/alias roles: %+v", got)
		}
	}
	for _, typ := range []string{"value_sum", "value_avg", "value_percentile"} {
		source := strings.Replace(correlationFieldListDocument("User"), "type: value_count", "type: "+typ, 1)
		got := ExtractFile(source)
		if len(got.Errors) != 0 || len(got.Correlations) != 1 || got.Correlations[0].Field != "User" || string(got.Correlations[0].Type) != typ {
			t.Fatalf("unrelated %s scalar control changed: %+v", typ, got)
		}
	}
	count := strings.Replace(correlationFieldListDocument("User"), "type: value_count", "type: event_count", 1)
	count = strings.Replace(count, "        field: User\n", "", 1)
	if got := ExtractFile(count); len(got.Errors) != 0 || len(got.Correlations) != 1 || got.Correlations[0].Field != "" {
		t.Fatalf("event_count control changed: %+v", got)
	}
	// A legacy non-list scalar is outside this list-only correction.
	if got := ExtractFile(correlationFieldListDocument("123")); len(got.Errors) != 0 || len(got.Correlations) != 1 || got.Correlations[0].Field != "123" {
		t.Fatalf("legacy non-list scalar changed: %+v", got)
	}
}

func TestCorrelationFieldListsSharedBudgetAndCancellation(t *testing.T) {
	for _, field := range []string{"[User]", "[User, Workstation]"} {
		t.Run(field, func(t *testing.T) {
			input := correlationFieldListDocument(field)
			var usedWork, usedOutput int
			run := func(limits parseLimits) *File {
				return guardedWithLimits(context.Background(), input, limits, func(b *parseBudget) *File {
					file := extractFile(input, b)
					usedWork, usedOutput = b.work, b.outputBytes
					return file
				}, func(message string) *File { return &File{Errors: []string{message}} })
			}
			want := run(defaultParseLimits())
			if usedWork <= 1 || usedOutput <= 1 {
				t.Fatalf("fixture did not exercise shared work/output: %d/%d", usedWork, usedOutput)
			}
			work, output := usedWork, usedOutput
			for _, resource := range []string{"work", "output bytes"} {
				limits := defaultParseLimits()
				if resource == "work" {
					limits.work = work
				} else {
					limits.outputBytes = output
				}
				if got := run(limits); !reflect.DeepEqual(got, want) {
					t.Fatalf("exact %s budget changed the public object: got %+v want %+v", resource, got, want)
				}
				if resource == "work" {
					limits.work--
				} else {
					limits.outputBytes--
				}
				got := run(limits)
				if len(got.Rules) != 0 || len(got.Correlations) != 0 || !strings.Contains(strings.Join(got.Errors, " "), "resource limit exceeded: "+resource) {
					t.Fatalf("one-short %s budget leaked public output: %+v", resource, got)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, field := range []string{"[User]", "[User, Workstation]"} {
		got := ExtractFileContext(ctx, correlationFieldListDocument(field))
		if len(got.Rules) != 0 || len(got.Correlations) != 0 || !strings.Contains(strings.Join(got.Errors, " "), "context canceled") {
			t.Fatalf("canceled field-list parse leaked output: %+v", got)
		}
	}
}
