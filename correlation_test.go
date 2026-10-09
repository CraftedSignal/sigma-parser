package sigma

import (
	"slices"
	"strings"
	"testing"
)

// The chained example of the Sigma correlation specification: a
// temporal_ordered correlation over an event_count correlation and a rule.
const chainedCorrelation = `title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
level: high
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Single failed login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Successful login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
`

func TestExtractFileChainedCorrelation(t *testing.T) {
	file := ExtractFile(chainedCorrelation)
	if len(file.Errors) > 0 || len(file.Rules) != 0 || len(file.Correlations) != 1 {
		t.Fatalf("expected one outermost correlation and no standalone rules, got %+v", file)
	}
	outer := file.Correlations[0]
	if outer.Type != CorrelationTemporalOrdered || outer.Timespan != "10m" || !slices.Equal(outer.GroupBy, []string{"User"}) ||
		outer.Level != "high" || len(outer.Rules) != 2 || len(outer.Conditions) != 0 {
		t.Fatalf("unexpected outer correlation %+v", outer)
	}
	inner := outer.Rules[0].Correlation
	if outer.Rules[0].Name != "multiple_failed_login" || inner == nil || inner.Type != CorrelationEventCount ||
		len(inner.Conditions) != 1 || inner.Conditions[0] != (CorrelationCondition{Operator: "gte", Value: 10}) {
		t.Fatalf("unexpected first reference %+v", outer.Rules[0])
	}
	failed := inner.Rules[0].Rule
	if failed == nil || failed.Name != "failed_login" || failed.LogSource.Service != "security" || len(failed.Errors) > 0 {
		t.Fatalf("unexpected inner rule %+v", inner.Rules[0])
	}
	if success := outer.Rules[1].Rule; success == nil || success.ID != "4d0a2c83-c62c-4ed4-b475-c7e23a9269b8" {
		t.Fatalf("unexpected second reference %+v", outer.Rules[1])
	}

	// Read as conditions, the file is the OR of its detection rules.
	if result := ExtractConditions(chainedCorrelation); len(result.Errors) > 0 || result.Expression.Kind != ExpressionOr {
		t.Fatalf("expected the detection rules ORed, got %+v", result)
	}
}

func TestExtractFileCorrelationFields(t *testing.T) {
	const base = `
---
name: website_access
id: 5638f7c0-ac70-491d-8465-2a65075e0d86
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
    condition: selection
`
	for name, tc := range map[string]struct {
		correlation string
		want        Correlation
	}{
		"value_count": {`correlation:
    type: value_count
    rules: [5638f7c0-ac70-491d-8465-2a65075e0d86]
    group-by: [ComputerName, WorkstationName]
    timespan: 1d
    condition:
        field: User
        gte: 100`, Correlation{Type: CorrelationValueCount, Field: "User", GroupBy: []string{"ComputerName", "WorkstationName"},
			Timespan: "1d", Conditions: []CorrelationCondition{{"gte", 100}}}},
		"value_sum range": {`correlation:
    type: value_sum
    rules: website_access
    group-by: SourceIP
    timespan: 1h
    condition:
        field: bytes_sent
        gt: 1000000
        lte: 2000000.5`, Correlation{Type: CorrelationValueSum, Field: "bytes_sent", GroupBy: []string{"SourceIP"},
			Timespan: "1h", Conditions: []CorrelationCondition{{"gt", 1000000}, {"lte", 2000000.5}}}},
		"value_percentile": {`correlation:
    type: value_percentile
    rules: [website_access]
    group-by: [ComputerName]
    timespan: 24h
    condition:
        field: image
        lte: 1`, Correlation{Type: CorrelationValuePercentile, Field: "image", GroupBy: []string{"ComputerName"},
			Timespan: "24h", Conditions: []CorrelationCondition{{"lte", 1}}}},
		"temporal with minimum": {`correlation:
    type: temporal
    rules: [website_access]
    timespan: 30s
    condition:
        gte: 1`, Correlation{Type: CorrelationTemporal, Timespan: "30s", Conditions: []CorrelationCondition{{"gte", 1}}}},
	} {
		t.Run(name, func(t *testing.T) {
			file := ExtractFile("title: c\n" + tc.correlation + base)
			if len(file.Errors) > 0 || len(file.Correlations) != 1 {
				t.Fatalf("unexpected file %+v", file)
			}
			got := file.Correlations[0]
			if got.Type != tc.want.Type || got.Field != tc.want.Field || got.Timespan != tc.want.Timespan ||
				!slices.Equal(got.GroupBy, tc.want.GroupBy) || !slices.Equal(got.Conditions, tc.want.Conditions) ||
				len(got.Rules) != 1 || got.Rules[0].Rule == nil {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestExtractFileCorrelationAliasesAndGenerate(t *testing.T) {
	file := ExtractFile(`title: Error then connection
generate: true
correlation:
    type: temporal
    rules: [internal_error, new_network_connection]
    group-by: [internal_ip, remote_ip]
    timespan: 10s
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
        remote_ip:
            internal_error: source.ip
            new_network_connection: destination.ip
---
name: internal_error
logsource: {category: webserver}
detection:
    selection:
        http.response.status_code: 500
    condition: selection
---
name: new_network_connection
logsource: {category: network_connection}
detection:
    selection:
        event.type: connection
    condition: selection
`)
	if len(file.Errors) > 0 || len(file.Correlations) != 1 {
		t.Fatalf("unexpected file %+v", file)
	}
	c := file.Correlations[0]
	if got := c.GroupByFor("internal_error"); !slices.Equal(got, []string{"destination.ip", "source.ip"}) {
		t.Fatalf("aliases for internal_error resolve to %q", got)
	}
	if got := c.GroupByFor("new_network_connection"); !slices.Equal(got, []string{"source.ip", "destination.ip"}) {
		t.Fatalf("aliases for new_network_connection resolve to %q", got)
	}
	// generate makes the referenced rules match on their own as well.
	if len(file.Rules) != 2 {
		t.Fatalf("expected the generated rules to stand alone, got %d", len(file.Rules))
	}
}

func TestExtractFileCorrelationErrors(t *testing.T) {
	const rule = "\n---\nname: r\nlogsource: {category: proxy}\ndetection:\n    sel:\n        a: b\n    condition: sel\n"
	for name, tc := range map[string]struct {
		file string
		want string
	}{
		"unknown reference":    {"title: c\ncorrelation:\n    type: event_count\n    rules: [missing]\n    timespan: 5m\n    condition: {gte: 2}" + rule, `references rule "missing", which is not defined in this file`},
		"value_count no field": {"title: c\ncorrelation:\n    type: value_count\n    rules: [r]\n    timespan: 5m\n    condition: {gte: 2}" + rule, "value_count needs a field"},
		"no condition":         {"title: c\ncorrelation:\n    type: event_count\n    rules: [r]\n    timespan: 5m" + rule, "missing condition"},
		"bad timespan":         {"title: c\ncorrelation:\n    type: event_count\n    rules: [r]\n    timespan: 1 hour\n    condition: {gte: 2}" + rule, "timespan"},
		"unknown type":         {"title: c\ncorrelation:\n    type: value_median\n    rules: [r]\n    timespan: 5m\n    condition: {gte: 2}" + rule, `unknown type "value_median"`},
		"unknown operator":     {"title: c\ncorrelation:\n    type: event_count\n    rules: [r]\n    timespan: 5m\n    condition: {over: 2}" + rule, `unknown condition operator "over"`},
		"text threshold":       {"title: c\ncorrelation:\n    type: event_count\n    rules: [r]\n    timespan: 5m\n    condition: {gte: many}" + rule, "needs a number"},
		"alias unknown rule":   {"title: c\ncorrelation:\n    type: temporal\n    rules: [r]\n    timespan: 5m\n    group-by: [ip]\n    aliases:\n        ip:\n            other: src" + rule, `maps rule "other"`},
		"ambiguous reference":  {"title: c\ncorrelation:\n    type: temporal\n    rules: [dup]\n    timespan: 5m" + strings.ReplaceAll(rule, "name: r", "id: dup") + strings.ReplaceAll(rule, "name: r", "id: dup"), `references rule "dup", which names more than one rule`},
		"self reference":       {"title: c\nname: loop\ncorrelation:\n    type: temporal\n    rules: [loop, r]\n    timespan: 5m" + rule, "references itself"},
	} {
		t.Run(name, func(t *testing.T) {
			file := ExtractFile(tc.file)
			if !strings.Contains(strings.Join(file.Errors, "; "), tc.want) {
				t.Fatalf("errors %q do not mention %q", file.Errors, tc.want)
			}
		})
	}
}

// Sigma 1 "near" reads as a temporal correlation of the rule's searches.
func TestExtractFileNear(t *testing.T) {
	file := ExtractFile(`title: Mimikatz in memory
logsource: {category: image_load, product: windows}
detection:
    selector:
        Image: C:\Windows\System32\rundll32.exe
    dllload1:
        ImageLoaded|endswith: '\vaultcli.dll'
    dllload2:
        ImageLoaded|endswith: '\wlanapi.dll'
    exclusion:
        ImageLoaded|endswith: '\samlib.dll'
    condition: selector | near dllload1 and dllload2 and not exclusion
    timeframe: 30s
level: medium
`)
	if len(file.Errors) > 0 || len(file.Rules) != 0 || len(file.Correlations) != 1 {
		t.Fatalf("unexpected file %+v", file)
	}
	c := file.Correlations[0]
	var names []string
	for _, ref := range c.Rules {
		names = append(names, ref.Name)
	}
	if c.Type != CorrelationTemporal || c.Timespan != "30s" || c.Level != "medium" ||
		!slices.Equal(names, []string{"anchor", "dllload1", "dllload2", "exclusion"}) ||
		c.Rules[0].Absent || c.Rules[1].Absent || !c.Rules[3].Absent {
		t.Fatalf("unexpected near correlation %+v (rules %q)", c, names)
	}
	if leaves := expressionLeaves(c.Rules[0].Rule.Expression); len(leaves) != 1 || leaves[0].Field != "Image" {
		t.Fatalf("anchor should hold the condition before the pipe, got %+v", leaves)
	}

	// Like other Sigma 1 aggregations, near without a timeframe spans the
	// query's time range.
	untimed := ExtractFile("title: t\nlogsource: {product: linux}\ndetection:\n    a: {x: 1}\n    b: {y: 2}\n    condition: a | near b\n")
	if len(untimed.Errors) > 0 || len(untimed.Correlations) != 1 || untimed.Correlations[0].Timespan != "" {
		t.Fatalf("unexpected untimed near %+v", untimed)
	}
	undefined := ExtractFile("title: t\nlogsource: {product: linux}\ndetection:\n    a: {x: 1}\n    condition: a | near c\n    timeframe: 1m\n")
	if !strings.Contains(strings.Join(undefined.Errors, "; "), `near references "c"`) {
		t.Fatalf("expected an undefined near search to be rejected, got %q", undefined.Errors)
	}
}

// File.Errors carries the rules' own errors, naming the rule when the file
// holds several.
func TestExtractFileReportsRuleErrors(t *testing.T) {
	single := ExtractFile("title: t\nlogsource: {product: linux}\ndetection:\n    sel:\n        a|strlen: 5\n    condition: sel\n")
	if len(single.Errors) != 1 || !strings.HasPrefix(single.Errors[0], "unsupported modifier") {
		t.Fatalf("expected the rule's error unprefixed, got %q", single.Errors)
	}
	file := ExtractFile(chainedCorrelation + "---\nname: broken\nlogsource: {product: linux}\ndetection:\n    sel:\n        a|strlen: 5\n    condition: sel\n")
	if len(file.Errors) != 1 || !strings.HasPrefix(file.Errors[0], `rule "broken": unsupported modifier`) {
		t.Fatalf("expected the broken rule's error, named, got %q", file.Errors)
	}
	if rules := ExtractFile(chainedCorrelation).DetectionRules(); len(rules) != 2 || rules[0].Name != "failed_login" || rules[1].Name != "successful_login" {
		t.Fatalf("expected the two referenced rules, got %d", len(rules))
	}
}
