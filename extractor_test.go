package sigma

import (
	"strings"
	"testing"
)

func TestExtractConditions_BasicRule(t *testing.T) {
	yaml := `
title: Mimikatz Usage
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains: 'sekurlsa'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if result.Title != "Mimikatz Usage" {
		t.Errorf("expected title 'Mimikatz Usage', got %q", result.Title)
	}
	if result.Level != "high" {
		t.Errorf("expected level 'high', got %q", result.Level)
	}
	if result.LogSource == nil {
		t.Fatal("expected logsource")
	}
	if result.LogSource.Category != "process_creation" {
		t.Errorf("expected category 'process_creation', got %q", result.LogSource.Category)
	}
	if len(result.Conditions) < 2 {
		t.Fatalf("expected at least 2 conditions, got %d", len(result.Conditions))
	}

	// Verify conditions
	foundImage := false
	foundCmd := false
	for _, c := range result.Conditions {
		if c.Field == "Image" && c.Operator == "endswith" {
			foundImage = true
		}
		if c.Field == "CommandLine" && c.Operator == "contains" {
			foundCmd = true
		}
	}
	if !foundImage {
		t.Error("missing Image endswith condition")
	}
	if !foundCmd {
		t.Error("missing CommandLine contains condition")
	}
}

func TestExtractConditions_SelectionAndNotFilter(t *testing.T) {
	yaml := `
title: Test Rule
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) < 2 {
		t.Fatalf("expected at least 2 conditions, got %d", len(result.Conditions))
	}

	// Filter should be negated
	foundNegated := false
	for _, c := range result.Conditions {
		if c.Field == "ParentImage" && c.Negated {
			foundNegated = true
		}
	}
	if !foundNegated {
		t.Error("expected ParentImage to be negated")
	}
}

func TestExtractConditions_OrConditions(t *testing.T) {
	yaml := `
title: Multiple Selections
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\cmd.exe'
    selection2:
        Image|endswith: '\powershell.exe'
    condition: selection1 or selection2
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) == 0 {
		t.Fatal("expected conditions")
	}
}

func TestExtractConditions_ListOfValues(t *testing.T) {
	yaml := `
title: List Values
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	// Should have one condition with alternatives
	found := false
	for _, c := range result.Conditions {
		if c.Field == "Image" && len(c.Alternatives) == 3 {
			found = true
		}
	}
	if !found {
		t.Error("expected Image condition with 3 alternatives")
		for _, c := range result.Conditions {
			t.Logf("  %+v", c)
		}
	}
}

func TestExtractConditions_Keywords(t *testing.T) {
	yaml := `
title: Keyword Detection
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    keywords:
        - 'mimikatz'
        - 'sekurlsa'
    condition: keywords
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Operator == "keyword" {
			found = true
		}
	}
	if !found {
		t.Error("expected keyword condition")
	}
}

func TestExtractConditions_AllOfThem(t *testing.T) {
	yaml := `
title: All Of Them
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\cmd.exe'
    selection2:
        CommandLine|contains: 'whoami'
    condition: all of them
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) < 2 {
		t.Fatalf("expected at least 2 conditions, got %d", len(result.Conditions))
	}
}

func TestExtractConditions_1OfSelection(t *testing.T) {
	yaml := `
title: 1 Of Selection
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_ps:
        Image|endswith: '\powershell.exe'
    condition: 1 of selection_*
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) < 1 {
		t.Fatal("expected at least 1 condition")
	}
}

func TestExtractConditions_Aggregation(t *testing.T) {
	yaml := `
title: Brute Force
status: test
level: medium
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection | count() by SourceIP > 10
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.GroupByFields) != 1 || result.GroupByFields[0] != "SourceIP" {
		t.Errorf("expected GroupByFields [SourceIP], got %v", result.GroupByFields)
	}
	if len(result.Commands) != 1 || result.Commands[0] != "count" {
		t.Errorf("expected Commands [count], got %v", result.Commands)
	}
}

func TestExtractConditions_NullValue(t *testing.T) {
	yaml := `
title: Null Value
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: null
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "ParentImage" && c.Operator == "exists" && c.Value == "false" {
			found = true
		}
	}
	if !found {
		t.Error("expected ParentImage exists=false condition")
		for _, c := range result.Conditions {
			t.Logf("  %+v", c)
		}
	}
}

func TestExtractConditions_WildcardValue(t *testing.T) {
	yaml := `
title: Wildcard
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '*mimikatz*'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) == 0 {
		t.Fatal("expected conditions")
	}
}

func TestExtractConditions_IntegerValue(t *testing.T) {
	yaml := `
title: EventID
status: test
level: medium
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "EventID" && c.Value == "4688" {
			found = true
		}
	}
	if !found {
		t.Error("expected EventID=4688 condition")
	}
}

func TestExtractConditions_ContainsAll(t *testing.T) {
	yaml := `
title: Contains All
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-nop'
            - '-w hidden'
            - '-enc'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	// With |all, each value should be a separate AND'd condition
	count := 0
	for _, c := range result.Conditions {
		if c.Field == "CommandLine" && c.Operator == "contains" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 CommandLine contains conditions (all modifier), got %d", count)
		for _, c := range result.Conditions {
			t.Logf("  %+v", c)
		}
	}
}

func TestExtractConditions_ListOfMaps(t *testing.T) {
	yaml := `
title: List of Maps
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\cmd.exe'
          CommandLine|contains: 'whoami'
        - Image|endswith: '\powershell.exe'
          CommandLine|contains: 'Get-Process'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Conditions) < 2 {
		t.Errorf("expected at least 2 conditions, got %d", len(result.Conditions))
	}
}

func TestExtractConditions_EmptyCondition(t *testing.T) {
	yaml := `
title: Missing Condition
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: test.exe
`
	result := ExtractConditions(yaml)
	if len(result.Errors) == 0 {
		t.Error("expected errors for missing condition")
	}
}

func TestExtractConditions_InvalidYAML(t *testing.T) {
	result := ExtractConditions("not: valid: yaml: [broken")
	if len(result.Errors) == 0 {
		t.Error("expected errors for invalid YAML")
	}
}

func TestExtractConditions_MissingDetection(t *testing.T) {
	yaml := `
title: No Detection
status: test
level: medium
logsource:
    category: test
`
	result := ExtractConditions(yaml)
	if len(result.Errors) == 0 {
		t.Error("expected errors for missing detection block")
	}
}

func TestExtractConditions_Tags(t *testing.T) {
	yaml := `
title: Tagged Rule
status: test
level: medium
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d: %v", len(result.Tags), result.Tags)
	}
}

func TestExtractConditions_BooleanValue(t *testing.T) {
	yaml := `
title: Boolean
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        Enabled: true
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "Enabled" && c.Value == "true" {
			found = true
		}
	}
	if !found {
		t.Error("expected Enabled=true condition")
	}
}

func TestExtractConditions_Timeout(t *testing.T) {
	// A valid but simple rule should not timeout
	yaml := `
title: Simple
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`
	result := ExtractConditions(yaml)
	for _, err := range result.Errors {
		if strings.Contains(err, "timed out") {
			t.Error("simple rule should not timeout")
		}
	}
}

func TestExtractConditions_MultipleConditionStrings(t *testing.T) {
	yaml := `
title: Multi Condition
status: test
level: medium
logsource:
    category: test
detection:
    selection:
        field: value
    condition:
        - selection
        - 1 of them
`
	result := ExtractConditions(yaml)
	// Should use first condition
	if len(result.Conditions) == 0 {
		t.Error("expected conditions from first condition string")
	}
}

func TestExtractConditions_FieldRefModifier(t *testing.T) {
	yaml := `
title: Field Reference
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        SubjectUserName|fieldref: TargetUserName
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "SubjectUserName" && c.Operator == "fieldref" && c.Value == "TargetUserName" {
			found = true
		}
	}
	if !found {
		t.Error("expected fieldref condition")
	}
}

func TestExtractConditions_ExistsModifier(t *testing.T) {
	yaml := `
title: Exists Check
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        FieldName|exists: true
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "FieldName" && c.Operator == "exists" && c.Value == "true" {
			found = true
		}
	}
	if !found {
		t.Error("expected exists condition")
	}
}

func TestExtractConditions_RegexModifier(t *testing.T) {
	yaml := `
title: Regex
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        CommandLine|re: '.*mimikatz.*'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "CommandLine" && c.Operator == "matches" {
			found = true
		}
	}
	if !found {
		t.Error("expected regex/matches condition")
	}
}

func TestExtractConditions_CIDRModifier(t *testing.T) {
	yaml := `
title: CIDR
status: test
level: medium
logsource:
    category: firewall
detection:
    selection:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
    condition: selection
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Conditions {
		if c.Field == "DestinationIp" && c.Operator == "cidrmatch" {
			found = true
		}
	}
	if !found {
		t.Error("expected cidrmatch condition")
	}
}

// Test that helpers return expected values
func TestIsStatisticalQuery(t *testing.T) {
	r := &ParseResult{Commands: []string{"count"}}
	if !IsStatisticalQuery(r) {
		t.Error("expected IsStatisticalQuery=true for count")
	}
	r2 := &ParseResult{}
	if IsStatisticalQuery(r2) {
		t.Error("expected IsStatisticalQuery=false for empty")
	}
}

func TestHasUnmappedComputedFields(t *testing.T) {
	if HasUnmappedComputedFields(&ParseResult{}) {
		t.Error("Sigma should never have unmapped computed fields")
	}
}

func TestClassifyFieldProvenance_AlwaysMain(t *testing.T) {
	if ClassifyFieldProvenance(nil, "any") != ProvenanceMain {
		t.Error("expected ProvenanceMain for all Sigma fields")
	}
}

func TestExtractConditions_CasedModifier(t *testing.T) {
	yaml := `
title: Case Sensitive Match
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith|cased: 'cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
`
	result := ExtractConditions(yaml)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}

	var casedCond, normalCond *Condition
	for i := range result.Conditions {
		if result.Conditions[i].Operator == "endswith" {
			casedCond = &result.Conditions[i]
		}
		if result.Conditions[i].Operator == "contains" {
			normalCond = &result.Conditions[i]
		}
	}

	if casedCond == nil {
		t.Fatal("expected endswith condition")
	}
	if !casedCond.CaseSensitive {
		t.Error("expected CaseSensitive=true for |endswith|cased")
	}

	if normalCond == nil {
		t.Fatal("expected contains condition")
	}
	if normalCond.CaseSensitive {
		t.Error("expected CaseSensitive=false for |contains without |cased")
	}
}
