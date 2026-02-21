package sigma

import (
	"testing"
)

func FuzzSigmaParser(f *testing.F) {
	// Seed corpus with various Sigma rule structures
	seeds := []string{
		// Minimal valid rule
		`title: Test
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection`,

		// Rule with modifiers
		`title: Modifiers
status: test
level: medium
logsource:
    category: test
detection:
    selection:
        field|contains|all:
            - value1
            - value2
    condition: selection`,

		// Rule with aggregation
		`title: Aggregation
status: test
level: medium
logsource:
    category: test
detection:
    selection:
        EventID: 4625
    condition: selection | count() by src > 10`,

		// Rule with all of them
		`title: All Of
status: test
level: high
logsource:
    category: test
detection:
    sel1:
        field1: val1
    sel2:
        field2: val2
    condition: all of them`,

		// Rule with 1 of pattern
		`title: One Of
status: test
level: medium
logsource:
    category: test
detection:
    selection_a:
        field: a
    selection_b:
        field: b
    condition: 1 of selection_*`,

		// Complex rule
		`title: Complex
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage: '\explorer.exe'
    condition: selection and not filter`,

		// Rule with keywords
		`title: Keywords
status: test
level: medium
logsource:
    category: test
detection:
    keywords:
        - keyword1
        - keyword2
    condition: keywords`,

		// Rule with null
		`title: Null
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field: null
    condition: selection`,

		// Deeply nested condition
		`title: Nested
status: test
level: medium
logsource:
    category: test
detection:
    a:
        f1: v1
    b:
        f2: v2
    c:
        f3: v3
    condition: (a or b) and not c`,

		// Rule with multiple condition strings
		`title: Multi
status: test
level: medium
logsource:
    category: test
detection:
    sel:
        field: value
    condition:
        - sel
        - 1 of them`,

		// Empty values
		`title: Empty
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field: ''
    condition: selection`,

		// Integer and boolean values
		`title: Types
status: test
level: low
logsource:
    category: test
detection:
    selection:
        EventID: 4688
        Enabled: true
    condition: selection`,

		// Near aggregation
		`title: Near
status: test
level: high
logsource:
    category: test
detection:
    s1:
        EventID: 1
    s2:
        EventID: 2
    timeframe: 5m
    condition: s1 | near s1 and s2`,

		// All modifiers
		`title: AllMods
status: test
level: medium
logsource:
    category: test
detection:
    selection:
        f1|contains: v1
        f2|startswith: v2
        f3|endswith: v3
        f4|re: '.*v4.*'
        f5|cidr: '10.0.0.0/8'
        f6|exists: true
    condition: selection`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		// The parser should never panic — any input is fair game
		result := ExtractConditions(data)
		if result == nil {
			t.Fatal("ExtractConditions returned nil")
		}
		// ComputedFields map should never be nil
		if result.ComputedFields == nil {
			t.Fatal("ComputedFields should never be nil")
		}
	})
}
