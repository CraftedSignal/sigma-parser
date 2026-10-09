package sigma

import "testing"

// Sigma 1.0 rule collections: action global/reset/repeat over YAML documents.
func TestRuleCollections(t *testing.T) {
	const collection = `action: global
title: Suspicious Tool
level: high
detection:
    selection:
        Image|endswith: '\tool.exe'
    condition: selection
---
logsource:
    category: process_creation
    product: windows
---
action: repeat
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\tool.dll'
---
action: reset
---
title: Unrelated
logsource:
    product: linux
detection:
    keywords:
        - evil
    condition: keywords
`
	rules := ExtractFile(collection).Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d: %+v", len(rules), rules)
	}
	// A repeated document deep-merges into the previous rule (as sigmac
	// does), so its selection keeps Image and adds ImageLoaded.
	for i, want := range []struct {
		title, category, product string
		fields                   []string
	}{
		{"Suspicious Tool", "process_creation", "windows", []string{"Image"}},
		{"Suspicious Tool", "image_load", "windows", []string{"Image", "ImageLoaded"}},
		{"Unrelated", "", "linux", []string{""}},
	} {
		rule := rules[i]
		if len(rule.Errors) > 0 || rule.Title != want.title || rule.LogSource == nil ||
			rule.LogSource.Category != want.category || rule.LogSource.Product != want.product {
			t.Fatalf("rule %d = %+v (log source %+v), want %+v", i, rule, rule.LogSource, want)
		}
		leaves := expressionLeaves(rule.Expression)
		if len(leaves) != len(want.fields) {
			t.Fatalf("rule %d conditions = %+v, want fields %q", i, leaves, want.fields)
		}
		for j, field := range want.fields {
			if leaves[j].Field != field {
				t.Fatalf("rule %d condition %d on %q, want %q", i, j, leaves[j].Field, field)
			}
		}
	}

	// As one result the rules are ORed, without a log source they disagree on.
	combined := ExtractConditions(collection)
	if len(combined.Errors) > 0 || combined.Expression == nil || combined.Expression.Kind != ExpressionOr || combined.LogSource != nil {
		t.Fatalf("expected an OR of the rules without a log source, got %+v", combined)
	}
	if leaves := expressionLeaves(combined.Expression); len(leaves) != 4 {
		t.Fatalf("expected all three rules' conditions, got %+v", leaves)
	}

	if file := ExtractFile("action: repeat\ndetection:\n  sel:\n    a: b\n  condition: sel\n"); len(file.Errors) == 0 {
		t.Fatal("expected a repeat without a previous rule to be rejected")
	}
}
