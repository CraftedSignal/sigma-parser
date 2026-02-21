package sigma

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestStress_DeeplyNestedCondition(t *testing.T) {
	// Build deeply nested condition: ((((a and b) or c) and d) or e) ...
	yaml := `
title: Deep Nesting
status: test
level: low
logsource:
    category: test
detection:
`
	detNames := make([]string, 20)
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("det%d", i)
		detNames[i] = name
		yaml += fmt.Sprintf("    %s:\n        field%d: value%d\n", name, i, i)
	}

	// Build nested condition
	cond := detNames[0]
	for i := 1; i < len(detNames); i++ {
		if i%2 == 0 {
			cond = fmt.Sprintf("(%s and %s)", cond, detNames[i])
		} else {
			cond = fmt.Sprintf("(%s or %s)", cond, detNames[i])
		}
	}
	yaml += fmt.Sprintf("    condition: %s\n", cond)

	result := ExtractConditions(yaml)
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Conditions) == 0 {
		t.Error("expected conditions from deeply nested expression")
	}
}

func TestStress_ManyDetectionItems(t *testing.T) {
	yaml := `
title: Many Items
status: test
level: low
logsource:
    category: test
detection:
`
	names := make([]string, 50)
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("sel%d", i)
		names[i] = name
		yaml += fmt.Sprintf("    %s:\n        field%d: value%d\n", name, i, i)
	}
	yaml += "    condition: 1 of them\n"

	result := ExtractConditions(yaml)
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Conditions) == 0 {
		t.Error("expected conditions from 1 of them with 50 items")
	}
}

func TestStress_LargeValueList(t *testing.T) {
	yaml := `
title: Large Value List
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field|contains:
`
	for i := 0; i < 200; i++ {
		yaml += fmt.Sprintf("            - 'value_%d'\n", i)
	}
	yaml += "    condition: selection\n"

	result := ExtractConditions(yaml)
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Conditions) == 0 {
		t.Error("expected conditions")
	}
	// Check alternatives count
	found := false
	for _, c := range result.Conditions {
		if c.Field == "field" && len(c.Alternatives) == 200 {
			found = true
		}
	}
	if !found {
		t.Error("expected field with 200 alternatives")
	}
}

func TestStress_RandomRules(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	operators := []string{"", "|contains", "|startswith", "|endswith", "|re", "|cidr"}
	logicalOps := []string{"and", "or"}

	for i := 0; i < 100; i++ {
		yaml := fmt.Sprintf(`
title: Random Rule %d
status: test
level: medium
logsource:
    category: test
    product: windows
detection:
`, i)
		numItems := rng.Intn(5) + 1
		names := make([]string, numItems)

		for j := 0; j < numItems; j++ {
			name := fmt.Sprintf("sel%d", j)
			names[j] = name
			numFields := rng.Intn(3) + 1
			yaml += fmt.Sprintf("    %s:\n", name)

			for k := 0; k < numFields; k++ {
				op := operators[rng.Intn(len(operators))]
				numValues := rng.Intn(3) + 1
				yaml += fmt.Sprintf("        field%d%s:\n", k, op)
				for v := 0; v < numValues; v++ {
					yaml += fmt.Sprintf("            - 'val_%d_%d_%d'\n", j, k, v)
				}
			}
		}

		// Build condition
		cond := names[0]
		for j := 1; j < len(names); j++ {
			op := logicalOps[rng.Intn(len(logicalOps))]
			cond += " " + op + " " + names[j]
		}
		yaml += fmt.Sprintf("    condition: %s\n", cond)

		result := ExtractConditions(yaml)
		if result == nil {
			t.Fatalf("rule %d: nil result", i)
		}
		// No panics is the main test
	}
}

func TestStress_LongConditionExpression(t *testing.T) {
	yaml := `
title: Long Condition
status: test
level: low
logsource:
    category: test
detection:
`
	var condParts []string
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("s%d", i)
		yaml += fmt.Sprintf("    %s:\n        f%d: v%d\n", name, i, i)
		condParts = append(condParts, name)
	}
	yaml += "    condition: " + strings.Join(condParts, " or ") + "\n"

	result := ExtractConditions(yaml)
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestStress_AllModifierCombinations(t *testing.T) {
	modifiers := []string{
		"contains", "startswith", "endswith", "re", "cidr",
		"gt", "gte", "lt", "lte", "exists", "fieldref",
		"all", "base64", "base64offset", "wide", "utf16le", "utf16be",
		"windash", "expand",
	}

	for _, mod := range modifiers {
		yaml := fmt.Sprintf(`
title: Modifier %s
status: test
level: low
logsource:
    category: test
detection:
    selection:
        field|%s: 'value'
    condition: selection
`, mod, mod)

		result := ExtractConditions(yaml)
		if result == nil {
			t.Fatalf("modifier %s: nil result", mod)
		}
		// No panics is the key check
	}
}
