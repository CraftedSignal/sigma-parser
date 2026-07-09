package sigma

import "testing"

// TestDeterministicExtraction verifies condition extraction is deterministic
// and does not drop same-field comparison conditions. Previously, map
// iteration order in quantifier matching plus an over-broad OR-merge folded
// `field > a` and `field > b` (from different selections) together
// non-deterministically, dropping one bound across runs.
func TestDeterministicExtraction(t *testing.T) {
	rule := `
title: Same field, different comparison values across selections
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        DestinationPort|gt: 20067
        Image|endswith: '\a.exe'
    selection_b:
        DestinationPort|gt: 14362
        Image|endswith: '\b.exe'
    condition: 1 of selection_*
`
	// Both DestinationPort bounds must always be present, on every run.
	for i := 0; i < 50; i++ {
		res := ExtractConditions(rule)
		vals := map[string]bool{}
		for _, c := range res.Conditions {
			if c.Field == "DestinationPort" {
				vals[c.Value] = true
			}
		}
		if !vals["20067"] || !vals["14362"] {
			t.Fatalf("run %d: expected both DestinationPort bounds, got %v", i, vals)
		}
	}
}

// TestComparisonsNotMergedToAlternatives verifies ordering comparisons on the
// same field across an OR are kept separate (folding them would drop a bound).
func TestComparisonsNotMergedToAlternatives(t *testing.T) {
	rule := `
title: t
logsource:
    category: process_creation
    product: windows
detection:
    sel1:
        Port|gt: 100
    sel2:
        Port|gt: 200
    condition: sel1 or sel2
`
	res := ExtractConditions(rule)
	var portConds int
	for _, c := range res.Conditions {
		if c.Field == "Port" {
			portConds++
			if len(c.Alternatives) > 0 {
				t.Errorf("comparison must not gain alternatives: %+v", c)
			}
		}
	}
	if portConds != 2 {
		t.Errorf("expected 2 separate Port conditions, got %d", portConds)
	}
}
