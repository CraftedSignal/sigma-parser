package sigma

import (
	"slices"
	"testing"
)

// ExtractFile reports a correlation's alias errors in the same order on every
// run. They used to follow the random iteration order of the Aliases map.
func TestExtractFileReportsAliasErrorsInAStableOrder(t *testing.T) {
	const file = "title: a\nname: rule_a\ndetection:\n  sel: {A: 1}\n  condition: sel\n---\n" +
		"title: c\nname: c\ncorrelation:\n  type: temporal\n  rules: [rule_a]\n  timespan: 1h\n  group-by: [a1]\n" +
		"  aliases:\n    a1: {zzz: f}\n    a2: {yyy: f}\n    a3: {xxx: f}\n    a4: {www: f}\n"
	want := []string{
		`correlation "c": alias "a1" maps rule "zzz", which the correlation does not reference`,
		`correlation "c": alias "a2" maps rule "yyy", which the correlation does not reference`,
		`correlation "c": alias "a3" maps rule "xxx", which the correlation does not reference`,
		`correlation "c": alias "a4" maps rule "www", which the correlation does not reference`,
	}
	for run := 0; run < 100; run++ {
		if errors := ExtractFile(file).Errors; !slices.Equal(errors, want) {
			t.Fatalf("run %d: errors %q, want %q", run, errors, want)
		}
	}
}
