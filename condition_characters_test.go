package sigma

import (
	"strings"
	"testing"
)

// The condition lexer reads UTF-8 characters, not bytes. A search identifier
// with a non-ASCII letter stays whole, and a selector pattern over one is a
// valid pattern: half a letter used to reach regexp.MustCompile and panic.
func TestConditionReadsNonASCIIIdentifiers(t *testing.T) {
	const detection = "title: t\ndetection:\n  sélection: {A: 1}\n  sel: {B: 2}\n  condition: "
	for condition, want := range map[string]string{
		"sélection":         "A",
		"1 of sé*":          "A",
		"sélection and sel": "A B",
	} {
		result := ExtractConditions(detection + condition + "\n")
		if len(result.Errors) > 0 {
			t.Errorf("%s: unexpected errors %q", condition, result.Errors)
			continue
		}
		var fields []string
		for _, leaf := range expressionLeaves(result.Expression) {
			fields = append(fields, leaf.Field)
		}
		if got := strings.Join(fields, " "); got != want {
			t.Errorf("%s: expression over %q, want %q", condition, got, want)
		}
	}

	result := ExtractConditions("title: t\ndetection:\n  sel: {A: 1}\n  condition: 1 of sé*\n")
	if errors := strings.Join(result.Errors, "; "); strings.Contains(errors, "panic") ||
		!strings.Contains(errors, `"sé*" matches no search identifier`) || result.Title != "t" {
		t.Fatalf("1 of sé* without a matching selection: errors %q, title %q", result.Errors, result.Title)
	}
}

// A character the condition grammar does not know is an error, reported
// once, in the search and in the aggregation after the pipe. It used to be
// skipped: sel and !filter read as sel and filter, and count() != 3 as
// count() = 3.
func TestConditionRejectsUnknownCharacters(t *testing.T) {
	for _, tc := range []struct{ condition, character string }{
		{"sel and !filter", "!"},
		{"sel and ~filter", "~"},
		{"sel and [filter]", "["},
		{"sel and [filter]", "]"},
		{"sel and ¬filter", "¬"},
		{"sel | count() by src_ip != 3", "!"},
	} {
		result := ExtractConditions("title: t\ndetection:\n  sel: {A: 1}\n  filter: {B: 1}\n  condition: " + tc.condition + "\n")
		want := `unexpected character "` + tc.character + `" in condition`
		reported := 0
		for _, err := range result.Errors {
			if strings.Contains(err, want) {
				reported++
			}
		}
		if reported != 1 {
			t.Errorf("%s: %q reported %d times, errors %q", tc.condition, tc.character, reported, result.Errors)
		}
	}
}
