package sigma

import (
	"strings"
	"testing"
)

// An integer too large for 64 bits keeps its digits, as PyYAML, and so
// pySigma, keeps it. yaml.v3 decodes it as a float64, so
// 18446744073709551616 used to be matched as 18446744073709552000. It is
// still a number, not a string.
func TestLargeIntegersKeepTheirDigits(t *testing.T) {
	for _, tc := range []struct{ entry, operator, value string }{
		{"A: 18446744073709551616", "=", "18446744073709551616"},
		{"A: -9223372036854775809", "=", "-9223372036854775809"},
		{"A: 18_446_744_073_709_551_616", "=", "18446744073709551616"},
		{"A|gt: 18446744073709551616", ">", "18446744073709551616"},
		{"A: 1.5e20", "=", "150000000000000000000"},
	} {
		result := ExtractConditions("title: t\ndetection:\n  sel:\n    " + tc.entry + "\n  condition: sel\n")
		if len(result.Errors) > 0 || len(result.Conditions) != 1 {
			t.Errorf("%s: errors %q, %d conditions", tc.entry, result.Errors, len(result.Conditions))
			continue
		}
		if c := result.Conditions[0]; c.Operator != tc.operator || c.Value != tc.value {
			t.Errorf("%s: %s %q, want %s %q", tc.entry, c.Operator, c.Value, tc.operator, tc.value)
		}
	}

	titled := ExtractConditions("title: 18446744073709551616\ndetection:\n  sel: {A: 1}\n  condition: sel\n")
	if titled.Title != "18446744073709551616" {
		t.Errorf("title of a large integer: %q", titled.Title)
	}

	encoded := ExtractConditions("title: t\ndetection:\n  sel:\n    A|base64: 18446744073709551616\n  condition: sel\n")
	if !strings.Contains(strings.Join(encoded.Errors, "; "), "base64 requires an authored string") {
		t.Errorf("A|base64 on a large integer: errors %q", encoded.Errors)
	}

	file := ExtractFile("name: r\ndetection:\n  sel: {A: 1}\n  condition: sel\n---\ntitle: c\ncorrelation:\n" +
		"  type: event_count\n  rules: [r]\n  timespan: 5m\n  condition: {gte: 18446744073709551616}\n")
	if len(file.Errors) > 0 || len(file.Correlations) != 1 || file.Correlations[0].Conditions[0].Value != 18446744073709551616 {
		t.Errorf("correlation threshold of a large integer: errors %q, file %+v", file.Errors, file)
	}
}
