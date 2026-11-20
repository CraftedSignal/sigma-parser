package sigma

import (
	"strings"
	"testing"
)

// A condition that ends inside a quoted string is an error. A quote as the
// last character used to panic, and the recovered panic replaced the whole
// result, title and logsource included.
func TestConditionEndingInAQuoteIsAnError(t *testing.T) {
	for _, condition := range []string{`"sel '"`, `"sel 'x"`, `"sel '\\"`} {
		result := ExtractConditions("title: t\nlogsource: {product: windows}\ndetection:\n  sel: {A: 1}\n  condition: " + condition + "\n")
		if errors := strings.Join(result.Errors, "; "); errors == "" || strings.Contains(errors, "panic") {
			t.Errorf("condition %s: errors %q", condition, result.Errors)
		}
		if result.Title != "t" || result.LogSource == nil {
			t.Errorf("condition %s: lost the rule's metadata: title %q, logsource %v", condition, result.Title, result.LogSource)
		}
	}
}
