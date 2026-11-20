package sigma

import (
	"slices"
	"testing"
)

// A condition written as a one-element list is that condition, so a near rule
// in that form is read as a temporal correlation too. It used to come back as
// a plain rule on the anchor search alone, the near search dropped without an
// error.
func TestExtractFileReadsNearInAOneElementConditionList(t *testing.T) {
	const detection = "title: n\ndetection:\n  a: {EventID: 1}\n  b: {EventID: 2}\n  timeframe: 10s\n  condition:"
	for _, condition := range []string{" a | near b\n", "\n    - a | near b\n"} {
		file := ExtractFile(detection + condition)
		if len(file.Errors) > 0 || len(file.Rules) != 0 || len(file.Correlations) != 1 {
			t.Errorf("condition%q: %d rules, %d correlations, errors %q", condition, len(file.Rules), len(file.Correlations), file.Errors)
			continue
		}
		c := file.Correlations[0]
		var names []string
		for _, ref := range c.Rules {
			names = append(names, ref.Name)
		}
		if c.Type != CorrelationTemporal || c.Timespan != "10s" || !slices.Equal(names, []string{"anchor", "b"}) {
			t.Errorf("condition%q: correlation %s over %q in %s", condition, c.Type, names, c.Timespan)
		}
	}
}
