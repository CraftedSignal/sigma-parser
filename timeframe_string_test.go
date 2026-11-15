package sigma_test

import (
	"context"
	"strings"
	"testing"

	sigma "github.com/craftedsignal/sigma-parser"
)

func assertInvalidTimeframeStringAcrossPublicAPIs(t *testing.T, rule, want string) {
	t.Helper()
	check := func(name string, errors []string, timeframe string) {
		t.Helper()
		joined := strings.Join(errors, "; ")
		if !strings.Contains(joined, "detection.timeframe") || !strings.Contains(joined, want) {
			t.Errorf("%s errors = %q; want %q", name, errors, want)
		}
		if len(joined) > 200 {
			t.Errorf("%s diagnostic expanded rejected timeframe to %d bytes", name, len(joined))
		}
		if timeframe != "" {
			t.Errorf("%s returned consumable timeframe of %d bytes", name, len(timeframe))
		}
	}
	checkFile := func(name string, file *sigma.File) {
		t.Helper()
		check(name, file.Errors, "")
		if len(file.Rules) != 0 || len(file.Correlations) != 0 {
			t.Errorf("%s returned consumable rule or correlation: %+v", name, file)
		}
	}

	plain := sigma.ExtractConditions(rule)
	check("ExtractConditions", plain.Errors, plain.Timeframe)
	checkFile("ExtractFile", sigma.ExtractFile(rule))
	semantic := sigma.AnalyzeQuery(rule)
	check("AnalyzeQuery", semantic.Errors, semantic.Timeframe)
	ctx := context.Background()
	plainContext := sigma.ExtractConditionsContext(ctx, rule)
	check("ExtractConditionsContext", plainContext.Errors, plainContext.Timeframe)
	checkFile("ExtractFileContext", sigma.ExtractFileContext(ctx, rule))
	semanticContext := sigma.AnalyzeQueryContext(ctx, rule)
	check("AnalyzeQueryContext", semanticContext.Errors, semanticContext.Timeframe)
}

func TestPublicAPIsRejectBlankTimeframeStrings(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty", `''`},
		{"spaces", `'   '`},
		{"escaped whitespace", `"\t\n"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalidTimeframeStringAcrossPublicAPIs(t, timeframeRule(tc.value, "selection"), "must not be empty")
		})
	}
}

func TestPublicAPIsRejectNumericOnlyTimeframeStrings(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"integer", `'60'`},
		{"explicit string tag", "!!str 60"},
		{"zero", `'0'`},
		{"leading zeroes", `'00060'`},
		{"plus sign", `'+60'`},
		{"minus sign", `'-60'`},
		{"decimal", `'1.5'`},
		{"leading dot", `'.5'`},
		{"trailing dot", `'5.'`},
		{"signed decimal", `'-0.5'`},
		{"exponent", `'1e3'`},
		{"signed exponent", `'1E+3'`},
		{"negative exponent", `'1e-3'`},
		{"trimmed number", `' 60 '`},
		{"long digits", "'" + strings.Repeat("8", 8192) + "'"},
		{"long exponent", "'1e" + strings.Repeat("8", 8192) + "'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalidTimeframeStringAcrossPublicAPIs(t, timeframeRule(tc.value, "selection"), "must include a time unit")
		})
	}
}

func TestPublicAPIsRejectStringTimeframesAcrossRoutes(t *testing.T) {
	for _, tc := range []struct{ name, rule, want string }{
		{"alias", "duration: &numeric '60'\n" + timeframeRulePrefix + "  timeframe: *numeric\n  condition: selection\n", "must include a time unit"},
		{"global", "action: global\ndetection:\n  timeframe: '60'\n---\n" + timeframeRulePrefix + "  condition: selection\n", "must include a time unit"},
		{"aggregation", timeframeRule(`'60'`, "selection | count() > 1"), "must include a time unit"},
		{"near with empty", "title: near\ndetection:\n  selection: {EventID: 1}\n  other: {EventID: 2}\n  timeframe: ''\n  condition: selection | near other\n", "must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalidTimeframeStringAcrossPublicAPIs(t, tc.rule, tc.want)
		})
	}
}

func TestPublicAPIsPreserveAcceptedTimeframeStrings(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"seconds", "15s", "15s"},
		{"minutes", "30m", "30m"},
		{"hours", "12h", "12h"},
		{"days", "7d", "7d"},
		{"months", "3M", "3M"},
		{"weeks compatibility", "1w", "1w"},
		{"years compatibility", "1y", "1y"},
		{"decimal with unit compatibility", "1.5h", "1.5h"},
		{"zero with unit compatibility", "0s", "0s"},
		{"leading zero with unit compatibility", "01m", "01m"},
		{"spaces retained", `' 5m '`, " 5m "},
		{"exponent with unit compatibility", "1e3s", "1e3s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := timeframeRule(tc.value, "selection")
			plain := sigma.ExtractConditions(rule)
			file := sigma.ExtractFile(rule)
			semantic := sigma.AnalyzeQuery(rule)
			ctx := context.Background()
			plainContext := sigma.ExtractConditionsContext(ctx, rule)
			fileContext := sigma.ExtractFileContext(ctx, rule)
			semanticContext := sigma.AnalyzeQueryContext(ctx, rule)
			if len(plain.Errors) != 0 || plain.Timeframe != tc.want || len(file.Errors) != 0 || len(file.Rules) != 1 || file.Rules[0].Timeframe != tc.want || len(semantic.Errors) != 0 || semantic.Timeframe != tc.want ||
				len(plainContext.Errors) != 0 || plainContext.Timeframe != tc.want || len(fileContext.Errors) != 0 || len(fileContext.Rules) != 1 || fileContext.Rules[0].Timeframe != tc.want || len(semanticContext.Errors) != 0 || semanticContext.Timeframe != tc.want {
				t.Fatalf("accepted timeframe %q changed: extraction=%+v file=%+v semantic=%+v extraction context=%+v file context=%+v semantic context=%+v", tc.value, plain, file, semantic, plainContext, fileContext, semanticContext)
			}
		})
	}
}

func TestAbsentTimeframeStillWorksWithNearAndAggregation(t *testing.T) {
	near := "title: near\ndetection:\n  selection: {EventID: 1}\n  other: {EventID: 2}\n  condition: selection | near other\n"
	file := sigma.ExtractFile(near)
	if len(file.Errors) != 0 || len(file.Correlations) != 1 || file.Correlations[0].Timespan != "" {
		t.Fatalf("absent near timeframe changed: %+v", file)
	}
	aggregation := sigma.ExtractConditions(timeframeRulePrefix + "  condition: selection | count() > 1\n")
	if len(aggregation.Errors) != 0 || aggregation.Timeframe != "" || len(aggregation.Commands) != 1 || aggregation.Commands[0] != "count" {
		t.Fatalf("absent aggregation timeframe changed: %+v", aggregation)
	}
}

func TestStringTimeframeValidationKeepsConditionAndCancellationPrecedence(t *testing.T) {
	missingCondition := timeframeRulePrefix + "  timeframe: '60'\n"
	result := sigma.ExtractConditions(missingCondition)
	if len(result.Errors) != 1 || result.Errors[0] != "sigma rule missing 'detection.condition'" {
		t.Fatalf("missing condition error precedence changed: %q", result.Errors)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rule := timeframeRule(`'60'`, "selection")
	for name, errors := range map[string][]string{
		"ExtractConditionsContext": sigma.ExtractConditionsContext(ctx, rule).Errors,
		"ExtractFileContext":       sigma.ExtractFileContext(ctx, rule).Errors,
		"AnalyzeQueryContext":      sigma.AnalyzeQueryContext(ctx, rule).Errors,
	} {
		if len(errors) != 1 || errors[0] != context.Canceled.Error() {
			t.Errorf("%s errors = %q; want context canceled", name, errors)
		}
	}
}
