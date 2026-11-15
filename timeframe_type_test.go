package sigma_test

import (
	"context"
	"strings"
	"testing"

	sigma "github.com/craftedsignal/sigma-parser"
)

const timeframeRulePrefix = "title: timeframe type\ndetection:\n  selection: {EventID: 1}\n"

func timeframeRule(value, condition string) string {
	return timeframeRulePrefix + "  timeframe: " + value + "\n  condition: " + condition + "\n"
}

func assertInvalidTimeframeAcrossPublicAPIs(t *testing.T, rule string) {
	t.Helper()
	check := func(name string, errors []string, timeframe string) {
		t.Helper()
		joined := strings.Join(errors, "; ")
		if !strings.Contains(joined, "detection.timeframe") || !strings.Contains(joined, "must be a string") {
			t.Errorf("%s errors = %q; want authored timeframe type error", name, errors)
		}
		if timeframe != "" {
			t.Errorf("%s timeframe = %q; want no consumable timeframe", name, timeframe)
		}
	}
	checkFile := func(name string, file *sigma.File) {
		t.Helper()
		check(name, file.Errors, "")
		if len(file.Rules) != 0 || len(file.Correlations) != 0 {
			t.Errorf("%s returned consumable rules or correlations: %+v", name, file)
		}
	}

	plain := sigma.ExtractConditions(rule)
	check("ExtractConditions", plain.Errors, plain.Timeframe)
	checkFile("ExtractFile", sigma.ExtractFile(rule))
	semantic := sigma.AnalyzeQuery(rule)
	check("AnalyzeQuery", semantic.Errors, semantic.Timeframe)
	ctx := context.Background()
	withContext := sigma.ExtractConditionsContext(ctx, rule)
	check("ExtractConditionsContext", withContext.Errors, withContext.Timeframe)
	checkFile("ExtractFileContext", sigma.ExtractFileContext(ctx, rule))
	semanticContext := sigma.AnalyzeQueryContext(ctx, rule)
	check("AnalyzeQueryContext", semanticContext.Errors, semanticContext.Timeframe)
}

func TestPublicAPIsRejectAuthoredNonStringTimeframes(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"integer", "60"},
		{"float", "1.5"},
		{"boolean", "true"},
		{"null", "null"},
		{"empty YAML value", ""},
		{"sequence", "[5m]"},
		{"mapping", "{duration: 5m}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalidTimeframeAcrossPublicAPIs(t, timeframeRule(tc.value, "selection"))
		})
	}
}

func TestPublicAPIsRejectNonStringTimeframeAcrossRoutes(t *testing.T) {
	for _, tc := range []struct{ name, rule string }{
		{"alias", "duration: &numeric 60\n" + timeframeRulePrefix + "  timeframe: *numeric\n  condition: selection\n"},
		{"global", "action: global\ndetection:\n  timeframe: 60\n---\n" + timeframeRulePrefix + "  condition: selection\n"},
		{"repeat", timeframeRule("5m", "selection") + "---\naction: repeat\ndetection:\n  timeframe: 60\n"},
		{"aggregation", timeframeRule("60", "selection | count() > 1")},
		{"near", "title: near\ndetection:\n  selection: {EventID: 1}\n  other: {EventID: 2}\n  timeframe: 60\n  condition: selection | near other\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalidTimeframeAcrossPublicAPIs(t, tc.rule)
		})
	}
}

func TestTimeframeTypeErrorKeepsMissingConditionPrecedenceAndBoundsDiagnostic(t *testing.T) {
	missingCondition := timeframeRulePrefix + "  timeframe: 60\n"
	result := sigma.ExtractConditions(missingCondition)
	if len(result.Errors) != 1 || result.Errors[0] != "sigma rule missing 'detection.condition'" {
		t.Fatalf("missing condition error precedence changed: %q", result.Errors)
	}
	container := timeframeRule("{duration: "+strings.Repeat("X", 8192)+"}", "selection")
	result = sigma.ExtractConditions(container)
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "detection.timeframe") || len(result.Errors[0]) > 200 || result.Timeframe != "" {
		t.Fatalf("invalid container leaked into diagnostic or timeframe: errors=%q timeframe=%q", result.Errors, result.Timeframe)
	}
}

func TestPublicAPIsPreserveStringTimeframesAndAbsence(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"seconds", "15s", "15s"},
		{"minutes", "30m", "30m"},
		{"hours", "12h", "12h"},
		{"days", "7d", "7d"},
		{"months", "3M", "3M"},
		{"quoted", `"5m"`, "5m"},
		{"explicit string tag", "!!str 60s", "60s"},
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
				t.Fatalf("string timeframe %q changed: extraction=%+v file=%+v semantic=%+v extraction context=%+v file context=%+v semantic context=%+v", tc.value, plain, file, semantic, plainContext, fileContext, semanticContext)
			}
		})
	}
	without := timeframeRulePrefix + "  condition: selection\n"
	plain := sigma.ExtractConditions(without)
	file := sigma.ExtractFile(without)
	semantic := sigma.AnalyzeQuery(without)
	ctx := context.Background()
	plainContext := sigma.ExtractConditionsContext(ctx, without)
	fileContext := sigma.ExtractFileContext(ctx, without)
	semanticContext := sigma.AnalyzeQueryContext(ctx, without)
	if len(plain.Errors) != 0 || plain.Timeframe != "" || len(file.Errors) != 0 || len(file.Rules) != 1 || file.Rules[0].Timeframe != "" || len(semantic.Errors) != 0 || semantic.Timeframe != "" ||
		len(plainContext.Errors) != 0 || plainContext.Timeframe != "" || len(fileContext.Errors) != 0 || len(fileContext.Rules) != 1 || fileContext.Rules[0].Timeframe != "" || len(semanticContext.Errors) != 0 || semanticContext.Timeframe != "" {
		t.Fatalf("absent timeframe changed: extraction=%+v file=%+v semantic=%+v extraction context=%+v file context=%+v semantic context=%+v", plain, file, semantic, plainContext, fileContext, semanticContext)
	}
}

func TestValidAggregationAndNearTimeframesRemainUsable(t *testing.T) {
	for _, value := range []string{"", "5m"} {
		var rule string
		if value == "" {
			rule = timeframeRulePrefix + "  condition: selection | count() > 1\n"
		} else {
			rule = timeframeRule(value, "selection | count() > 1")
		}
		result := sigma.ExtractConditions(rule)
		if len(result.Errors) != 0 || result.Timeframe != value || len(result.Commands) != 1 || result.Commands[0] != "count" {
			t.Fatalf("aggregation timeframe %q changed: %+v", value, result)
		}
	}
	near := "title: near\ndetection:\n  selection: {EventID: 1}\n  other: {EventID: 2}\n  timeframe: 30s\n  condition: selection | near other\n"
	file := sigma.ExtractFile(near)
	if len(file.Errors) != 0 || len(file.Correlations) != 1 || file.Correlations[0].Timespan != "30s" {
		t.Fatalf("valid near timeframe changed: %+v", file)
	}
}

func TestCanceledContextAPIsKeepCancellationError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rule := timeframeRule("60", "selection")
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
