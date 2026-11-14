package sigma

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const smallResourceRule = "title: Small\ndetection:\n  selection: &values\n    Field: value\n  second: *values\n  condition: selection or second\n"

func extractWithTestLimits(input string, limits parseLimits) *ParseResult {
	return guardedWithLimits(context.Background(), input, limits, func(b *parseBudget) *ParseResult {
		return extractConditionsInternal(input, b)
	}, func(message string) *ParseResult {
		return &ParseResult{Errors: []string{message}}
	})
}

func TestResourceSmallBudgetsRejectWithoutPartialConditions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		adjust func(*parseLimits)
		want   string
	}{
		{"nodes", func(l *parseLimits) { l.nodes = 5 }, "nodes"},
		{"decoded bytes", func(l *parseLimits) { l.decodedBytes = 4 }, "decoded bytes"},
		{"work", func(l *parseLimits) { l.work = 1 }, "work"},
		{"depth", func(l *parseLimits) { l.depth = 2 }, "depth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := defaultParseLimits()
			tc.adjust(&limits)
			result := extractWithTestLimits(smallResourceRule, limits)
			if !strings.Contains(strings.Join(result.Errors, " "), tc.want) {
				t.Fatalf("expected %s rejection: %v", tc.want, result.Errors)
			}
			if len(result.Conditions) != 0 || result.Expression != nil {
				t.Fatal("resource rejection returned partial detection semantics")
			}
		})
	}
}

func TestResourceLegitimateAliasesPreserveConditions(t *testing.T) {
	result := ExtractConditions(smallResourceRule)
	if len(result.Errors) != 0 || len(result.Conditions) != 1 || result.Conditions[0].Value != "value" {
		t.Fatalf("ordinary repeated alias changed extraction: %+v", result)
	}
}

func TestResourceExpansionBudgets(t *testing.T) {
	input := "title: Small\ndetection:\n  selection:\n    Field|windash: '-a'\n  condition: selection\n"
	for _, tc := range []struct {
		name   string
		adjust func(*parseLimits)
		want   string
	}{
		{"variants", func(l *parseLimits) { l.variants = 4 }, "variants"},
		{"output bytes", func(l *parseLimits) { l.outputBytes = 16 }, "output bytes"},
		{"conditions", func(l *parseLimits) { l.conditions = 3 }, "conditions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := defaultParseLimits()
			tc.adjust(&limits)
			result := extractWithTestLimits(input, limits)
			if !strings.Contains(strings.Join(result.Errors, " "), tc.want) {
				t.Fatalf("expected %s rejection: %v", tc.want, result.Errors)
			}
			if len(result.Conditions) != 0 || result.Expression != nil {
				t.Fatal("resource rejection returned truncated match logic")
			}
		})
	}
}

func TestResourceConditionDepthAndReferenceCopies(t *testing.T) {
	for _, tc := range []struct {
		name, condition, want string
		adjust                func(*parseLimits)
	}{
		{"depth", "not not not not not not not not selection", "depth", func(l *parseLimits) { l.depth = 6 }},
		{"copies", "selection and selection", "conditions", func(l *parseLimits) { l.conditions = 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := "title: Small\ndetection:\n  selection:\n    Field: value\n  condition: " + tc.condition + "\n"
			limits := defaultParseLimits()
			tc.adjust(&limits)
			result := extractWithTestLimits(input, limits)
			if !strings.Contains(strings.Join(result.Errors, " "), tc.want) {
				t.Fatalf("expected %s rejection: %v", tc.want, result.Errors)
			}
			if result.Expression != nil || len(result.Conditions) != 0 {
				t.Fatal("rejected operation exposed partial detection data")
			}
		})
	}
}

func TestResourceInputLimitPrecedesExtraction(t *testing.T) {
	oldHook := extractHook
	t.Cleanup(func() { extractHook = oldHook })
	input := strings.Repeat(" ", (1<<20)+1)
	for _, entry := range []struct {
		name  string
		parse func(string) []string
	}{
		{"conditions", func(s string) []string { return ExtractConditions(s).Errors }},
		{"file", func(s string) []string { return ExtractFile(s).Errors }},
		{"semantic", func(s string) []string { return AnalyzeQuery(s).Errors }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			calls := 0
			extractHook = func(string) { calls++ }
			errs := entry.parse(input)
			if calls != 0 {
				t.Errorf("oversized input reached extraction %d times", calls)
			}
			if !strings.Contains(strings.Join(errs, " "), "input bytes") {
				t.Errorf("oversized input did not report input-byte limit: %v", errs)
			}
		})
	}
}

func TestResourceCancellationReturnsNoPartialResult(t *testing.T) {
	for _, entry := range []struct {
		name  string
		parse func(context.Context, string) (bool, []string)
	}{
		{"conditions", func(ctx context.Context, s string) (bool, []string) {
			r := ExtractConditionsContext(ctx, s)
			return len(r.Conditions) > 0 || r.Expression != nil, r.Errors
		}},
		{"file", func(ctx context.Context, s string) (bool, []string) {
			r := ExtractFileContext(ctx, s)
			return len(r.Rules) > 0 || len(r.Correlations) > 0, r.Errors
		}},
		{"semantic", func(ctx context.Context, s string) (bool, []string) {
			r := AnalyzeQueryContext(ctx, s)
			return len(r.Conditions) > 0 || r.Expression != nil || len(r.Detections) > 0, r.Errors
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			partial, errs := entry.parse(ctx, smallResourceRule)
			if partial || !strings.Contains(strings.Join(errs, " "), "context canceled") {
				t.Fatalf("canceled parse returned partial=%v errors=%v", partial, errs)
			}
		})
	}
	// Cancel between handwritten stages: parsing must stop before item resolution.
	ctx, cancel := context.WithCancel(context.Background())
	reached := false
	result := guardedWithLimits(ctx, smallResourceRule, defaultParseLimits(), func(b *parseBudget) *ParseResult {
		rules, err := parseSigmaRules(smallResourceRule, b)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		result := extractRule(rules[0], b)
		reached = true
		return result
	}, func(message string) *ParseResult { return &ParseResult{Errors: []string{message}} })
	if reached || len(result.Conditions) > 0 || !strings.Contains(strings.Join(result.Errors, " "), "context canceled") {
		t.Fatalf("stage cancellation was lost: reached=%v result=%+v", reached, result)
	}
}

func TestResourceBudgetsAreSharedAcrossDocumentsValuesAndSemanticEnrichment(t *testing.T) {
	single := "title: Small\nname: first\ndetection:\n  selection:\n    Field: value\n  condition: selection\n"
	var used int
	baseline := guardedWithLimits(context.Background(), single, defaultParseLimits(), func(b *parseBudget) *ParseResult {
		result := extractConditionsInternal(single, b)
		used = b.conditions
		return result
	}, func(message string) *ParseResult { return &ParseResult{Errors: []string{message}} })
	if len(baseline.Errors) > 0 || used == 0 {
		t.Fatalf("invalid baseline: %+v, used=%d", baseline, used)
	}
	limits := defaultParseLimits()
	limits.conditions = used
	semantic := guardedWithLimits(context.Background(), single, limits, func(b *parseBudget) *SemanticQuery { return analyzeQuery(single, b) }, func(message string) *SemanticQuery { return &SemanticQuery{Errors: []string{message}} })
	if !strings.Contains(strings.Join(semantic.Errors, " "), "conditions") || len(semantic.Conditions) > 0 || len(semantic.Detections) > 0 || semantic.Expression != nil {
		t.Fatalf("semantic copies escaped shared budget: %+v", semantic)
	}
	input := single + "---\n" + strings.Replace(single, "name: first", "name: second", 1)
	for _, resource := range []string{"documents", "conditions"} {
		t.Run(resource, func(t *testing.T) {
			limits := defaultParseLimits()
			if resource == "documents" {
				limits.documents = 1
			} else {
				limits.conditions = used
			}
			file := guardedWithLimits(context.Background(), input, limits, func(b *parseBudget) *File { return extractFile(input, b) }, func(message string) *File { return &File{Errors: []string{message}} })
			if !strings.Contains(strings.Join(file.Errors, " "), resource) || len(file.Rules) > 0 || len(file.Correlations) > 0 {
				t.Fatalf("collection escaped shared budget: %+v", file)
			}
		})
	}
	// Each flag alone has only five possible matches; the operation still
	// charges every value rather than restarting the budget for each modifier.
	input = "title: Small\ndetection:\n  selection:\n    Field|windash: ['-a', '-b']\n  condition: selection\n"
	limits = defaultParseLimits()
	limits.variants = 15
	result := extractWithTestLimits(input, limits)
	if !strings.Contains(strings.Join(result.Errors, " "), "variants") || len(result.Conditions) > 0 {
		t.Fatalf("modifier values escaped cumulative budget: %+v", result)
	}
}

func TestResourceAliasCycleAndCheckedProduct(t *testing.T) {
	// A tiny in-memory node graph tests the guard without parsing a hostile
	// document or relying on recursive overflow to demonstrate the failure.
	cycle := &yaml.Node{Kind: yaml.AliasNode}
	cycle.Alias = cycle
	result := guardedWithLimits(context.Background(), "", defaultParseLimits(), func(b *parseBudget) string {
		if _, err := decodeOrdered(cycle, b); err != nil {
			t.Fatal(err)
		}
		return "accepted"
	}, func(message string) string { return message })
	if !strings.Contains(result, "cyclic YAML alias") {
		t.Fatalf("active alias cycle was accepted: %s", result)
	}
	maxInt := int(^uint(0) >> 1)
	result = guardedWithLimits(context.Background(), "", defaultParseLimits(), func(b *parseBudget) string { b.product(maxInt, 2, maxInt, "variants"); return "accepted" }, func(message string) string { return message })
	if !strings.Contains(result, "variants") {
		t.Fatalf("overflowing Cartesian product was accepted: %s", result)
	}
}

func TestResourceAliasExpansionChargesEveryOccurrence(t *testing.T) {
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "safe"}
	alias := &yaml.Node{Kind: yaml.AliasNode, Alias: scalar}
	repeated := &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{scalar, alias, alias}}
	limits := defaultParseLimits()
	limits.decodedBytes = 8
	result := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) string {
		if _, err := decodeOrdered(repeated, b); err != nil {
			t.Fatal(err)
		}
		return "accepted"
	}, func(message string) string { return message })
	if !strings.Contains(result, "decoded bytes") {
		t.Fatalf("alias occurrences were not charged: %s", result)
	}
}

func TestResourceCorrelationOutputAndRepeatedReferences(t *testing.T) {
	leaf := &ParseResult{Title: "ordinary", Conditions: []Condition{{Field: "Field", Operator: "=", Value: "safe"}}}
	shared := &Correlation{Rules: []CorrelationRule{{Name: "leaf", Rule: leaf}}}
	outer := &Correlation{Rules: []CorrelationRule{{Name: "one", Correlation: shared}, {Name: "two", Correlation: shared}}}
	file := &File{Correlations: []*Correlation{outer}}
	if rules := file.DetectionRules(); len(rules) != 1 || rules[0] != leaf {
		t.Fatalf("shared correlation should visit each rule once: %+v", rules)
	}
	limits := defaultParseLimits()
	limits.conditions = 1
	result := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) *File { b.checkFileOutput(file); return file }, func(message string) *File { return &File{Errors: []string{message}} })
	if !strings.Contains(strings.Join(result.Errors, " "), "conditions") || len(result.Correlations) > 0 || len(result.Rules) > 0 {
		t.Fatalf("serialized references escaped cumulative output budget: %+v", result)
	}
}

func TestResourceSemanticEnrichmentDoesNotSwallowAbort(t *testing.T) {
	baseline := ExtractConditions(smallResourceRule)
	if len(baseline.Errors) > 0 {
		t.Fatal(baseline.Errors)
	}
	for _, resource := range []string{"nodes", "context canceled"} {
		t.Run(resource, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := guardedWithLimits(ctx, smallResourceRule, defaultParseLimits(), func(b *parseBudget) *SemanticQuery {
				semantic := semanticFromExtraction(baseline, b)
				if resource == "nodes" {
					b.limits.nodes = b.nodes
				} else {
					cancel()
				}
				enrichSemanticQueryFromYAML(semantic, smallResourceRule, b)
				return semantic
			}, func(message string) *SemanticQuery { return &SemanticQuery{Errors: []string{message}} })
			if !strings.Contains(strings.Join(result.Errors, " "), resource) || len(result.Conditions) > 0 || result.Expression != nil || len(result.Detections) > 0 {
				t.Fatalf("enrichment swallowed abort and returned partial semantics: %+v", result)
			}
		})
	}
}

func TestResourceCollectionSemanticNamesConsumeSharedBudget(t *testing.T) {
	for _, expression := range []*SemanticConditionExpression{
		{Operator: "ref", Selector: "selection"},
		{Operator: "quantifier", Quantifier: "all", Pattern: "them"},
	} {
		limits := defaultParseLimits()
		limits.outputBytes = 1
		result := guardedWithLimits(context.Background(), "", limits, func(b *parseBudget) *SemanticQuery {
			scopeSemanticCondition(expression, "rule1_", b)
			return &SemanticQuery{ConditionExpression: expression}
		}, func(message string) *SemanticQuery { return &SemanticQuery{Errors: []string{message}} })
		if !strings.Contains(strings.Join(result.Errors, " "), "output bytes") || result.ConditionExpression != nil {
			t.Fatalf("collection names escaped shared budget or exposed partial selectors: %+v", result)
		}
	}
}
