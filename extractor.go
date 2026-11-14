package sigma

import (
	"context"
	"fmt"
	"time"
)

var (
	maxParseTime = 5 * time.Second
	extractHook  func(string)
)

// ExtractConditions parses a Sigma YAML rule and returns structured conditions.
// This is the main entry point, matching the API of spl-parser and leql-parser.
// A rule collection is extracted as the OR of its rules (see ExtractFile).
// Includes cooperative cancellation, resource bounds, and panic recovery.
func ExtractConditions(yamlContent string) *ParseResult {
	return ExtractConditionsContext(context.Background(), yamlContent)
}

// ExtractConditionsContext parses with caller cancellation and a cooperative
// five-second deadline. It never leaves a parse worker running.
func ExtractConditionsContext(ctx context.Context, yamlContent string) *ParseResult {
	return guarded(ctx, yamlContent, func(b *parseBudget) *ParseResult {
		return extractConditionsInternal(yamlContent, b)
	}, func(message string) *ParseResult {
		return &ParseResult{ComputedFields: make(map[string]string), Errors: []string{message}}
	})
}

func guarded[T any](ctx context.Context, input string, extract func(*parseBudget) T, failed func(string) T) T {
	return guardedWithLimits(ctx, input, defaultParseLimits(), extract, failed)
}

func guardedWithLimits[T any](ctx context.Context, input string, limits parseLimits, extract func(*parseBudget) T, failed func(string) T) (result T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if abort, ok := recovered.(parseAbort); ok {
				result = failed(abortMessage(abort.err))
			} else {
				result = failed(fmt.Sprintf("panic during parsing: %v", recovered))
			}
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	b := newParseBudget(ctx, limits)
	b.input(input)
	ctx, cancel := context.WithTimeout(ctx, maxParseTime)
	defer cancel()
	b.ctx = ctx
	b.check()
	if extractHook != nil {
		extractHook(input)
	}
	b.check()
	result = extract(b)
	b.check()
	return result
}

// extractConditionsInternal does the actual parsing work.
func extractConditionsInternal(yamlContent string, budgets ...*parseBudget) *ParseResult {
	b := budgetFrom(budgets)
	b.input(yamlContent)
	rule, err := parseSigmaRule(yamlContent, b)
	if err != nil {
		return &ParseResult{ComputedFields: make(map[string]string), Errors: []string{err.Error()}}
	}
	return extractRule(rule, b)
}

// extractRule extracts the conditions of one parsed rule.
func extractRule(rule *sigmaRule, budgets ...*parseBudget) *ParseResult {
	b := budgetFrom(budgets)
	b.step(1)
	result := &ParseResult{
		ComputedFields: make(map[string]string),
	}

	// Copy metadata
	result.Title = rule.Title
	result.ID = rule.ID
	result.Name = rule.Name
	result.Level = rule.Level
	result.Status = rule.Status
	result.Tags = rule.Tags
	if rule.LogSource.Category != "" || rule.LogSource.Product != "" || rule.LogSource.Service != "" {
		result.LogSource = &LogSource{
			Category: rule.LogSource.Category,
			Product:  rule.LogSource.Product,
			Service:  rule.LogSource.Service,
		}
	}

	// Phase 2: Resolve detection items
	items, errs := resolveDetectionItems(rule.Detection, b)
	result.Errors = append(result.Errors, errs...)

	// Phase 3: Parse condition expression
	condition, _ := rule.Detection.get("condition")
	ast, aggExprs, multipleConditions, conditionErrs := parseDetectionCondition(condition, b)
	result.Errors = append(result.Errors, conditionErrs...)
	if ast == nil {
		result.Errors = append(result.Errors, "empty condition expression")
		return result
	}
	result.Errors = append(result.Errors, conditionReferenceErrors(ast, items, b)...)
	result.Expression = buildExpression(ast, items, b)
	result.Errors = append(result.Errors, validateExpression(result.Expression, b)...)
	result.Warnings = commandLineWarnings(result.Expression, b)

	// Phase 4: Evaluate AST → conditions
	conditions := evaluateAST(ast, items, false, b)

	// Phase 4b: Parse aggregation if present
	timeframe := ""
	if tf, ok := rule.Detection.get("timeframe"); ok {
		timeframe = b.formatValue(tf)
	}
	result.Timeframe = timeframe
	if multipleConditions && len(aggExprs) > 0 {
		result.Errors = append(result.Errors, "multiple condition strings with aggregation cannot be represented losslessly")
	}
	for _, aggExpr := range aggExprs {
		b.step(len(aggExpr) + 1)
		agg, aggErrs := parseAggregation(aggExpr, timeframe, b)
		result.Errors = append(result.Errors, aggErrs...)
		if agg == nil {
			continue
		}
		aggConds, groupBy, commands := agg.toConditions()
		b.copyConditions(aggConds)
		conditions = append(conditions, aggConds...)
		result.GroupByFields = append(result.GroupByFields, groupBy...)
		result.Commands = append(result.Commands, commands...)
	}

	// Phase 5: Post-process
	conditions = groupORConditions(conditions, b)
	conditions = deduplicateConditions(conditions, b)

	result.Conditions = conditions
	return result
}

func parseDetectionCondition(raw any, budgets ...*parseBudget) (condNode, []string, bool, []string) {
	b := budgetFrom(budgets)
	switch v := raw.(type) {
	case string:
		node, aggExpr, errs := parseConditionExpr(v, b)
		return node, nonEmptyAggExprs(aggExpr), false, errs
	case []any:
		b.node(len(v))
		children := make([]condNode, 0, len(v))
		var aggExprs []string
		var errors []string
		for _, item := range v {
			b.step(1)
			node, aggExpr, errs := parseConditionExpr(b.formatValue(item), b)
			errors = append(errors, errs...)
			if node != nil {
				children = append(children, node)
			}
			aggExprs = append(aggExprs, nonEmptyAggExprs(aggExpr)...)
		}
		switch len(children) {
		case 0:
			return nil, aggExprs, len(v) > 1, errors
		case 1:
			return children[0], aggExprs, len(v) > 1, errors
		default:
			return condNodeOr{children: children}, aggExprs, true, errors
		}
	default:
		return nil, nil, false, []string{fmt.Sprintf("unsupported condition expression type %T", raw)}
	}
}

func nonEmptyAggExprs(expr string) []string {
	if expr == "" {
		return nil
	}
	return []string{expr}
}
