package sigma

import (
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
// Includes 5-second timeout and panic recovery.
func ExtractConditions(yamlContent string) *ParseResult {
	return guarded(yamlContent, func() *ParseResult {
		return extractConditionsInternal(yamlContent)
	}, func(message string) *ParseResult {
		return &ParseResult{ComputedFields: make(map[string]string), Errors: []string{message}}
	})
}

// guarded runs an extraction with the parse timeout and panic recovery,
// reporting either through failed.
func guarded[T any](yamlContent string, extract func() T, failed func(message string) T) T {
	done := make(chan T, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- failed(fmt.Sprintf("panic during parsing: %v", r))
			}
		}()
		if extractHook != nil {
			extractHook(yamlContent)
		}
		done <- extract()
	}()

	select {
	case result := <-done:
		return result
	case <-time.After(maxParseTime):
		return failed(fmt.Sprintf("parsing timed out after %s", maxParseTime))
	}
}

// extractConditionsInternal does the actual parsing work.
func extractConditionsInternal(yamlContent string) *ParseResult {
	rule, err := parseSigmaRule(yamlContent)
	if err != nil {
		return &ParseResult{ComputedFields: make(map[string]string), Errors: []string{err.Error()}}
	}
	return extractRule(rule)
}

// extractRule extracts the conditions of one parsed rule.
func extractRule(rule *sigmaRule) *ParseResult {
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
	items, errs := resolveDetectionItems(rule.Detection)
	result.Errors = append(result.Errors, errs...)

	// Phase 3: Parse condition expression
	condition, _ := rule.Detection.get("condition")
	ast, aggExprs, multipleConditions, conditionErrs := parseDetectionCondition(condition)
	result.Errors = append(result.Errors, conditionErrs...)
	if ast == nil {
		result.Errors = append(result.Errors, "empty condition expression")
		return result
	}
	result.Errors = append(result.Errors, conditionReferenceErrors(ast, items)...)
	result.Expression = buildExpression(ast, items)
	result.Errors = append(result.Errors, validateExpression(result.Expression)...)
	result.Warnings = commandLineWarnings(result.Expression)

	// Phase 4: Evaluate AST → conditions
	conditions := evaluateAST(ast, items, false)

	// Phase 4b: Parse aggregation if present
	timeframe := ""
	if tf, ok := rule.Detection.get("timeframe"); ok {
		timeframe = fmt.Sprintf("%v", tf)
	}
	result.Timeframe = timeframe
	if multipleConditions && len(aggExprs) > 0 {
		result.Errors = append(result.Errors, "multiple condition strings with aggregation cannot be represented losslessly")
	}
	for _, aggExpr := range aggExprs {
		agg, aggErrs := parseAggregation(aggExpr, timeframe)
		result.Errors = append(result.Errors, aggErrs...)
		if agg == nil {
			continue
		}
		aggConds, groupBy, commands := agg.toConditions()
		conditions = append(conditions, aggConds...)
		result.GroupByFields = append(result.GroupByFields, groupBy...)
		result.Commands = append(result.Commands, commands...)
	}

	// Phase 5: Post-process
	conditions = groupORConditions(conditions)
	conditions = deduplicateConditions(conditions)

	result.Conditions = conditions
	return result
}

func parseDetectionCondition(raw any) (condNode, []string, bool, []string) {
	switch v := raw.(type) {
	case string:
		node, aggExpr, errs := parseConditionExpr(v)
		return node, nonEmptyAggExprs(aggExpr), false, errs
	case []any:
		children := make([]condNode, 0, len(v))
		var aggExprs []string
		var errors []string
		for _, item := range v {
			node, aggExpr, errs := parseConditionExpr(fmt.Sprintf("%v", item))
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
