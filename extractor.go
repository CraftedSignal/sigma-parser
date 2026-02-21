package sigma

import (
	"fmt"
	"time"
)

// ExtractConditions parses a Sigma YAML rule and returns structured conditions.
// This is the main entry point, matching the API of spl-parser and leql-parser.
// Includes 5-second timeout and panic recovery.
func ExtractConditions(yamlContent string) *ParseResult {
	result := &ParseResult{
		ComputedFields: make(map[string]string),
	}

	type extractResult struct {
		result *ParseResult
	}

	done := make(chan extractResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- extractResult{
					result: &ParseResult{
						ComputedFields: make(map[string]string),
						Errors:         []string{fmt.Sprintf("panic during parsing: %v", r)},
					},
				}
			}
		}()
		done <- extractResult{result: extractConditionsInternal(yamlContent)}
	}()

	select {
	case res := <-done:
		return res.result
	case <-time.After(5 * time.Second):
		result.Errors = append(result.Errors, "parsing timed out after 5 seconds")
		return result
	}
}

// extractConditionsInternal does the actual parsing work.
func extractConditionsInternal(yamlContent string) *ParseResult {
	result := &ParseResult{
		ComputedFields: make(map[string]string),
	}

	// Phase 1: YAML deserialization
	rule, err := parseSigmaRule(yamlContent)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	// Copy metadata
	result.Title = rule.Title
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
	condStr := ""
	switch v := rule.Detection["condition"].(type) {
	case string:
		condStr = v
	case []any:
		// Multiple conditions — use first one
		if len(v) > 0 {
			condStr = fmt.Sprintf("%v", v[0])
		}
	}

	if condStr == "" {
		result.Errors = append(result.Errors, "empty condition expression")
		return result
	}

	ast, aggExpr, parseErrs := parseConditionExpr(condStr)
	result.Errors = append(result.Errors, parseErrs...)

	// Phase 4: Evaluate AST → conditions
	conditions := evaluateAST(ast, items, false)

	// Phase 4b: Parse aggregation if present
	timeframe := ""
	if tf, ok := rule.Detection["timeframe"]; ok {
		timeframe = fmt.Sprintf("%v", tf)
	}
	agg, aggErrs := parseAggregation(aggExpr, timeframe)
	result.Errors = append(result.Errors, aggErrs...)

	if agg != nil {
		aggConds, groupBy, commands := agg.toConditions()
		conditions = append(conditions, aggConds...)
		result.GroupByFields = groupBy
		result.Commands = commands
	}

	// Phase 5: Post-process
	conditions = groupORConditions(conditions)
	conditions = deduplicateConditions(conditions)

	result.Conditions = conditions
	return result
}
