package sigma

import (
	"strings"
)

// detectionItem holds the resolved match logic of a named search identifier.
type detectionItem struct {
	name       string
	expr       *Expression // lossless match logic
	conditions []Condition // flat view of expr for legacy consumers
	isKeyword  bool
	units      []*Expression // per-value logic of a single-field item, for "N of" thresholds
}

// resolveDetectionItems resolves every search identifier of a detection block
// (everything except "condition" and "timeframe").
func resolveDetectionItems(detection orderedMap, budgets ...*parseBudget) (map[string]*detectionItem, []string) {
	b := budgetFrom(budgets)
	b.node(len(detection))
	items := make(map[string]*detectionItem)
	var errors []string
	for _, entry := range detection {
		b.step(1)
		lower := strings.ToLower(entry.key)
		if lower == "condition" || lower == "timeframe" {
			continue
		}
		item, errs := resolveDetectionEntry(entry.key, entry.value, b)
		items[entry.key] = item
		errors = append(errors, errs...)
	}
	return items, errors
}

// resolveDetectionEntry resolves one search identifier: a map of fields
// (ANDed), a list of maps (ORed), or keywords (a list or a plain value).
func resolveDetectionEntry(name string, raw any, budgets ...*parseBudget) (*detectionItem, []string) {
	b := budgetFrom(budgets)
	b.step(1)
	item := &detectionItem{name: name}
	var errs []string
	switch v := raw.(type) {
	case orderedMap:
		item.expr, item.units, errs = resolveFieldMap(v, b)
	case []any:
		item.expr, item.isKeyword, errs = resolveList(v, b)
	case nil:
		errs = []string{b.formatError("detection '%s' is empty", name)}
	default:
		item.isKeyword = true
		item.expr, item.units, errs = fieldExpression("", raw, b)
	}
	item.conditions = flattenExpression(item.expr, false, b)
	return item, errs
}

// resolveFieldMap ANDs the fields of a map in their authored order.
func resolveFieldMap(m orderedMap, budgets ...*parseBudget) (*Expression, []*Expression, []string) {
	b := budgetFrom(budgets)
	b.node(len(m))
	children := make([]*Expression, 0, len(m))
	var units []*Expression
	var errs []string
	for _, entry := range m {
		b.step(1)
		expr, fieldUnits, fieldErrs := fieldExpression(entry.key, entry.value, b)
		errs = append(errs, fieldErrs...)
		if expr != nil {
			children = append(children, expr)
		}
		if len(m) == 1 {
			units = fieldUnits
		}
	}
	return compactExpression(ExpressionAnd, children), units, errs
}

// resolveList resolves a list of maps (ORed) or a keyword list.
func resolveList(list []any, budgets ...*parseBudget) (*Expression, bool, []string) {
	b := budgetFrom(budgets)
	b.node(len(list))
	if len(list) == 0 {
		return nil, false, nil
	}
	if _, ok := list[0].(orderedMap); !ok {
		expr, _, errs := fieldExpression("", list, b)
		return expr, true, errs
	}
	children := make([]*Expression, 0, len(list))
	var errs []string
	for _, element := range list {
		b.step(1)
		m, ok := element.(orderedMap)
		if !ok {
			errs = append(errs, b.formatError("expected map in list, got %T", element))
			continue
		}
		expr, _, mapErrs := resolveFieldMap(m, b)
		errs = append(errs, mapErrs...)
		if expr != nil {
			children = append(children, expr)
		}
	}
	return compactExpression(ExpressionOr, children), false, errs
}

// isNestedValue reports a mapping, or a list holding mappings or lists. Sigma
// values are scalars or flat scalar lists, so these cannot be matched.
func isNestedValue(raw any) bool {
	switch value := raw.(type) {
	case orderedMap:
		return true
	case []any:
		for _, item := range value {
			switch item.(type) {
			case orderedMap, []any:
				return true
			}
		}
	}
	return false
}

// flattenExpression lists an expression's conditions with the logical
// operator linking each to the previous one, pushing negation down with De
// Morgan's laws. Grouping is lost; Expression carries the exact logic.
func flattenExpression(expression *Expression, negated bool, budgets ...*parseBudget) []Condition {
	b := budgetFrom(budgets)
	b.step(1)
	defer b.enter()()
	if expression == nil {
		return nil
	}
	switch expression.Kind {
	case ExpressionCondition:
		if expression.Condition == nil {
			return nil
		}
		condition := *expression.Condition
		b.copyCondition(condition)
		condition.LogicalOp = ""
		if negated {
			condition.Negated = !condition.Negated
		}
		return []Condition{condition}
	case ExpressionNot:
		var out []Condition
		for _, child := range expression.Children {
			conditions := flattenExpression(child, !negated, b)
			b.node(len(conditions))
			out = append(out, conditions...)
		}
		return out
	}
	operator := "OR"
	if (expression.Kind == ExpressionAnd) != negated {
		operator = "AND"
	}
	var out []Condition
	for _, child := range expression.Children {
		conditions := flattenExpression(child, negated, b)
		if len(out) > 0 && len(conditions) > 0 {
			conditions[0].LogicalOp = operator
		}
		b.node(len(conditions))
		out = append(out, conditions...)
	}
	return out
}
