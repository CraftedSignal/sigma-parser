package sigma

import (
	"fmt"
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
func resolveDetectionItems(detection orderedMap) (map[string]*detectionItem, []string) {
	items := make(map[string]*detectionItem)
	var errors []string
	for _, entry := range detection {
		lower := strings.ToLower(entry.key)
		if lower == "condition" || lower == "timeframe" {
			continue
		}
		item, errs := resolveDetectionEntry(entry.key, entry.value)
		items[entry.key] = item
		errors = append(errors, errs...)
	}
	return items, errors
}

// resolveDetectionEntry resolves one search identifier: a map of fields
// (ANDed), a list of maps (ORed), or keywords (a list or a plain value).
func resolveDetectionEntry(name string, raw any) (*detectionItem, []string) {
	item := &detectionItem{name: name}
	var errs []string
	switch v := raw.(type) {
	case orderedMap:
		item.expr, item.units, errs = resolveFieldMap(v)
	case []any:
		item.expr, item.isKeyword, errs = resolveList(v)
	case nil:
		errs = []string{fmt.Sprintf("detection '%s' is empty", name)}
	default:
		item.isKeyword = true
		item.expr, item.units, errs = fieldExpression("", raw)
	}
	item.conditions = flattenExpression(item.expr, false)
	return item, errs
}

// resolveFieldMap ANDs the fields of a map in their authored order.
func resolveFieldMap(m orderedMap) (*Expression, []*Expression, []string) {
	children := make([]*Expression, 0, len(m))
	var units []*Expression
	var errs []string
	for _, entry := range m {
		expr, fieldUnits, fieldErrs := fieldExpression(entry.key, entry.value)
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
func resolveList(list []any) (*Expression, bool, []string) {
	if len(list) == 0 {
		return nil, false, nil
	}
	if _, ok := list[0].(orderedMap); !ok {
		expr, _, errs := fieldExpression("", list)
		return expr, true, errs
	}
	children := make([]*Expression, 0, len(list))
	var errs []string
	for _, element := range list {
		m, ok := element.(orderedMap)
		if !ok {
			errs = append(errs, fmt.Sprintf("expected map in list, got %T", element))
			continue
		}
		expr, _, mapErrs := resolveFieldMap(m)
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
func flattenExpression(expression *Expression, negated bool) []Condition {
	if expression == nil {
		return nil
	}
	switch expression.Kind {
	case ExpressionCondition:
		if expression.Condition == nil {
			return nil
		}
		condition := *expression.Condition
		condition.LogicalOp = ""
		if negated {
			condition.Negated = !condition.Negated
		}
		return []Condition{condition}
	case ExpressionNot:
		var out []Condition
		for _, child := range expression.Children {
			out = append(out, flattenExpression(child, !negated)...)
		}
		return out
	}
	operator := "OR"
	if (expression.Kind == ExpressionAnd) != negated {
		operator = "AND"
	}
	var out []Condition
	for _, child := range expression.Children {
		conditions := flattenExpression(child, negated)
		if len(out) > 0 && len(conditions) > 0 {
			conditions[0].LogicalOp = operator
		}
		out = append(out, conditions...)
	}
	return out
}
