package sigma

import (
	"fmt"
	"strings"
)

// detectionItem holds the resolved conditions for a named detection block.
type detectionItem struct {
	name       string
	conditions []Condition
	isKeyword  bool
}

// resolveDetectionItems walks the detection map and resolves each named entry
// (excluding "condition" and "timeframe") into a detectionItem.
func resolveDetectionItems(detection map[string]any) (map[string]*detectionItem, []string) {
	items := make(map[string]*detectionItem)
	var errors []string

	for name, raw := range detection {
		lower := strings.ToLower(name)
		if lower == "condition" || lower == "timeframe" {
			continue
		}

		item, errs := resolveDetectionEntry(name, raw)
		items[name] = item
		errors = append(errors, errs...)
	}

	return items, errors
}

// resolveDetectionEntry resolves a single detection entry to conditions.
func resolveDetectionEntry(name string, raw any) (*detectionItem, []string) {
	item := &detectionItem{name: name}
	var errors []string

	switch v := raw.(type) {
	case map[string]any:
		// Map of field:value — AND between fields
		conds, errs := resolveFieldMap(v)
		item.conditions = conds
		errors = append(errors, errs...)

	case []any:
		// List — could be list of maps (OR between maps) or keyword list
		conds, isKeyword, errs := resolveList(v)
		item.conditions = conds
		item.isKeyword = isKeyword
		errors = append(errors, errs...)

	case string:
		// Single keyword string
		item.isKeyword = true
		item.conditions = []Condition{{
			Field:    "",
			Operator: "keyword",
			Value:    v,
		}}

	default:
		errors = append(errors, fmt.Sprintf("detection '%s': unsupported type %T", name, raw))
	}

	return item, errors
}

// resolveFieldMap resolves a map of field:value pairs. Fields within a map are AND'd.
func resolveFieldMap(m map[string]any) ([]Condition, []string) {
	var conditions []Condition
	var errors []string

	for fieldWithMods, rawValue := range m {
		conds, errs := resolveFieldValue(fieldWithMods, rawValue)
		// AND between fields in same map
		for i := range conds {
			if i == 0 && len(conditions) > 0 {
				conds[i].LogicalOp = "AND"
			} else if i > 0 {
				// Multiple values for same field are OR'd (unless |all)
				// LogicalOp is set in resolveFieldValue
			}
		}
		if len(conds) > 0 && len(conditions) > 0 && conds[0].LogicalOp == "" {
			conds[0].LogicalOp = "AND"
		}
		conditions = append(conditions, conds...)
		errors = append(errors, errs...)
	}

	return conditions, errors
}

// resolveFieldValue resolves a single field:value pair, applying modifiers.
func resolveFieldValue(fieldWithMods string, rawValue any) ([]Condition, []string) {
	values, isNull := coerceToStringSlice(rawValue)

	// Handle null — maps to exists:false
	if isNull {
		field, _ := parseModifiers(fieldWithMods, nil)
		return []Condition{{
			Field:    field,
			Operator: "exists",
			Value:    "false",
		}}, nil
	}

	field, modResult := parseModifiers(fieldWithMods, values)

	// exists modifier: value is the modifier result
	if modResult.operator == "exists" {
		val := "true"
		if len(modResult.values) > 0 {
			v := strings.ToLower(modResult.values[0])
			if v == "false" || v == "no" || v == "0" {
				val = "false"
			}
		}
		return []Condition{{
			Field:    field,
			Operator: "exists",
			Value:    val,
		}}, nil
	}

	// Single value
	if len(modResult.values) == 1 {
		cond := Condition{
			Field:    field,
			Operator: modResult.operator,
			Value:    modResult.values[0],
		}
		// Bare wildcard → exists
		if cond.Value == "*" && cond.Operator == "=" {
			cond.Operator = "exists"
			cond.Value = "true"
		}
		return []Condition{cond}, nil
	}

	// Multiple values: OR between them (unless |all → AND)
	if modResult.allOf {
		conds := make([]Condition, len(modResult.values))
		for i, v := range modResult.values {
			conds[i] = Condition{
				Field:    field,
				Operator: modResult.operator,
				Value:    v,
			}
			if i > 0 {
				conds[i].LogicalOp = "AND"
			}
		}
		return conds, nil
	}

	// OR: group into single condition with alternatives
	cond := Condition{
		Field:        field,
		Operator:     modResult.operator,
		Value:        modResult.values[0],
		Alternatives: modResult.values,
	}
	return []Condition{cond}, nil
}

// resolveList resolves a YAML list (either list of maps or keyword list).
func resolveList(list []any) ([]Condition, bool, []string) {
	if len(list) == 0 {
		return nil, false, nil
	}

	// Check if it's a list of maps (OR between maps, AND within each map)
	if _, ok := list[0].(map[string]any); ok {
		return resolveListOfMaps(list)
	}

	// Otherwise it's a keyword list (OR between keywords)
	return resolveKeywordList(list)
}

// resolveListOfMaps handles a list of field:value maps (OR between maps).
func resolveListOfMaps(list []any) ([]Condition, bool, []string) {
	var conditions []Condition
	var errors []string

	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			errors = append(errors, fmt.Sprintf("expected map in list, got %T", item))
			continue
		}
		conds, errs := resolveFieldMap(m)
		// OR between list elements
		if i > 0 && len(conds) > 0 {
			conds[0].LogicalOp = "OR"
		}
		conditions = append(conditions, conds...)
		errors = append(errors, errs...)
	}

	return conditions, false, errors
}

// resolveKeywordList handles a list of keyword strings.
func resolveKeywordList(list []any) ([]Condition, bool, []string) {
	values := make([]string, 0, len(list))
	for _, item := range list {
		values = append(values, fmt.Sprintf("%v", item))
	}

	if len(values) == 0 {
		return nil, true, nil
	}

	cond := Condition{
		Field:        "",
		Operator:     "keyword",
		Value:        values[0],
		Alternatives: values,
	}
	return []Condition{cond}, true, nil
}

// coerceToStringSlice converts any YAML value to a string slice.
// Returns isNull=true if the value is nil.
func coerceToStringSlice(raw any) ([]string, bool) {
	if raw == nil {
		return nil, true
	}

	switch v := raw.(type) {
	case string:
		return []string{v}, false
	case int:
		return []string{fmt.Sprintf("%d", v)}, false
	case int64:
		return []string{fmt.Sprintf("%d", v)}, false
	case float64:
		// Check if it's actually an integer
		if v == float64(int64(v)) {
			return []string{fmt.Sprintf("%d", int64(v))}, false
		}
		return []string{fmt.Sprintf("%g", v)}, false
	case bool:
		if v {
			return []string{"true"}, false
		}
		return []string{"false"}, false
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if item == nil {
				continue
			}
			result = append(result, fmt.Sprintf("%v", item))
		}
		if len(result) == 0 {
			return nil, true
		}
		return result, false
	default:
		return []string{fmt.Sprintf("%v", v)}, false
	}
}
