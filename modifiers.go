package sigma

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// valueKind is what a detection value means once its modifiers apply.
type valueKind int

const (
	kindString valueKind = iota
	kindRegex
	kindCIDR
	kindCompare
	kindExists
	kindFieldRef
)

// modifierAliases maps alternative modifier names to their canonical form.
var modifierAliases = map[string]string{
	"wide":       "utf16le",
	"ignorecase": "i",
	"multiline":  "m",
	"dotall":     "s",
}

var compareModifiers = map[string]string{"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}

var datePartModifiers = map[string]bool{
	"minute": true, "hour": true, "day": true, "week": true, "month": true, "year": true,
}

var valueTransforms = map[string]bool{
	"windash": true, "base64": true, "base64offset": true, "utf16le": true, "utf16be": true, "utf16": true,
}

// fieldSpec is a detection field with its modifier chain interpreted.
type fieldSpec struct {
	field     string
	kind      valueKind
	compare   string // ">", ">=", "<" or "<=" for kindCompare
	datePart  string // minute, hour, day, week, month or year
	steps     []string
	openStart bool // contains or endswith applies
	openEnd   bool // contains or startswith applies
	cased     bool
	reFlagI   bool
	reFlagM   bool
	reFlagS   bool
	allOf     bool
	negated   bool
	expand    bool
}

// parseFieldSpec interprets "Field|mod1|mod2" with the modifier rules of the
// Sigma specification (appendix "Sigma Modifiers") and pySigma: re and cidr
// only apply to unmodified values, regex flags need re, encodings and
// windash need strings, numeric and date-part modifiers need plain values.
func parseFieldSpec(fieldWithMods string) (fieldSpec, []string) {
	parts := strings.Split(fieldWithMods, "|")
	spec := fieldSpec{field: parts[0]}
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	for index, raw := range parts[1:] {
		modifier := strings.ToLower(raw)
		if alias, ok := modifierAliases[modifier]; ok {
			modifier = alias
		}
		plain := spec.kind == kindString && len(spec.steps) == 0 && !spec.openStart && !spec.openEnd
		switch {
		case modifier == "re", modifier == "cidr":
			if index > 0 {
				fail("%s modifier only applies to an unmodified value", modifier)
			}
			spec.kind = kindRegex
			if modifier == "cidr" {
				spec.kind = kindCIDR
			}
		case modifier == "i", modifier == "m", modifier == "s":
			if spec.kind != kindRegex {
				fail("regex flag modifier %s requires re", raw)
				continue
			}
			spec.reFlagI = spec.reFlagI || modifier == "i"
			spec.reFlagM = spec.reFlagM || modifier == "m"
			spec.reFlagS = spec.reFlagS || modifier == "s"
		case compareModifiers[modifier] != "":
			// A comparison may also take a field reference: ProcessId|gt|fieldref.
			refCompare := spec.kind == kindFieldRef && !spec.openStart && !spec.openEnd
			if !plain && !refCompare {
				fail("%s modifier needs a plain numeric value", modifier)
			}
			if !refCompare {
				spec.kind = kindCompare
			}
			spec.compare = compareModifiers[modifier]
		case datePartModifiers[modifier]:
			if !plain || spec.datePart != "" {
				fail("%s modifier needs a plain date value", modifier)
			}
			spec.datePart = modifier
		case modifier == "exists":
			if index > 0 || len(parts) > 2 {
				fail("exists modifier cannot be combined with other modifiers")
			}
			spec.kind = kindExists
		case modifier == "fieldref":
			// A reference may follow a comparison (gt|fieldref) or a match
			// position (endswith|fieldref, the same as fieldref|endswith).
			positioned := spec.kind == kindString && spec.datePart == "" && onlyPositionSteps(spec.steps)
			if !positioned && (spec.kind != kindCompare || spec.datePart != "") {
				fail("fieldref modifier only applies to an unmodified value")
			}
			spec.kind = kindFieldRef
		case modifier == "contains", modifier == "startswith", modifier == "endswith":
			if (spec.kind != kindString && spec.kind != kindRegex && spec.kind != kindFieldRef) || spec.compare != "" {
				fail("%s modifier does not apply to this value type", modifier)
			}
			spec.openStart = spec.openStart || modifier != "startswith"
			spec.openEnd = spec.openEnd || modifier != "endswith"
			spec.steps = append(spec.steps, modifier)
		case valueTransforms[modifier]:
			if spec.kind != kindString || spec.datePart != "" {
				fail("%s modifier needs a string value", modifier)
			}
			spec.steps = append(spec.steps, modifier)
		case modifier == "cased":
			if spec.kind != kindString && spec.kind != kindFieldRef {
				fail("cased modifier needs a string value")
			}
			spec.cased = true
		case modifier == "all":
			spec.allOf = true
		case modifier == "neq":
			spec.negated = true
		case modifier == "expand":
			spec.expand = true
		default:
			fail("unsupported modifier %q", raw)
		}
	}
	return spec, errs
}

// fieldExpression builds the match logic of one field:value entry. Each value
// may expand into variants (windash, base64offset) that are ORed; the values
// themselves are ORed, or ANDed with the all modifier; neq negates the whole
// entry. It also returns one expression per value for "N of" thresholds over
// a single selection.
func fieldExpression(fieldWithMods string, raw any) (*Expression, []*Expression, []string) {
	spec, errs := parseFieldSpec(fieldWithMods)
	if len(errs) > 0 {
		return nil, nil, errs
	}
	if isNestedValue(raw) {
		if spec.field == "" {
			return nil, nil, []string{"keyword list contains a nested mapping or list"}
		}
		return nil, nil, []string{fmt.Sprintf("field %q: nested mapping or list is not a valid Sigma value", spec.field)}
	}
	values, isNull := fieldValues(raw)
	if isNull {
		leaf := Condition{Field: spec.field, Operator: "exists", Value: "false"}
		return negateIf(leafExpression(leaf), spec.negated), nil, nil
	}

	var units []*Expression
	var leaves []Condition
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		// A repeated value adds nothing to an OR or an AND.
		if key := formatScalar(value); seen[key] {
			continue
		} else {
			seen[key] = true
		}
		valueLeaves, valueErrs := spec.valueLeaves(value)
		errs = append(errs, valueErrs...)
		if len(valueLeaves) == 0 {
			continue
		}
		leaves = append(leaves, valueLeaves...)
		units = append(units, orExpression(valueLeaves))
	}
	if len(errs) > 0 || len(units) == 0 {
		return nil, nil, errs
	}

	expr := orExpression(leaves)
	if spec.allOf {
		expr = compactExpression(ExpressionAnd, units)
	}
	if spec.allOf || spec.negated {
		units = nil
	}
	return negateIf(expr, spec.negated), units, nil
}

// fieldValues lists the values of an entry. A null value, or an empty list,
// tests that the field does not exist.
func fieldValues(raw any) ([]any, bool) {
	list, ok := raw.([]any)
	if !ok {
		return []any{raw}, raw == nil
	}
	return list, len(list) == 0
}

// valueLeaves turns one detection value into the conditions it ORs. A null
// inside a value list matches an absent field, as in pySigma.
func (spec fieldSpec) valueLeaves(value any) ([]Condition, []string) {
	if value == nil {
		return []Condition{{Field: spec.field, Operator: "exists", Value: "false"}}, nil
	}
	base := Condition{Field: spec.field, CaseSensitive: spec.cased, RequiresExpansion: spec.expand, DatePart: spec.datePart}
	text := formatScalar(value)
	switch spec.kind {
	case kindRegex:
		pattern := text
		if spec.openStart && !spec.openEnd {
			pattern = "(?:" + pattern + ")$"
		} else if spec.openEnd && !spec.openStart {
			pattern = "^(?:" + pattern + ")"
		}
		base.Operator, base.Value = "matches", pattern
		base.CaseSensitive, base.Multiline, base.DotAll = !spec.reFlagI, spec.reFlagM, spec.reFlagS
		return []Condition{base}, nil
	case kindCIDR:
		if _, _, err := net.ParseCIDR(text); err != nil && net.ParseIP(text) == nil {
			return nil, []string{fmt.Sprintf("field %q: %q is not an IP network", spec.field, text)}
		}
		base.Operator, base.Value = "cidrmatch", text
		return []Condition{base}, nil
	case kindCompare:
		if !isNumber(value) {
			return nil, []string{fmt.Sprintf("field %q: %s comparison needs a number, got %q", spec.field, spec.compare, text)}
		}
		base.Operator, base.Value = spec.compare, text
		return []Condition{base}, nil
	case kindExists:
		exists, ok := parseBool(value)
		if !ok {
			return nil, []string{fmt.Sprintf("field %q: exists needs true or false, got %q", spec.field, text)}
		}
		return []Condition{{Field: spec.field, Operator: "exists", Value: strconv.FormatBool(exists)}}, nil
	case kindFieldRef:
		if text == "" {
			return nil, []string{fmt.Sprintf("field %q: fieldref needs a field name", spec.field)}
		}
		base.Operator, base.Value, base.ValueReference = positionOperator(spec.openStart, spec.openEnd), text, text
		if spec.compare != "" {
			base.Operator = spec.compare
		}
		return []Condition{base}, nil
	}
	if spec.datePart != "" {
		if !isNumber(value) {
			return nil, []string{fmt.Sprintf("field %q: %s needs a number, got %q", spec.field, spec.datePart, text)}
		}
		base.Operator, base.Value = "=", text
		return []Condition{base}, nil
	}

	variants := []sigmaString{literalString(text)}
	if _, isString := value.(string); isString {
		variants = []sigmaString{parseSigmaString(text)}
	}
	for _, step := range spec.steps {
		next, err := applyStringStep(step, variants)
		if err != "" {
			return nil, []string{fmt.Sprintf("field %q: %s", spec.field, err)}
		}
		variants = next
	}
	leaves := make([]Condition, 0, len(variants))
	for _, variant := range variants {
		if spec.field == "" {
			// Keywords match anywhere in the event.
			variant = variant.withWildcardPrefix().withWildcardSuffix()
		}
		leaf := base
		leaf.Operator, leaf.Value = stringMatch(variant)
		switch {
		case leaf.Operator == "exists":
			leaf.CaseSensitive = false
		case spec.field == "" && leaf.Operator == "contains":
			leaf.Operator = "keyword"
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

// applyStringStep applies one transformation or position modifier to every
// variant of a string value.
func applyStringStep(step string, variants []sigmaString) ([]sigmaString, string) {
	var out []sigmaString
	for _, variant := range variants {
		switch step {
		case "contains":
			out = append(out, variant.withWildcardPrefix().withWildcardSuffix())
			continue
		case "startswith":
			out = append(out, variant.withWildcardSuffix())
			continue
		case "endswith":
			out = append(out, variant.withWildcardPrefix())
			continue
		case "windash":
			out = append(out, windash(variant)...)
			continue
		}
		if variant.hasWildcards() {
			return nil, step + " encoding is not allowed on values with wildcards"
		}
		literal := variant.literal()
		switch step {
		case "utf16le":
			out = append(out, literalString(encodeUTF16LE(literal)))
		case "utf16be":
			out = append(out, literalString(encodeUTF16BE(literal)))
		case "utf16":
			out = append(out, literalString("\xff\xfe"+encodeUTF16LE(literal)))
		case "base64":
			out = append(out, literalString(base64.StdEncoding.EncodeToString([]byte(literal))))
		case "base64offset":
			for _, encoded := range base64OffsetVariants(literal) {
				out = append(out, literalString(encoded))
			}
		}
	}
	return out, ""
}

func onlyPositionSteps(steps []string) bool {
	for _, step := range steps {
		if step != "contains" && step != "startswith" && step != "endswith" {
			return false
		}
	}
	return true
}

func positionOperator(openStart, openEnd bool) string {
	switch {
	case openStart && openEnd:
		return "contains"
	case openStart:
		return "endswith"
	case openEnd:
		return "startswith"
	default:
		return "="
	}
}

// orExpression ORs leaves, folding values that share a field and match type
// into one condition with Alternatives.
func orExpression(leaves []Condition) *Expression {
	merged := make([]Condition, 0, len(leaves))
	index := make(map[string]int, len(leaves))
	for _, leaf := range leaves {
		key, ok := alternativeKey(leaf)
		if !ok {
			merged = append(merged, leaf)
			continue
		}
		at, seen := index[key]
		if !seen {
			index[key] = len(merged)
			merged = append(merged, leaf)
			continue
		}
		condition := &merged[at]
		if len(condition.Alternatives) == 0 {
			condition.Alternatives = []string{condition.Value}
		}
		if !containsString(condition.Alternatives, leaf.Value) {
			condition.Alternatives = append(condition.Alternatives, leaf.Value)
		}
	}
	children := make([]*Expression, 0, len(merged))
	for _, condition := range merged {
		children = append(children, leafExpression(condition))
	}
	return compactExpression(ExpressionOr, children)
}

// alternativeKey identifies conditions whose values can share one condition;
// comparisons, existence checks and field references stay separate.
func alternativeKey(c Condition) (string, bool) {
	switch c.Operator {
	case ">", ">=", "<", "<=", "exists":
		return "", false
	}
	if c.ValueReference != "" {
		return "", false
	}
	return fmt.Sprintf("%s\x00%s\x00%t\x00%t\x00%t\x00%t\x00%s", c.Field, c.Operator, c.CaseSensitive, c.Multiline, c.DotAll, c.RequiresExpansion, c.DatePart), true
}

func leafExpression(condition Condition) *Expression {
	return &Expression{Kind: ExpressionCondition, Condition: &condition}
}

func negateIf(expression *Expression, negate bool) *Expression {
	if !negate || expression == nil {
		return expression
	}
	return &Expression{Kind: ExpressionNot, Children: []*Expression{expression}}
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

// formatScalar renders a YAML scalar as Sigma matches it.
func formatScalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func isNumber(value any) bool {
	switch v := value.(type) {
	case int, int64, uint64, float64:
		return true
	case string:
		_, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return err == nil
	}
	return false
}

func parseBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes":
			return true, true
		case "false", "no":
			return false, true
		}
	}
	return false, false
}
