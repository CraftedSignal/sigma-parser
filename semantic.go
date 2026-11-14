package sigma

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// SemanticQuery is the parser-owned semantic view of a Sigma rule. It keeps
// Sigma-specific selector logic next to the parser instead of rediscovering it
// in platform adapters.
type SemanticQuery struct {
	Conditions               []Condition                  `json:"conditions,omitempty"`
	Expression               *SemanticExpression          `json:"expression,omitempty"`
	ConditionExpression      *SemanticConditionExpression `json:"condition_expression,omitempty"`
	Detections               []SemanticDetection          `json:"detections,omitempty"`
	GroupByFields            []string                     `json:"group_by_fields,omitempty"`
	ComputedFields           map[string]string            `json:"computed_fields,omitempty"`
	Commands                 []string                     `json:"commands,omitempty"`
	Joins                    []SemanticJoin               `json:"joins,omitempty"`
	Errors                   []string                     `json:"errors,omitempty"`
	LogSource                *LogSource                   `json:"logsource,omitempty"`
	Level                    string                       `json:"level,omitempty"`
	Status                   string                       `json:"status,omitempty"`
	Title                    string                       `json:"title,omitempty"`
	Tags                     []string                     `json:"tags,omitempty"`
	Timeframe                string                       `json:"timeframe,omitempty"`
	Aggregations             []string                     `json:"aggregations,omitempty"`
	MultipleConditionStrings bool                         `json:"multiple_condition_strings,omitempty"`
}

// SemanticExpression is the resolved condition-bearing Sigma expression tree.
type SemanticExpression struct {
	Kind      ExpressionKind        `json:"kind"`
	Condition *Condition            `json:"condition,omitempty"`
	Children  []*SemanticExpression `json:"children,omitempty"`
	Threshold int                   `json:"threshold,omitempty"`
}

// SemanticConditionExpression preserves the Sigma detection.condition selector
// expression before selector references are expanded into field conditions.
type SemanticConditionExpression struct {
	Operator   string                         `json:"operator"`
	Selector   string                         `json:"selector,omitempty"`
	Quantifier string                         `json:"quantifier,omitempty"`
	Pattern    string                         `json:"pattern,omitempty"`
	Children   []*SemanticConditionExpression `json:"children,omitempty"`
}

// SemanticDetection is a named Sigma detection item with resolved modifiers.
type SemanticDetection struct {
	Name       string      `json:"name"`
	Conditions []Condition `json:"conditions,omitempty"`
	Keyword    bool        `json:"keyword,omitempty"`
}

// SemanticJoin is present for API parity with other parser packages. Sigma has
// no joins, but callers can consume joins uniformly.
type SemanticJoin struct {
	Type          string            `json:"type"`
	JoinFields    []string          `json:"join_fields,omitempty"`
	Options       map[string]string `json:"options,omitempty"`
	Subsearch     string            `json:"subsearch,omitempty"`
	PipeStage     int               `json:"pipe_stage"`
	IsAppend      bool              `json:"is_append,omitempty"`
	ExposedFields []string          `json:"exposed_fields,omitempty"`
}

// AnalyzeQuery parses a Sigma rule and returns the parser-owned semantic model.
func AnalyzeQuery(ruleYAML string) *SemanticQuery {
	return AnalyzeQueryContext(context.Background(), ruleYAML)
}

// AnalyzeQueryContext shares one budget across extraction and enrichment.
func AnalyzeQueryContext(ctx context.Context, ruleYAML string) *SemanticQuery {
	return guarded(ctx, ruleYAML, func(b *parseBudget) *SemanticQuery {
		return analyzeQuery(ruleYAML, b)
	}, func(message string) *SemanticQuery {
		return &SemanticQuery{Errors: []string{message}}
	})
}

func analyzeQuery(ruleYAML string, b *parseBudget) *SemanticQuery {
	semantic := semanticFromExtraction(extractConditionsInternal(ruleYAML, b), b)
	enrichSemanticQueryFromYAML(semantic, ruleYAML, b)
	return semantic
}

// semanticFromExtraction normalizes parser extraction output into the
// parser-owned semantic model.
func semanticFromExtraction(result *ParseResult, budgets ...*parseBudget) *SemanticQuery {
	b := budgetFrom(budgets)
	if result == nil {
		return nil
	}
	return &SemanticQuery{
		Conditions:     cloneSemanticConditions(result.Conditions, b),
		Expression:     semanticExpressionFromParseExpression(result.Expression, b),
		GroupByFields:  cloneSemanticStrings(result.GroupByFields, b),
		ComputedFields: cloneSemanticStringMap(result.ComputedFields, b),
		Commands:       cloneSemanticStrings(result.Commands, b),
		Joins:          semanticJoinsFromParseJoins(result.Joins),
		Errors:         cloneSemanticStrings(result.Errors, b),
		LogSource:      cloneSemanticLogSource(result.LogSource),
		Level:          result.Level,
		Status:         result.Status,
		Title:          result.Title,
		Tags:           cloneSemanticStrings(result.Tags, b),
		Timeframe:      result.Timeframe,
	}
}

func enrichSemanticQueryFromYAML(semantic *SemanticQuery, ruleYAML string, budgets ...*parseBudget) {
	b := budgetFrom(budgets)
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(parseAbort); ok {
				panic(recovered)
			}
		}
	}()
	rules, err := parseSigmaRules(ruleYAML, b)
	if err != nil {
		return
	}
	b.node(len(rules))
	var conditions []*SemanticConditionExpression
	for i, rule := range rules {
		b.step(1)
		items, _ := resolveDetectionItems(rule.Detection, b)
		detections := semanticDetectionsFromItems(items, b)
		condition, _ := rule.Detection.get("condition")
		node, aggregations, multipleConditions, _ := parseDetectionCondition(condition, b)
		expression := semanticConditionExpressionFromCondNode(node, b)
		if len(rules) > 1 {
			prefix := fmt.Sprintf("rule%d_", i+1)
			for j := range detections {
				detections[j].Name = scopedDetectionName(detections[j].Name, prefix, b)
			}
			scopeSemanticCondition(expression, prefix, b)
		}
		b.node(len(detections))
		semantic.Detections = append(semantic.Detections, detections...)
		if expression != nil {
			conditions = append(conditions, expression)
		}
		b.stringsOutput(aggregations)
		semantic.Aggregations = append(semantic.Aggregations, aggregations...)
		semantic.MultipleConditionStrings = semantic.MultipleConditionStrings || multipleConditions
	}
	switch len(conditions) {
	case 1:
		semantic.ConditionExpression = conditions[0]
	default:
		if len(conditions) > 1 {
			b.node(1)
			semantic.ConditionExpression = &SemanticConditionExpression{Operator: "or", Children: conditions}
		}
	}
}

func semanticExpressionFromParseExpression(expression *Expression, budgets ...*parseBudget) *SemanticExpression {
	b := budgetFrom(budgets)
	b.step(1)
	b.node(1)
	defer b.enter()()
	if expression == nil {
		return nil
	}
	semantic := &SemanticExpression{
		Kind:      expression.Kind,
		Threshold: expression.Threshold,
	}
	if expression.Condition != nil {
		b.copyCondition(*expression.Condition)
		condition := cloneSemanticCondition(*expression.Condition)
		semantic.Condition = &condition
	}
	for _, child := range expression.Children {
		if converted := semanticExpressionFromParseExpression(child, b); converted != nil {
			semantic.Children = append(semantic.Children, converted)
		}
	}
	return semantic
}

func semanticConditionExpressionFromCondNode(node condNode, budgets ...*parseBudget) *SemanticConditionExpression {
	b := budgetFrom(budgets)
	b.step(1)
	b.node(1)
	defer b.enter()()
	switch n := node.(type) {
	case nil:
		return nil
	case condNodeRef:
		b.output(len(n.name))
		return &SemanticConditionExpression{Operator: "ref", Selector: n.name}
	case condNodeAnd:
		return semanticConditionExpressionGroup("and", n.children, b)
	case condNodeOr:
		return semanticConditionExpressionGroup("or", n.children, b)
	case condNodeNot:
		child := semanticConditionExpressionFromCondNode(n.child, b)
		if child == nil {
			return nil
		}
		return &SemanticConditionExpression{Operator: "not", Children: []*SemanticConditionExpression{child}}
	case condNodeQuantifier:
		b.output(len(n.quantifier) + len(n.pattern))
		return &SemanticConditionExpression{
			Operator:   "quantifier",
			Quantifier: n.quantifier,
			Pattern:    n.pattern,
		}
	default:
		return nil
	}
}

func semanticConditionExpressionGroup(operator string, children []condNode, budgets ...*parseBudget) *SemanticConditionExpression {
	b := budgetFrom(budgets)
	b.node(len(children))
	semantic := &SemanticConditionExpression{Operator: operator}
	for _, child := range children {
		if converted := semanticConditionExpressionFromCondNode(child, b); converted != nil {
			semantic.Children = append(semantic.Children, converted)
		}
	}
	if len(semantic.Children) == 0 {
		return nil
	}
	if len(semantic.Children) == 1 {
		return semantic.Children[0]
	}
	return semantic
}

func semanticDetectionsFromItems(items map[string]*detectionItem, budgets ...*parseBudget) []SemanticDetection {
	b := budgetFrom(budgets)
	b.node(2 * len(items))
	if len(items) == 0 {
		return nil
	}
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]SemanticDetection, 0, len(names))
	for _, name := range names {
		b.step(1)
		item := items[name]
		if item == nil {
			continue
		}
		out = append(out, SemanticDetection{
			Name:       item.name,
			Conditions: cloneSemanticConditions(item.conditions, b),
			Keyword:    item.isKeyword,
		})
	}
	return out
}

func semanticJoinsFromParseJoins(joins []JoinInfo) []SemanticJoin {
	if len(joins) == 0 {
		return nil
	}
	out := make([]SemanticJoin, 0, len(joins))
	for _, join := range joins {
		out = append(out, SemanticJoin{
			Type:          join.Type,
			JoinFields:    cloneSemanticStrings(join.JoinFields),
			Options:       cloneSemanticStringMap(join.Options),
			Subsearch:     join.Subsearch,
			PipeStage:     join.PipeStage,
			IsAppend:      join.IsAppend,
			ExposedFields: cloneSemanticStrings(join.ExposedFields),
		})
	}
	return out
}

func cloneSemanticConditions(conditions []Condition, budgets ...*parseBudget) []Condition {
	b := budgetFrom(budgets)
	b.copyConditions(conditions)
	if len(conditions) == 0 {
		return nil
	}
	out := make([]Condition, len(conditions))
	for i, condition := range conditions {
		out[i] = cloneSemanticCondition(condition)
	}
	return out
}

func cloneSemanticCondition(condition Condition) Condition {
	condition.Alternatives = cloneSemanticStrings(condition.Alternatives)
	return condition
}

func cloneSemanticLogSource(logSource *LogSource) *LogSource {
	if logSource == nil {
		return nil
	}
	return &LogSource{
		Category: logSource.Category,
		Product:  logSource.Product,
		Service:  logSource.Service,
	}
}

func cloneSemanticStrings(values []string, budgets ...*parseBudget) []string {
	b := budgetFrom(budgets)
	b.stringsOutput(values)
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneSemanticStringMap(values map[string]string, budgets ...*parseBudget) map[string]string {
	b := budgetFrom(budgets)
	b.node(len(values))
	for key, value := range values {
		b.step(1)
		b.output(len(key) + len(value))
	}
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

// scopedDetectionName preserves private selections while separating documents.
func scopedDetectionName(name, prefix string, budgets ...*parseBudget) string {
	b := budgetFrom(budgets)
	b.step(len(name) + 1)
	b.output(len(name) + len(prefix) + 1)
	if strings.HasPrefix(name, "_") {
		return "_" + prefix + strings.TrimPrefix(name, "_")
	}
	return prefix + name
}

func scopeSemanticCondition(expression *SemanticConditionExpression, prefix string, budgets ...*parseBudget) {
	b := budgetFrom(budgets)
	b.step(1)
	defer b.enter()()
	if expression == nil {
		return
	}
	if expression.Operator == "ref" {
		expression.Selector = scopedDetectionName(expression.Selector, prefix, b)
	}
	if expression.Operator == "quantifier" {
		pattern := expression.Pattern
		if pattern == "them" {
			pattern = "*"
		}
		expression.Pattern = scopedDetectionName(pattern, prefix, b)
	}
	for _, child := range expression.Children {
		scopeSemanticCondition(child, prefix, b)
	}
}
