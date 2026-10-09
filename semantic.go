package sigma

import "sort"

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
	semantic := semanticFromExtraction(ExtractConditions(ruleYAML))
	enrichSemanticQueryFromYAML(semantic, ruleYAML)
	return semantic
}

// semanticFromExtraction normalizes parser extraction output into the
// parser-owned semantic model.
func semanticFromExtraction(result *ParseResult) *SemanticQuery {
	if result == nil {
		return nil
	}
	return &SemanticQuery{
		Conditions:     cloneSemanticConditions(result.Conditions),
		Expression:     semanticExpressionFromParseExpression(result.Expression),
		GroupByFields:  cloneSemanticStrings(result.GroupByFields),
		ComputedFields: cloneSemanticStringMap(result.ComputedFields),
		Commands:       cloneSemanticStrings(result.Commands),
		Joins:          semanticJoinsFromParseJoins(result.Joins),
		Errors:         cloneSemanticStrings(result.Errors),
		LogSource:      cloneSemanticLogSource(result.LogSource),
		Level:          result.Level,
		Status:         result.Status,
		Title:          result.Title,
		Tags:           cloneSemanticStrings(result.Tags),
		Timeframe:      result.Timeframe,
	}
}

func enrichSemanticQueryFromYAML(semantic *SemanticQuery, ruleYAML string) {
	defer func() {
		_ = recover()
	}()
	rule, err := parseSigmaRule(ruleYAML)
	if err != nil {
		return
	}
	items, _ := resolveDetectionItems(rule.Detection)
	semantic.Detections = semanticDetectionsFromItems(items)
	condition, _ := rule.Detection.get("condition")
	node, aggregations, multipleConditions, _ := parseDetectionCondition(condition)
	semantic.ConditionExpression = semanticConditionExpressionFromCondNode(node)
	semantic.Aggregations = cloneSemanticStrings(aggregations)
	semantic.MultipleConditionStrings = multipleConditions
}

func semanticExpressionFromParseExpression(expression *Expression) *SemanticExpression {
	if expression == nil {
		return nil
	}
	semantic := &SemanticExpression{
		Kind:      expression.Kind,
		Threshold: expression.Threshold,
	}
	if expression.Condition != nil {
		condition := cloneSemanticCondition(*expression.Condition)
		semantic.Condition = &condition
	}
	for _, child := range expression.Children {
		if converted := semanticExpressionFromParseExpression(child); converted != nil {
			semantic.Children = append(semantic.Children, converted)
		}
	}
	return semantic
}

func semanticConditionExpressionFromCondNode(node condNode) *SemanticConditionExpression {
	switch n := node.(type) {
	case nil:
		return nil
	case condNodeRef:
		return &SemanticConditionExpression{Operator: "ref", Selector: n.name}
	case condNodeAnd:
		return semanticConditionExpressionGroup("and", n.children)
	case condNodeOr:
		return semanticConditionExpressionGroup("or", n.children)
	case condNodeNot:
		child := semanticConditionExpressionFromCondNode(n.child)
		if child == nil {
			return nil
		}
		return &SemanticConditionExpression{Operator: "not", Children: []*SemanticConditionExpression{child}}
	case condNodeQuantifier:
		return &SemanticConditionExpression{
			Operator:   "quantifier",
			Quantifier: n.quantifier,
			Pattern:    n.pattern,
		}
	default:
		return nil
	}
}

func semanticConditionExpressionGroup(operator string, children []condNode) *SemanticConditionExpression {
	semantic := &SemanticConditionExpression{Operator: operator}
	for _, child := range children {
		if converted := semanticConditionExpressionFromCondNode(child); converted != nil {
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

func semanticDetectionsFromItems(items map[string]*detectionItem) []SemanticDetection {
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
		item := items[name]
		if item == nil {
			continue
		}
		out = append(out, SemanticDetection{
			Name:       item.name,
			Conditions: cloneSemanticConditions(item.conditions),
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

func cloneSemanticConditions(conditions []Condition) []Condition {
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

func cloneSemanticStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneSemanticStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
