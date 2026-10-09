package sigma

import (
	"strconv"
	"strings"
)

func buildExpression(node condNode, items map[string]*detectionItem) *Expression {
	switch typedNode := node.(type) {
	case condNodeRef:
		item, ok := items[typedNode.name]
		if !ok {
			return nil
		}
		return expressionFromConditions(item.conditions)
	case condNodeAnd:
		return expressionGroup(ExpressionAnd, typedNode.children, items)
	case condNodeOr:
		return expressionGroup(ExpressionOr, typedNode.children, items)
	case condNodeNot:
		child := buildExpression(typedNode.child, items)
		if child == nil {
			return nil
		}
		return &Expression{Kind: ExpressionNot, Children: []*Expression{child}}
	case condNodeQuantifier:
		names := matchDetectionItems(typedNode.pattern, items)
		children := make([]*Expression, 0, len(names))
		for _, name := range names {
			child := expressionFromConditions(items[name].conditions)
			if child != nil {
				children = append(children, child)
			}
		}
		if len(children) == 0 {
			return nil
		}
		if typedNode.quantifier == "all" {
			return compactExpression(ExpressionAnd, children)
		}
		threshold, err := strconv.Atoi(typedNode.quantifier)
		if err != nil || threshold <= 1 {
			return compactExpression(ExpressionOr, children)
		}
		if len(children) == 1 && !isWildcardPattern(typedNode.pattern) {
			// One named selection can never satisfy "N of" for N > 1, so count
			// its alternatives instead: "2 of flags" means at least two of the
			// values listed under flags match.
			children = expressionAlternatives(children[0])
		}
		return &Expression{Kind: ExpressionThreshold, Children: children, Threshold: threshold}
	default:
		return nil
	}
}

func validateExpression(expression *Expression) []string {
	if expression == nil {
		return nil
	}
	var errors []string
	if expression.Kind == ExpressionThreshold && expression.Threshold > len(expression.Children) {
		errors = append(errors, "threshold requires more matching selections than the condition pattern provides")
	}
	for _, child := range expression.Children {
		errors = append(errors, validateExpression(child)...)
	}
	return errors
}

func expressionGroup(kind ExpressionKind, nodes []condNode, items map[string]*detectionItem) *Expression {
	children := make([]*Expression, 0, len(nodes))
	for _, node := range nodes {
		child := buildExpression(node, items)
		if child != nil {
			children = append(children, child)
		}
	}
	return compactExpression(kind, children)
}

func expressionFromConditions(conditions []Condition) *Expression {
	if len(conditions) == 0 {
		return nil
	}

	orChildren := make([]*Expression, 0, 2)
	andChildren := make([]*Expression, 0, len(conditions))
	flushAnd := func() {
		orChildren = append(orChildren, compactExpression(ExpressionAnd, andChildren))
		andChildren = nil
	}

	for index := range conditions {
		condition := conditions[index]
		logicalOperator := condition.LogicalOp
		condition.LogicalOp = ""
		leafCondition := condition
		leaf := &Expression{Kind: ExpressionCondition, Condition: &leafCondition}
		if index > 0 && logicalOperator == "OR" {
			flushAnd()
		}
		andChildren = append(andChildren, leaf)
	}
	flushAnd()
	return compactExpression(ExpressionOr, orChildren)
}

func isWildcardPattern(pattern string) bool {
	return pattern == "them" || strings.Contains(pattern, "*")
}

// expressionAlternatives splits an expression into its distinct OR'd
// alternatives, including the values of a multi-valued condition.
func expressionAlternatives(expression *Expression) []*Expression {
	switch {
	case expression.Kind == ExpressionOr:
		return expression.Children
	case expression.Kind == ExpressionCondition && len(expression.Condition.Alternatives) > 1:
		seen := make(map[string]bool, len(expression.Condition.Alternatives))
		alternatives := make([]*Expression, 0, len(expression.Condition.Alternatives))
		for _, value := range expression.Condition.Alternatives {
			if seen[value] {
				continue
			}
			seen[value] = true
			condition := *expression.Condition
			condition.Value = value
			condition.Alternatives = nil
			alternatives = append(alternatives, &Expression{Kind: ExpressionCondition, Condition: &condition})
		}
		return alternatives
	default:
		return []*Expression{expression}
	}
}

func compactExpression(kind ExpressionKind, children []*Expression) *Expression {
	if len(children) == 0 {
		return nil
	}
	if len(children) == 1 {
		return children[0]
	}
	return &Expression{Kind: kind, Children: children}
}
