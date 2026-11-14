package sigma

import (
	"strconv"
	"strings"
)

func buildExpression(node condNode, items map[string]*detectionItem, budgets ...*parseBudget) *Expression {
	b := budgetFrom(budgets)
	b.step(1)
	b.node(1)
	defer b.enter()()
	switch typedNode := node.(type) {
	case condNodeRef:
		item, ok := items[typedNode.name]
		if !ok {
			return nil
		}
		return cloneExpression(item.expr, b)
	case condNodeAnd:
		return expressionGroup(ExpressionAnd, typedNode.children, items, b)
	case condNodeOr:
		return expressionGroup(ExpressionOr, typedNode.children, items, b)
	case condNodeNot:
		child := buildExpression(typedNode.child, items, b)
		if child == nil {
			return nil
		}
		return &Expression{Kind: ExpressionNot, Children: []*Expression{child}}
	case condNodeQuantifier:
		names := matchDetectionItems(typedNode.pattern, items, b)
		b.node(len(names))
		children := make([]*Expression, 0, len(names))
		for _, name := range names {
			if child := cloneExpression(items[name].expr, b); child != nil {
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
		if len(names) == 1 && !isWildcardPattern(typedNode.pattern) && len(items[names[0]].units) > 1 {
			// One named selection can never satisfy "N of" for N > 1, so count
			// its values instead: "2 of flags" means at least two of the
			// values listed under flags match.
			children = children[:0]
			for _, unit := range items[names[0]].units {
				children = append(children, cloneExpression(unit, b))
			}
		}
		return &Expression{Kind: ExpressionThreshold, Children: children, Threshold: threshold}
	default:
		return nil
	}
}

func validateExpression(expression *Expression, budgets ...*parseBudget) []string {
	b := budgetFrom(budgets)
	b.step(1)
	defer b.enter()()
	if expression == nil {
		return nil
	}
	var errors []string
	if expression.Kind == ExpressionThreshold && expression.Threshold > len(expression.Children) {
		errors = append(errors, "threshold requires more matching selections than the condition pattern provides")
	}
	for _, child := range expression.Children {
		errors = append(errors, validateExpression(child, b)...)
	}
	return errors
}

func expressionGroup(kind ExpressionKind, nodes []condNode, items map[string]*detectionItem, budgets ...*parseBudget) *Expression {
	b := budgetFrom(budgets)
	b.node(len(nodes))
	children := make([]*Expression, 0, len(nodes))
	for _, node := range nodes {
		child := buildExpression(node, items, b)
		if child != nil {
			children = append(children, child)
		}
	}
	return compactExpression(kind, children)
}

func isWildcardPattern(pattern string) bool {
	return pattern == "them" || strings.Contains(pattern, "*")
}

func cloneExpression(expression *Expression, budgets ...*parseBudget) *Expression {
	b := budgetFrom(budgets)
	b.step(1)
	b.node(1)
	defer b.enter()()
	if expression == nil {
		return nil
	}
	clone := &Expression{Kind: expression.Kind, Threshold: expression.Threshold}
	if expression.Condition != nil {
		b.copyCondition(*expression.Condition)
		condition := *expression.Condition
		condition.Alternatives = append([]string(nil), condition.Alternatives...)
		clone.Condition = &condition
	}
	for _, child := range expression.Children {
		clone.Children = append(clone.Children, cloneExpression(child, b))
	}
	return clone
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
