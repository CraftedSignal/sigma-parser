package sigma

import (
	"testing"
)

func TestConditionParser_SimpleRef(t *testing.T) {
	node, agg, errs := parseConditionExpr("selection")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if agg != "" {
		t.Errorf("expected no aggregation, got %q", agg)
	}
	ref, ok := node.(condNodeRef)
	if !ok {
		t.Fatalf("expected condNodeRef, got %T", node)
	}
	if ref.name != "selection" {
		t.Errorf("expected name 'selection', got %q", ref.name)
	}
}

func TestConditionParser_And(t *testing.T) {
	node, _, errs := parseConditionExpr("selection and filter")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	and, ok := node.(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd, got %T", node)
	}
	if len(and.children) != 2 {
		t.Errorf("expected 2 children, got %d", len(and.children))
	}
}

func TestConditionParser_Or(t *testing.T) {
	node, _, errs := parseConditionExpr("selection1 or selection2")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	or, ok := node.(condNodeOr)
	if !ok {
		t.Fatalf("expected condNodeOr, got %T", node)
	}
	if len(or.children) != 2 {
		t.Errorf("expected 2 children, got %d", len(or.children))
	}
}

func TestConditionParser_Not(t *testing.T) {
	node, _, errs := parseConditionExpr("not selection")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	not, ok := node.(condNodeNot)
	if !ok {
		t.Fatalf("expected condNodeNot, got %T", node)
	}
	ref, ok := not.child.(condNodeRef)
	if !ok {
		t.Fatalf("expected condNodeRef child, got %T", not.child)
	}
	if ref.name != "selection" {
		t.Errorf("expected name 'selection', got %q", ref.name)
	}
}

func TestConditionParser_SelectionAndNotFilter(t *testing.T) {
	node, _, errs := parseConditionExpr("selection and not filter")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	and, ok := node.(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd, got %T", node)
	}
	if len(and.children) != 2 {
		t.Errorf("expected 2 children, got %d", len(and.children))
	}
	_, ok = and.children[1].(condNodeNot)
	if !ok {
		t.Fatalf("expected condNodeNot as second child, got %T", and.children[1])
	}
}

func TestConditionParser_Parens(t *testing.T) {
	node, _, errs := parseConditionExpr("(selection1 or selection2) and filter")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	and, ok := node.(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd, got %T", node)
	}
	_, ok = and.children[0].(condNodeOr)
	if !ok {
		t.Fatalf("expected condNodeOr as first child, got %T", and.children[0])
	}
}

func TestConditionParser_AllOfThem(t *testing.T) {
	node, _, errs := parseConditionExpr("all of them")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	q, ok := node.(condNodeQuantifier)
	if !ok {
		t.Fatalf("expected condNodeQuantifier, got %T", node)
	}
	if q.quantifier != "all" || q.pattern != "them" {
		t.Errorf("expected all of them, got %q of %q", q.quantifier, q.pattern)
	}
}

func TestConditionParser_1OfSelection(t *testing.T) {
	node, _, errs := parseConditionExpr("1 of selection*")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	q, ok := node.(condNodeQuantifier)
	if !ok {
		t.Fatalf("expected condNodeQuantifier, got %T", node)
	}
	if q.quantifier != "1" || q.pattern != "selection*" {
		t.Errorf("expected 1 of selection*, got %q of %q", q.quantifier, q.pattern)
	}
}

func TestConditionParser_Aggregation(t *testing.T) {
	_, agg, errs := parseConditionExpr("selection | count() > 5")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if agg == "" {
		t.Fatal("expected aggregation expression")
	}
	if agg != "count() > 5" {
		t.Errorf("expected 'count() > 5', got %q", agg)
	}
}

func TestConditionParser_ComplexNested(t *testing.T) {
	node, _, errs := parseConditionExpr("(selection1 or selection2) and not (filter1 or filter2)")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	and, ok := node.(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd, got %T", node)
	}
	if len(and.children) != 2 {
		t.Errorf("expected 2 children, got %d", len(and.children))
	}
	not, ok := and.children[1].(condNodeNot)
	if !ok {
		t.Fatalf("expected condNodeNot, got %T", and.children[1])
	}
	_, ok = not.child.(condNodeOr)
	if !ok {
		t.Fatalf("expected condNodeOr inside not, got %T", not.child)
	}
}

func TestConditionParser_MultipleOr(t *testing.T) {
	node, _, _ := parseConditionExpr("a or b or c or d")
	or, ok := node.(condNodeOr)
	if !ok {
		t.Fatalf("expected condNodeOr, got %T", node)
	}
	if len(or.children) != 4 {
		t.Errorf("expected 4 children, got %d", len(or.children))
	}
}

func TestConditionParser_Precedence(t *testing.T) {
	// AND has higher precedence than OR
	node, _, _ := parseConditionExpr("a or b and c")
	or, ok := node.(condNodeOr)
	if !ok {
		t.Fatalf("expected condNodeOr at top, got %T", node)
	}
	if len(or.children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(or.children))
	}
	_, ok = or.children[1].(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd as second child, got %T", or.children[1])
	}
}

func TestConditionParser_CaseInsensitive(t *testing.T) {
	node, _, errs := parseConditionExpr("selection AND NOT filter")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	and, ok := node.(condNodeAnd)
	if !ok {
		t.Fatalf("expected condNodeAnd, got %T", node)
	}
	_, ok = and.children[1].(condNodeNot)
	if !ok {
		t.Fatalf("expected condNodeNot, got %T", and.children[1])
	}
}

func TestConditionParser_AllOfStar(t *testing.T) {
	node, _, errs := parseConditionExpr("all of *")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	q, ok := node.(condNodeQuantifier)
	if !ok {
		t.Fatalf("expected condNodeQuantifier, got %T", node)
	}
	if q.quantifier != "all" || q.pattern != "*" {
		t.Errorf("expected 'all of *', got %q of %q", q.quantifier, q.pattern)
	}
}
