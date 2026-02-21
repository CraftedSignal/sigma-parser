package sigma

import (
	"testing"
)

func TestAggregation_Count(t *testing.T) {
	agg, errs := parseAggregation("count() > 5", "")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if agg.function != "count" {
		t.Errorf("expected 'count', got %q", agg.function)
	}
	if agg.field != "" {
		t.Errorf("expected empty field, got %q", agg.field)
	}
	if agg.comparison != ">" || agg.threshold != "5" {
		t.Errorf("expected '> 5', got '%s %s'", agg.comparison, agg.threshold)
	}
}

func TestAggregation_CountField(t *testing.T) {
	agg, errs := parseAggregation("count(TargetUserName) > 10", "")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if agg.function != "count" || agg.field != "TargetUserName" {
		t.Errorf("expected count(TargetUserName), got %s(%s)", agg.function, agg.field)
	}
	if agg.comparison != ">" || agg.threshold != "10" {
		t.Errorf("expected '> 10', got '%s %s'", agg.comparison, agg.threshold)
	}
}

func TestAggregation_SumWithGroupBy(t *testing.T) {
	agg, errs := parseAggregation("sum(bytes) by src_ip >= 1000", "")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if agg.function != "sum" || agg.field != "bytes" {
		t.Errorf("expected sum(bytes), got %s(%s)", agg.function, agg.field)
	}
	if len(agg.groupBy) != 1 || agg.groupBy[0] != "src_ip" {
		t.Errorf("expected groupBy [src_ip], got %v", agg.groupBy)
	}
	if agg.comparison != ">=" || agg.threshold != "1000" {
		t.Errorf("expected '>= 1000', got '%s %s'", agg.comparison, agg.threshold)
	}
}

func TestAggregation_MultipleGroupBy(t *testing.T) {
	agg, errs := parseAggregation("count() by src_ip, dst_ip > 100", "")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(agg.groupBy) != 2 {
		t.Fatalf("expected 2 groupBy fields, got %d: %v", len(agg.groupBy), agg.groupBy)
	}
	if agg.groupBy[0] != "src_ip" || agg.groupBy[1] != "dst_ip" {
		t.Errorf("expected [src_ip, dst_ip], got %v", agg.groupBy)
	}
}

func TestAggregation_AllFunctions(t *testing.T) {
	funcs := []string{"count", "sum", "min", "max", "avg"}
	for _, fn := range funcs {
		agg, errs := parseAggregation(fn+"(field) > 0", "")
		if len(errs) > 0 {
			t.Errorf("function %s: unexpected errors: %v", fn, errs)
			continue
		}
		if agg.function != fn {
			t.Errorf("expected function %q, got %q", fn, agg.function)
		}
	}
}

func TestAggregation_AllComparisons(t *testing.T) {
	tests := []struct {
		expr string
		comp string
	}{
		{"count() > 5", ">"},
		{"count() >= 5", ">="},
		{"count() < 5", "<"},
		{"count() <= 5", "<="},
		{"count() = 5", "="},
	}
	for _, tt := range tests {
		agg, errs := parseAggregation(tt.expr, "")
		if len(errs) > 0 {
			t.Errorf("%s: unexpected errors: %v", tt.expr, errs)
			continue
		}
		if agg.comparison != tt.comp {
			t.Errorf("%s: expected comparison %q, got %q", tt.expr, tt.comp, agg.comparison)
		}
	}
}

func TestAggregation_Near(t *testing.T) {
	agg, errs := parseAggregation("near selection1 and selection2", "5m")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !agg.isNear {
		t.Error("expected isNear=true")
	}
	if len(agg.nearItems) != 2 {
		t.Fatalf("expected 2 near items, got %d: %v", len(agg.nearItems), agg.nearItems)
	}
	if agg.nearItems[0] != "selection1" || agg.nearItems[1] != "selection2" {
		t.Errorf("expected [selection1, selection2], got %v", agg.nearItems)
	}
}

func TestAggregation_ToConditions(t *testing.T) {
	agg := &aggregation{
		function:   "count",
		groupBy:    []string{"src_ip"},
		comparison: ">",
		threshold:  "5",
	}
	conds, groupBy, commands := agg.toConditions()
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}
	if conds[0].Field != "count()" {
		t.Errorf("expected field 'count()', got %q", conds[0].Field)
	}
	if conds[0].Operator != ">" || conds[0].Value != "5" {
		t.Errorf("expected '> 5', got '%s %s'", conds[0].Operator, conds[0].Value)
	}
	if len(groupBy) != 1 || groupBy[0] != "src_ip" {
		t.Errorf("expected groupBy [src_ip], got %v", groupBy)
	}
	if len(commands) != 1 || commands[0] != "count" {
		t.Errorf("expected commands [count], got %v", commands)
	}
}

func TestAggregation_NearToConditions(t *testing.T) {
	agg := &aggregation{
		isNear:    true,
		function:  "near",
		nearItems: []string{"s1", "s2"},
	}
	conds, _, commands := agg.toConditions()
	if len(conds) != 0 {
		t.Errorf("expected 0 conditions for near, got %d", len(conds))
	}
	if len(commands) != 1 || commands[0] != "near" {
		t.Errorf("expected commands [near], got %v", commands)
	}
}

func TestAggregation_Empty(t *testing.T) {
	agg, errs := parseAggregation("", "")
	if agg != nil {
		t.Errorf("expected nil aggregation, got %+v", agg)
	}
	if len(errs) > 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestParseTimeframe(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"5s", 5},
		{"5m", 300},
		{"1h", 3600},
		{"2d", 172800},
		{"", 0},
		{"30", 30},
	}
	for _, tt := range tests {
		got := parseTimeframe(tt.input)
		if got != tt.expected {
			t.Errorf("parseTimeframe(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestAggregation_UnknownFunction(t *testing.T) {
	_, errs := parseAggregation("unknown() > 5", "")
	if len(errs) == 0 {
		t.Error("expected error for unknown function")
	}
}
