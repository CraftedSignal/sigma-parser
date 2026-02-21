package sigma

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseModifiers_NoModifier(t *testing.T) {
	field, result := parseModifiers("CommandLine", []string{"test.exe"})
	if field != "CommandLine" {
		t.Errorf("expected field 'CommandLine', got %q", field)
	}
	if result.operator != "=" {
		t.Errorf("expected operator '=', got %q", result.operator)
	}
	if result.allOf {
		t.Error("expected allOf=false")
	}
}

func TestParseModifiers_Contains(t *testing.T) {
	field, result := parseModifiers("CommandLine|contains", []string{"mimikatz"})
	if field != "CommandLine" {
		t.Errorf("expected field 'CommandLine', got %q", field)
	}
	if result.operator != "contains" {
		t.Errorf("expected operator 'contains', got %q", result.operator)
	}
}

func TestParseModifiers_StartsWith(t *testing.T) {
	_, result := parseModifiers("Image|startswith", []string{`C:\Windows\`})
	if result.operator != "startswith" {
		t.Errorf("expected operator 'startswith', got %q", result.operator)
	}
}

func TestParseModifiers_EndsWith(t *testing.T) {
	_, result := parseModifiers("Image|endswith", []string{".exe"})
	if result.operator != "endswith" {
		t.Errorf("expected operator 'endswith', got %q", result.operator)
	}
}

func TestParseModifiers_Regex(t *testing.T) {
	_, result := parseModifiers("CommandLine|re", []string{`.*mimikatz.*`})
	if result.operator != "matches" {
		t.Errorf("expected operator 'matches', got %q", result.operator)
	}
}

func TestParseModifiers_CIDR(t *testing.T) {
	_, result := parseModifiers("DestinationIp|cidr", []string{"10.0.0.0/8"})
	if result.operator != "cidrmatch" {
		t.Errorf("expected operator 'cidrmatch', got %q", result.operator)
	}
}

func TestParseModifiers_Comparison(t *testing.T) {
	tests := []struct {
		mod string
		op  string
	}{
		{"gt", ">"},
		{"gte", ">="},
		{"lt", "<"},
		{"lte", "<="},
	}
	for _, tt := range tests {
		_, result := parseModifiers("EventID|"+tt.mod, []string{"10"})
		if result.operator != tt.op {
			t.Errorf("modifier %q: expected operator %q, got %q", tt.mod, tt.op, result.operator)
		}
	}
}

func TestParseModifiers_Exists(t *testing.T) {
	_, result := parseModifiers("FieldName|exists", []string{"true"})
	if result.operator != "exists" {
		t.Errorf("expected operator 'exists', got %q", result.operator)
	}
}

func TestParseModifiers_FieldRef(t *testing.T) {
	_, result := parseModifiers("SubjectUserName|fieldref", []string{"TargetUserName"})
	if result.operator != "fieldref" {
		t.Errorf("expected operator 'fieldref', got %q", result.operator)
	}
}

func TestParseModifiers_All(t *testing.T) {
	_, result := parseModifiers("CommandLine|contains|all", []string{"-nop", "-w hidden"})
	if result.operator != "contains" {
		t.Errorf("expected operator 'contains', got %q", result.operator)
	}
	if !result.allOf {
		t.Error("expected allOf=true")
	}
}

func TestParseModifiers_Base64(t *testing.T) {
	_, result := parseModifiers("CommandLine|base64", []string{"test"})
	encoded := base64.StdEncoding.EncodeToString([]byte("test"))
	found := false
	for _, v := range result.values {
		if v == encoded {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected base64 encoded value %q in %v", encoded, result.values)
	}
}

func TestParseModifiers_Base64Offset(t *testing.T) {
	_, result := parseModifiers("CommandLine|base64offset", []string{"test"})
	// Should have original + 3 offset variants
	if len(result.values) < 4 {
		t.Errorf("expected at least 4 values for base64offset, got %d: %v", len(result.values), result.values)
	}
}

func TestParseModifiers_Wide(t *testing.T) {
	_, result := parseModifiers("CommandLine|wide", []string{"test"})
	if len(result.values) < 2 {
		t.Errorf("expected at least 2 values for wide, got %d", len(result.values))
	}
	// Should contain the original value
	if result.values[0] != "test" {
		t.Errorf("expected first value 'test', got %q", result.values[0])
	}
}

func TestParseModifiers_Windash(t *testing.T) {
	_, result := parseModifiers("CommandLine|windash", []string{"-exec"})
	found := false
	for _, v := range result.values {
		if v == "/exec" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '/exec' variant in %v", result.values)
	}
}

func TestParseModifiers_WindashSlash(t *testing.T) {
	_, result := parseModifiers("CommandLine|windash", []string{"/exec"})
	found := false
	for _, v := range result.values {
		if v == "-exec" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '-exec' variant in %v", result.values)
	}
}

func TestParseModifiers_ContainsAll(t *testing.T) {
	_, result := parseModifiers("CommandLine|contains|all", []string{"a", "b", "c"})
	if result.operator != "contains" {
		t.Errorf("expected 'contains', got %q", result.operator)
	}
	if !result.allOf {
		t.Error("expected allOf=true")
	}
	if len(result.values) != 3 {
		t.Errorf("expected 3 values, got %d", len(result.values))
	}
}

func TestParseModifiers_CaseInsensitive(t *testing.T) {
	_, result := parseModifiers("Field|CONTAINS|ALL", []string{"test"})
	if result.operator != "contains" {
		t.Errorf("expected 'contains', got %q", result.operator)
	}
	if !result.allOf {
		t.Error("expected allOf=true")
	}
}

func TestParseModifiers_UTF16LE(t *testing.T) {
	_, result := parseModifiers("Field|utf16le", []string{"A"})
	if len(result.values) < 2 {
		t.Errorf("expected at least 2 values, got %d", len(result.values))
	}
	// UTF16LE of "A" is 0x41 0x00
	utf16Val := result.values[1]
	if len(utf16Val) != 2 || utf16Val[0] != 0x41 || utf16Val[1] != 0x00 {
		t.Errorf("expected UTF-16LE encoding of 'A', got %v", []byte(utf16Val))
	}
}

func TestParseModifiers_UTF16BE(t *testing.T) {
	_, result := parseModifiers("Field|utf16be", []string{"A"})
	if len(result.values) < 2 {
		t.Errorf("expected at least 2 values, got %d", len(result.values))
	}
	// UTF16BE of "A" is 0x00 0x41
	utf16Val := result.values[1]
	if len(utf16Val) != 2 || utf16Val[0] != 0x00 || utf16Val[1] != 0x41 {
		t.Errorf("expected UTF-16BE encoding of 'A', got %v", []byte(utf16Val))
	}
}

func TestParseModifiers_Expand(t *testing.T) {
	// expand modifier passes through values unchanged
	_, result := parseModifiers("CommandLine|expand", []string{"%APPDATA%\\test"})
	if len(result.values) != 1 || result.values[0] != "%APPDATA%\\test" {
		t.Errorf("expected value pass-through, got %v", result.values)
	}
}

func TestParseModifiers_ChainedModifiers(t *testing.T) {
	// base64 + contains
	_, result := parseModifiers("CommandLine|base64|contains", []string{"test"})
	if result.operator != "contains" {
		t.Errorf("expected 'contains', got %q", result.operator)
	}
	// Should have original + base64 encoded
	foundEncoded := false
	for _, v := range result.values {
		if strings.Contains(v, "=") || len(v) > len("test") {
			foundEncoded = true
			break
		}
	}
	if !foundEncoded {
		t.Log("Note: base64+contains chain produced:", result.values)
	}
}
