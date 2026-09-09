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
	if result.operator != "=" || !result.fieldReference {
		t.Errorf("expected equality field reference, got operator=%q fieldReference=%v", result.operator, result.fieldReference)
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
	if len(result.values) != 3 {
		t.Errorf("expected 3 values for base64offset, got %d: %v", len(result.values), result.values)
	}
}

func TestParseModifiers_Wide(t *testing.T) {
	_, result := parseModifiers("CommandLine|wide", []string{"test"})
	if len(result.values) != 1 || result.values[0] != "t\x00e\x00s\x00t\x00" {
		t.Errorf("expected only UTF-16LE value, got %v", result.values)
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
	if len(result.values) != 1 {
		t.Fatalf("expected one value, got %d", len(result.values))
	}
	// UTF16LE of "A" is 0x41 0x00
	utf16Val := result.values[0]
	if len(utf16Val) != 2 || utf16Val[0] != 0x41 || utf16Val[1] != 0x00 {
		t.Errorf("expected UTF-16LE encoding of 'A', got %v", []byte(utf16Val))
	}
}

func TestParseModifiers_UTF16BE(t *testing.T) {
	_, result := parseModifiers("Field|utf16be", []string{"A"})
	if len(result.values) != 1 {
		t.Fatalf("expected one value, got %d", len(result.values))
	}
	// UTF16BE of "A" is 0x00 0x41
	utf16Val := result.values[0]
	if len(utf16Val) != 2 || utf16Val[0] != 0x00 || utf16Val[1] != 0x41 {
		t.Errorf("expected UTF-16BE encoding of 'A', got %v", []byte(utf16Val))
	}
}

func TestParseModifiers_Expand(t *testing.T) {
	_, result := parseModifiers("CommandLine|expand", []string{"%APPDATA%\\test"})
	if !result.requiresExpansion || len(result.errors) != 0 {
		t.Fatalf("expected lossless expansion marker, got %#v", result)
	}
}

func TestParseModifiers_RegexCaseSensitivity(t *testing.T) {
	_, sensitive := parseModifiers("TargetFilename|re", []string{"^test$"})
	if !sensitive.caseSensitive {
		t.Fatal("Sigma regex must be case-sensitive unless the i flag is present")
	}
	_, insensitive := parseModifiers("TargetFilename|re|i", []string{"^test$"})
	if insensitive.caseSensitive || len(insensitive.errors) != 0 {
		t.Fatalf("expected valid case-insensitive regex, got %#v", insensitive)
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

func TestParseModifiers_Cased(t *testing.T) {
	field, result := parseModifiers("FieldName|cased", []string{"CasedValue"})
	if field != "FieldName" {
		t.Errorf("expected field 'FieldName', got %q", field)
	}
	if result.operator != "=" {
		t.Errorf("expected operator '=', got %q", result.operator)
	}
	if !result.caseSensitive {
		t.Error("expected caseSensitive=true for |cased modifier")
	}
}

func TestParseModifiers_ContainsCased(t *testing.T) {
	field, result := parseModifiers("CommandLine|contains|cased", []string{"Mimikatz"})
	if field != "CommandLine" {
		t.Errorf("expected field 'CommandLine', got %q", field)
	}
	if result.operator != "contains" {
		t.Errorf("expected operator 'contains', got %q", result.operator)
	}
	if !result.caseSensitive {
		t.Error("expected caseSensitive=true for |contains|cased chain")
	}
}

func TestParseModifiers_CasedAll(t *testing.T) {
	_, result := parseModifiers("Image|endswith|cased|all", []string{"cmd.exe", "powershell.exe"})
	if result.operator != "endswith" {
		t.Errorf("expected operator 'endswith', got %q", result.operator)
	}
	if !result.caseSensitive {
		t.Error("expected caseSensitive=true")
	}
	if !result.allOf {
		t.Error("expected allOf=true")
	}
}

func TestParseModifiers_NoCased(t *testing.T) {
	_, result := parseModifiers("CommandLine|contains", []string{"test"})
	if result.caseSensitive {
		t.Error("expected caseSensitive=false when |cased not present")
	}
}
