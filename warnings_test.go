package sigma

import (
	"strings"
	"testing"
)

// An exact command-line value that can only be a parameter never matches a
// real command line, so the parser warns about it; whole command lines,
// Windows' "-" for an empty command line, login shells and modified values
// stay quiet.
func TestCommandLineWarnings(t *testing.T) {
	for name, tc := range map[string]struct {
		detection string
		warn      []string // values the warning must name; none for no warning
	}{
		"dash parameter":       {`sel: {CommandLine: -NoProfile}`, []string{`"-NoProfile"`}},
		"parameter in a list":  {`sel: {CommandLine: [whoami, ' -dhl']}`, []string{`" -dhl"`}},
		"windows switch":       {`sel: {ParentCommandLine: /c}`, []string{`"/c"`}},
		"ECS field":            {`sel: {process.command_line: '-enc AAAA'}`, []string{`"-enc AAAA"`}},
		"all of exact values":  {`sel: {CommandLine|all: [/tn, WindowsHelper]}`, []string{`"/tn"`}},
		"filter":               {"sel: {Image|endswith: '\\powershell.exe'}\nfilter: {CommandLine: -NoProfile}\ncondition: sel and not filter", []string{`"-NoProfile"`}},
		"whole command line":   {`sel: {CommandLine: 'cmd.exe /c'}`, nil},
		"whole command line 2": {`sel: {ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'}`, nil},
		"unix path":            {`sel: {CommandLine: '/usr/bin/python3 -c x'}`, nil},
		"empty command line":   {`sel: {CommandLine: '-'}`, nil},
		"login shell":          {`sel: {CommandLine: '-bash'}`, nil},
		"contains":             {`sel: {CommandLine|contains: -NoProfile}`, nil},
		"wildcard":             {`sel: {CommandLine: '* -NoProfile *'}`, nil},
		"not a command line":   {`sel: {Image: -foo}`, nil},
		"regex":                {`sel: {CommandLine|re: '-enc'}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			detection := tc.detection
			if !strings.Contains(detection, "condition:") {
				detection += "\ncondition: sel"
			}
			rule := "title: t\nlogsource: {product: windows}\ndetection:\n  " + strings.ReplaceAll(detection, "\n", "\n  ") + "\n"
			result := ExtractConditions(rule)
			if len(result.Errors) > 0 {
				t.Fatalf("errors: %q", result.Errors)
			}
			if len(tc.warn) == 0 {
				if len(result.Warnings) > 0 {
					t.Fatalf("expected no warnings, got %q", result.Warnings)
				}
				return
			}
			if len(result.Warnings) != 1 {
				t.Fatalf("expected one warning, got %q", result.Warnings)
			}
			for _, value := range tc.warn {
				if !strings.Contains(result.Warnings[0], value) {
					t.Fatalf("warning %q does not name %s", result.Warnings[0], value)
				}
			}
			if file := ExtractFile(rule); strings.Join(file.Warnings, "\n") != strings.Join(result.Warnings, "\n") {
				t.Fatalf("file warnings %q differ from the rule's %q", file.Warnings, result.Warnings)
			}
		})
	}
}

// In a file of several rules, a warning names its rule.
func TestFileWarningsNameTheRule(t *testing.T) {
	file := ExtractFile(`title: c
correlation:
    type: event_count
    rules: [dump]
    timespan: 5m
    condition: {gte: 2}
---
name: dump
logsource: {product: linux}
detection:
    sel:
        CommandLine: -dump
    condition: sel
---
name: other
logsource: {product: linux}
detection:
    sel:
        CommandLine: -i
    condition: sel
`)
	warnings := strings.Join(file.Warnings, "\n")
	if len(file.Errors) > 0 || len(file.Warnings) != 2 ||
		!strings.Contains(warnings, `rule "dump": CommandLine: "-dump"`) || !strings.Contains(warnings, `rule "other": CommandLine: "-i"`) {
		t.Fatalf("expected a named warning per rule, got %q (errors %q)", file.Warnings, file.Errors)
	}
}
