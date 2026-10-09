package sigma

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// loginShellRe matches the command line of a login shell, which is the
// shell's name after a dash, such as -bash.
var loginShellRe = regexp.MustCompile(`^-(?:[a-z]*sh|fish)$`)

// commandLineWarnings reports exact command-line values that can only be a
// parameter, such as CommandLine: -NoProfile. A value without a modifier
// must equal the whole field, so such a value never matches a real command
// line; the rule almost certainly meant CommandLine|contains.
func commandLineWarnings(expression *Expression) []string {
	var warnings []string
	seen := map[string]bool{}
	var walk func(*Expression)
	walk = func(e *Expression) {
		if e == nil {
			return
		}
		if c := e.Condition; c != nil && c.Operator == "=" && c.DatePart == "" && c.ValueReference == "" &&
			!c.RequiresExpansion && isCommandLineField(c.Field) {
			values := c.Alternatives
			if len(values) == 0 {
				values = []string{c.Value}
			}
			var parameters []string
			for _, value := range values {
				if isCommandLineParameter(value) {
					parameters = append(parameters, strconv.Quote(value))
				}
			}
			warning := ""
			switch len(parameters) {
			case 0:
			case 1:
				warning = fmt.Sprintf("%s: %s only matches a command line that is exactly %s; use %s|contains to match it as a parameter",
					c.Field, parameters[0], parameters[0], c.Field)
			default:
				warning = fmt.Sprintf("%s: %s only match command lines that are exactly one of these values; use %s|contains to match them as parameters",
					c.Field, strings.Join(parameters, ", "), c.Field)
			}
			if warning != "" && !seen[warning] {
				seen[warning] = true
				warnings = append(warnings, warning)
			}
		}
		for _, child := range e.Children {
			walk(child)
		}
	}
	walk(expression)
	return warnings
}

// isCommandLineField reports whether a field holds a process command line,
// such as CommandLine, ParentCommandLine or process.command_line.
func isCommandLineField(field string) bool {
	normalized := strings.NewReplacer("_", "", ".", "", "-", "").Replace(strings.ToLower(field))
	return strings.HasSuffix(normalized, "commandline") || strings.HasSuffix(normalized, "cmdline")
}

// isCommandLineParameter reports whether a value can only be a parameter,
// never a whole command line: it starts with a dash (-NoProfile) or is a
// Windows switch (/c, /tn WindowsHelper). Windows logs "-" for an empty
// command line, a login shell's command line is -bash, and a value starting
// with a path (/usr/bin/python3 -c ...) can be a whole command line.
func isCommandLineParameter(value string) bool {
	value = strings.TrimSpace(value)
	switch {
	case value == "-" || loginShellRe.MatchString(value):
		return false
	case strings.HasPrefix(value, "-"):
		return true
	case strings.HasPrefix(value, "/"):
		first, _, _ := strings.Cut(value, " ")
		return !strings.Contains(first[1:], "/")
	}
	return false
}
