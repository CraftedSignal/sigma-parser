# Sigma Parser

[![Go Reference](https://pkg.go.dev/badge/github.com/craftedsignal/sigma-parser.svg)](https://pkg.go.dev/github.com/craftedsignal/sigma-parser)
[![Go Report Card](https://goreportcard.com/badge/github.com/craftedsignal/sigma-parser)](https://goreportcard.com/report/github.com/craftedsignal/sigma-parser)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

A production-ready Go parser for [Sigma](https://sigmahq.io/) detection rules. Extracts conditions, fields, and detection logic from YAML-based Sigma rules. Uses `yaml.v3` and a recursive descent condition parser (no ANTLR needed).

## Features

- **Full Detection Resolution**: Maps, lists, keyword lists, null values, wildcards
- **Every Sigma Modifier** (modifiers appendix v2.1.0): contains, startswith, endswith, all, exists, cased, neq, windash, re with i/m/s, base64, base64offset, utf16le/wide, utf16be, utf16, gt/gte/lt/lte, minute/hour/day/week/month/year, cidr, expand, fieldref
- **Condition Parser**: Recursive descent for AND/OR/NOT, parentheses, quantifiers (`all of them`, `1 of selection_*`)
- **Full Aggregation Support**: count/sum/min/max/avg with group-by and comparison operators, near with timeframe
- **3,100+ Rule Corpus**: Tested against the entire SigmaHQ rule repository
- **Fuzz Tested**: No panics on arbitrary input

## Installation

```bash
go get github.com/craftedsignal/sigma-parser
```

## Usage

### Basic Condition Extraction

```go
package main

import (
    "fmt"
    sigma "github.com/craftedsignal/sigma-parser"
)

func main() {
    rule := `
title: Mimikatz Usage
status: stable
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003.001
`

    result := sigma.ExtractConditions(rule)

    fmt.Printf("Title: %s (Level: %s)\n", result.Title, result.Level)
    fmt.Printf("Found %d conditions:\n", len(result.Conditions))
    for _, cond := range result.Conditions {
        fmt.Printf("  Field: %s, Operator: %s, Value: %s\n",
            cond.Field, cond.Operator, cond.Value)
        if len(cond.Alternatives) > 0 {
            fmt.Printf("    Alternatives: %v\n", cond.Alternatives)
        }
    }
}
```

### Output

```
Title: Mimikatz Usage (Level: critical)
Found 2 conditions:
  Field: Image, Operator: endswith, Value: \mimikatz.exe
  Field: CommandLine, Operator: contains, Value: sekurlsa::
    Alternatives: [sekurlsa:: kerberos::]
```

### Aggregation Rules

```go
rule := `
title: Brute Force
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by SourceIP > 10
`

result := sigma.ExtractConditions(rule)
fmt.Println(result.GroupByFields) // [SourceIP]
fmt.Println(result.Commands)      // [count]
```

## Supported Sigma Features

| Feature | Status |
|---------|--------|
| Field:value maps | Supported |
| List of maps (OR) | Supported |
| Keyword lists | Supported |
| Null values | Supported |
| Wildcards (*, ?) and \ escapes | Supported; values reach Condition as literals or, for inner wildcards, regexes |
| All modifiers, v2.1.0 | Supported, with pySigma's chaining rules |
| Condition expressions | Supported |
| Quantifiers (1 of, any of, all of) | Supported; `*` anywhere in patterns, `_` identifiers excluded |
| Threshold quantifiers (N of) | Extension; `N of selection` on one named selection counts its values |
| Aggregation (count/sum/min/max/avg) | Supported |
| Near aggregation | Supported; `ExtractFile` reads it as a temporal correlation |
| Timeframe | Supported |
| LogSource metadata | Supported |
| Tags (MITRE ATT&CK) | Supported |
| Multiple condition strings | Supported |
| Rule collections (action global/reset/repeat) | Supported; `ExtractFile` returns each rule |
| Correlation rules, v2.1.0 (all types, aliases, chaining) | Supported; `ExtractFile` resolves references by name or id within the file |
| Warnings | `Warnings` flags exact command-line values that can only be a parameter, such as `CommandLine: -NoProfile` |

## API Reference

### Types

```go
type Condition struct {
    Field        string   // Field name (empty for keywords)
    Operator     string   // "=", "contains", "startswith", "endswith", "matches", "cidrmatch", etc.
    Value        string   // The condition value
    Negated      bool     // True if condition is negated (NOT)
    LogicalOp    string   // "AND" or "OR" connecting to previous condition
    Alternatives []string // Multiple values grouped by OR on same field
}

type ParseResult struct {
    Conditions     []Condition
    GroupByFields  []string          // From aggregation group-by
    ComputedFields map[string]string // Always empty for Sigma
    Commands       []string          // Aggregation functions detected
    Errors         []string          // Parse errors: the rule is not valid Sigma
    Warnings       []string          // Valid Sigma that likely does not match as meant
    LogSource      *LogSource        // category/product/service
    Level          string            // informational, low, medium, high, critical
    Status         string            // experimental, test, stable
    Title          string
    Tags           []string          // MITRE ATT&CK tags
}
```

### Functions

```go
// ExtractConditions parses a rule; a collection is read as the OR of its rules.
func ExtractConditions(yamlContent string) *ParseResult

// ExtractFile parses a file into its standalone rules and its outermost
// correlations, with the rules and correlations they reference resolved.
func ExtractFile(yamlContent string) *File
```

## Testing

```bash
# Run all tests (including 3,100+ SigmaHQ corpus)
make test

# Run fuzz tests
make fuzz

# Run benchmarks
make benchmark
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `make test`
2. Code is formatted: `make fmt`
3. Linter passes: `make lint`

## License

AGPL-3.0 - see [LICENSE](LICENSE) for details.

## Related Projects

- [spl-parser](https://github.com/craftedsignal/spl-parser) - Splunk Processing Language parser
- [kql-parser](https://github.com/craftedsignal/kql-parser) - Kusto Query Language parser
- [leql-parser](https://github.com/craftedsignal/leql-parser) - Rapid7 LEQL parser
- [CraftedSignal](https://craftedsignal.com) - Detection engineering platform
