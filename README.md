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

if len(result.Errors) > 0 {
    // Reject or report the invalid rule before consuming its conditions.
}
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

`ParseResult.Expression` and `SemanticQuery.Expression` carry the resolved
Boolean groups, including OR between maps in a list and whole-group NOT.
`Conditions` and `SemanticDetection.Conditions` are legacy flat projections;
their `LogicalOp` fields cannot reconstruct arbitrary grouping. Consumers that
need the full detection logic should use the root expression.

An authored `Field: null` sets `Condition.NullTest` in both expressions and
flat conditions. This flag is authoritative: it denotes a symbolic Sigma null
test for a target to lower. For compatibility, its `Operator` remains `exists`
and `Value` remains `false`; explicit `Field|exists: false` has the same legacy
fields with `NullTest == false`. The parser does not choose target-specific
null matching behavior. An empty string remains an ordinary equality value.

Modifier input is checked before scalar conversion. `exists` takes a YAML
Boolean and requires a field; regex, CIDR, field references, `expand`, and
string transformations take authored strings. Generic `contains`,
`startswith`, `endswith`, and `cased` still accept numeric scalars. `all`
requires an authored nonempty list, including a singleton list; duplicate
removal does not change that rule. Field references reject unescaped wildcard
patterns and resolve escaped literal `*`, `?`, and backslashes. Empty
selections, empty field-value lists, and null elements in field-value lists
produce diagnostics in `Errors`. Invalid ordinary entries can leave other
valid entries in a partial result, so callers should check `Errors`.

## Resource bounds and cancellation

`ExtractConditions`, `ExtractFile`, and `AnalyzeQuery` reject complete inputs
larger than `MaxInputSize` (1 MiB) before YAML decoding. The corresponding
`ExtractConditionsContext`, `ExtractFileContext`, and `AnalyzeQueryContext`
functions also accept caller cancellation. Parsing runs synchronously with a
cooperative five-second deadline; it does not leave a background parse worker.

Each operation shares these limits across all documents, YAML alias
occurrences, values, modifiers, selector references, and semantic enrichment:

| Resource | Limit |
|----------|-------|
| YAML documents | 256 |
| YAML/expression/correlation traversal depth | 64 |
| Materialized/expanded nodes and container slots | 100,000 |
| Cumulative decoded scalar bytes | 8 MiB |
| Materialized modifier variants | 10,000 |
| Materialized condition copies | 10,000 |
| Generated/copied output text | 16 MiB |
| Explicit traversal/processing work units | 4,000,000 |

These are cumulative work limits, including intermediate representations and
copies, rather than limits on the final deduplicated result. For example,
`AnalyzeQuery` charges extraction and semantic enrichment to the same budget.
Ordinary repeated aliases are supported; aliases that cycle or exceed the
cumulative bounds are rejected. Windash Cartesian products are checked before
allocation. Correlation references are also checked as expanded output, even
when their internal representation shares a referenced rule.

A resource or cancellation failure returns an error and no partial conditions,
expression, detections, or file rules. Detection semantics are never truncated
to fit a limit. Larger collections and highly expansive valid rules may need
to be split into smaller inputs.

Cancellation is cooperative, not a hard real-time or per-call heap guarantee.
The handwritten traversal and expansion stages check the context and work
budget. `yaml.v3` has no context-aware decoder: the reader and boundaries around
`Decode` check cancellation, but cannot interrupt decoder work on already
buffered bytes. The input cap bounds what reaches that decoder. The node and scalar-byte
counters cover traversal and materialization after decoding; the decoder
builds its initial YAML node tree under the input cap.

## API Reference

### Types

```go
type Condition struct {
    Field        string   // Field name (empty for keywords)
    Operator     string   // "=", "contains", "startswith", "endswith", "matches", "cidrmatch", etc.
    Value        string   // The condition value
    NullTest     bool     // Authoritative symbolic Sigma null test
    Negated      bool     // True if condition is negated (NOT)
    LogicalOp    string   // "AND" or "OR" connecting to previous condition
    Alternatives []string // Multiple values grouped by OR on same field
}

type ParseResult struct {
    Conditions     []Condition
    Expression     *Expression     // Complete resolved Boolean logic
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
