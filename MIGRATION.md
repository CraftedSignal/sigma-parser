# Modifier and null preservation

Rules that previously accepted textual `exists` values, scalar `|all`, null
members of field-value lists, empty selections or field-value lists, and
non-string inputs to string-only modifiers now report `Errors`. Check errors
before using a parsed rule. A nonempty authored singleton list remains valid
for `|all`, regardless of duplicate removal. Generic numeric values remain
valid for `contains`, `startswith`, `endswith`, and `cased`.

Authored `Field: null` now sets `Condition.NullTest == true` in the flat and
resolved models, including semantic output. `Field|exists: false` has
`NullTest == false`. Both retain `Operator == "exists"` and `Value == "false"`
for existing readers. Consumers lowering Sigma to a target should check
`NullTest` first and decide how that target represents a Sigma null test.
`Field|neq: null` and `condition: not sel` retain whole-entry negation.

For Boolean groups, use `ParseResult.Expression` or
`SemanticQuery.Expression`. The legacy `Conditions` projections cannot encode
arbitrary parentheses, though they retain each leaf's modifier metadata.
