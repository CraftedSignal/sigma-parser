package sigma

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxInputSize bounds a complete Sigma rule or collection before parsing.
const MaxInputSize = 1 << 20

// Counters measure the whole operation's materialized work, including
// intermediate copies, rather than just final deduplicated conditions.
type parseLimits struct {
	inputBytes, depth, documents, nodes, decodedBytes int
	variants, conditions, outputBytes, work           int
}

func defaultParseLimits() parseLimits {
	return parseLimits{inputBytes: MaxInputSize, depth: 64, documents: 256,
		nodes: 100_000, decodedBytes: 8 << 20, variants: 10_000,
		conditions: 10_000, outputBytes: 16 << 20, work: 4_000_000}
}

type resourceLimitError struct {
	resource string
	limit    int
}

func (e resourceLimitError) Error() string {
	return fmt.Sprintf("parser resource limit exceeded: %s (limit %d)", e.resource, e.limit)
}

type parseAbort struct{ err error }

type parseBudget struct {
	ctx                                     context.Context
	limits                                  parseLimits
	depth, documents, nodes, decodedBytes   int
	variants, conditions, outputBytes, work int
	active                                  map[*yaml.Node]bool
}

func newParseBudget(ctx context.Context, limits parseLimits) *parseBudget {
	return &parseBudget{ctx: ctx, limits: limits, active: make(map[*yaml.Node]bool)}
}

func budgetFrom(budgets []*parseBudget) *parseBudget {
	if len(budgets) > 0 && budgets[0] != nil {
		return budgets[0]
	}
	return newParseBudget(context.Background(), defaultParseLimits())
}

func (b *parseBudget) check() {
	if err := b.ctx.Err(); err != nil {
		panic(parseAbort{err})
	}
}

func (b *parseBudget) fail(resource string, limit int) {
	panic(parseAbort{resourceLimitError{resource: resource, limit: limit}})
}

func (b *parseBudget) take(counter *int, n, limit int, resource string) {
	b.check()
	if n < 0 || *counter > limit || n > limit-*counter {
		b.fail(resource, limit)
	}
	*counter += n
}

func (b *parseBudget) input(text string) {
	b.check()
	if len(text) > b.limits.inputBytes {
		b.fail("input bytes", b.limits.inputBytes)
	}
}

func (b *parseBudget) step(n int) { b.take(&b.work, n, b.limits.work, "work") }
func (b *parseBudget) node(n int) { b.take(&b.nodes, n, b.limits.nodes, "nodes") }
func (b *parseBudget) decoded(n int) {
	b.take(&b.decodedBytes, n, b.limits.decodedBytes, "decoded bytes")
}
func (b *parseBudget) output(n int)    { b.take(&b.outputBytes, n, b.limits.outputBytes, "output bytes") }
func (b *parseBudget) variant(n int)   { b.take(&b.variants, n, b.limits.variants, "variants") }
func (b *parseBudget) condition(n int) { b.take(&b.conditions, n, b.limits.conditions, "conditions") }

// Check division before multiplying, before using a Cartesian allocation size.
func (b *parseBudget) product(a, c, limit int, resource string) int {
	b.check()
	if a < 0 || c < 0 || (c != 0 && a > limit/c) {
		b.fail(resource, limit)
	}
	return a * c
}

func (b *parseBudget) enter() func() {
	b.take(&b.depth, 1, b.limits.depth, "depth")
	return func() { b.depth-- }
}

func (b *parseBudget) copyCondition(c Condition) {
	b.condition(1)
	b.node(1 + len(c.Alternatives))
	b.output(len(c.Field) + len(c.Operator) + len(c.Value) + len(c.ValueReference) + len(c.SourceField))
	for _, value := range c.Alternatives {
		b.output(len(value))
	}
}

func (b *parseBudget) copyConditions(conditions []Condition) {
	for _, condition := range conditions {
		b.step(1)
		b.copyCondition(condition)
	}
}

// Reserve formatted metadata before fmt allocates, including non-scalar
// metadata from YAML. Repeated collection globals consume the same budget.
func (b *parseBudget) formatValue(value any) string {
	b.reserveValue(value)
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprintf("%v", value)
}

func (b *parseBudget) reserveValue(value any) {
	b.step(1)
	defer b.enter()()
	switch v := value.(type) {
	case string:
		b.output(len(v))
	case orderedMap:
		b.output(2)
		for _, entry := range v {
			b.output(len(entry.key) + 4)
			b.reserveValue(entry.value)
		}
	case []any:
		b.output(2)
		for _, item := range v {
			b.output(1)
			b.reserveValue(item)
		}
	default:
		b.output(32)
	}
}

// Reserve a conservative upper bound before quoting parser diagnostics.
func (b *parseBudget) formatError(format string, args ...any) string {
	b.output(len(format) + 64)
	for _, arg := range args {
		// %q can expand one input byte into six output bytes.
		for i := 0; i < 6; i++ {
			b.reserveValue(arg)
		}
	}
	return fmt.Sprintf(format, args...)
}

func (b *parseBudget) stringsOutput(values []string) {
	b.node(len(values))
	for _, value := range values {
		b.step(1)
		b.output(len(value))
	}
}

// Correlation references form a graph, but consumers serialize a tree. Count
// every referenced occurrence, including shared subgraphs, before returning
// it so a compact file cannot defer unbounded expansion to its consumer.
func (b *parseBudget) checkFileOutput(file *File) {
	for _, rule := range file.Rules {
		b.ruleOutput(rule)
	}
	for _, correlation := range file.Correlations {
		b.correlationOutput(correlation)
	}
}

func (b *parseBudget) ruleOutput(rule *ParseResult) {
	if rule == nil {
		return
	}
	b.step(1)
	b.output(len(rule.Title) + len(rule.ID) + len(rule.Name) + len(rule.Level) + len(rule.Status) + len(rule.Timeframe))
	b.stringsOutput(rule.Tags)
	b.stringsOutput(rule.GroupByFields)
	b.stringsOutput(rule.Commands)
	b.stringsOutput(rule.Errors)
	b.stringsOutput(rule.Warnings)
	if rule.LogSource != nil {
		b.output(len(rule.LogSource.Category) + len(rule.LogSource.Product) + len(rule.LogSource.Service))
	}
	b.copyConditions(rule.Conditions)
	b.expressionOutput(rule.Expression)
}

func (b *parseBudget) expressionOutput(expression *Expression) {
	if expression == nil {
		return
	}
	b.step(1)
	b.node(1)
	defer b.enter()()
	if expression.Condition != nil {
		b.copyCondition(*expression.Condition)
	}
	for _, child := range expression.Children {
		b.expressionOutput(child)
	}
}

func (b *parseBudget) correlationOutput(correlation *Correlation) {
	if correlation == nil {
		return
	}
	b.step(1)
	b.node(1)
	defer b.enter()()
	b.output(len(correlation.Title) + len(correlation.ID) + len(correlation.Name) + len(correlation.Status) + len(correlation.Level) + len(correlation.Field) + len(correlation.Timespan))
	b.stringsOutput(correlation.Tags)
	b.node(len(correlation.Conditions))
	for _, condition := range correlation.Conditions {
		b.step(1)
		b.output(len(condition.Operator) + 32)
	}
	for _, field := range correlation.GroupBy {
		b.output(len(field))
		b.step(1)
	}
	for alias, fields := range correlation.Aliases {
		b.output(len(alias))
		for name, field := range fields {
			b.step(1)
			b.output(len(name) + len(field))
		}
	}
	for _, ref := range correlation.Rules {
		b.step(1)
		b.output(len(ref.Name))
		b.ruleOutput(ref.Rule)
		b.correlationOutput(ref.Correlation)
	}
}

// yaml.v3 has no context-aware parse API. A checked reader plus checks around
// Decode are cooperative; they cannot preempt its work on buffered bytes.
type budgetReader struct {
	reader *strings.Reader
	budget *parseBudget
}

func (r budgetReader) Read(p []byte) (int, error) {
	r.budget.check()
	n, err := r.reader.Read(p)
	r.budget.step(n)
	return n, err
}

func abortMessage(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "parsing timed out: " + err.Error()
	}
	return err.Error()
}
