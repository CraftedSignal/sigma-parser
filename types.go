package sigma

// Condition represents a single field condition extracted from a Sigma rule.
//
// String values follow Sigma semantics: for "=", "contains", "startswith",
// "endswith" and "keyword" the Value is a literal with escapes resolved, and
// a value whose wildcards (`*`, `?`) cannot be expressed by those operators
// becomes a "matches" regular expression.
type Condition struct {
	Field             string   // Field name (empty for keyword conditions)
	Operator          string   // "=", "contains", "startswith", "endswith", "matches", "cidrmatch", ">", ">=", "<", "<=", "exists", "keyword"
	Value             string   // The condition value
	ValueReference    string   // Referenced field name for |fieldref (Operator gives the match position)
	Negated           bool     // True if condition is negated (NOT)
	CaseSensitive     bool     // True for |cased strings and for regexes without |i
	Multiline         bool     // Regex |m: ^ and $ match at line breaks
	DotAll            bool     // Regex |s: . also matches line breaks
	DatePart          string   // minute, hour, day, week, month or year: compare that part of a timestamp field
	RequiresExpansion bool     // True if |expand placeholders require a processing pipeline
	PipeStage         int      // Always 0 for Sigma (no pipeline stages)
	LogicalOp         string   // "AND" or "OR" connecting to previous condition
	Alternatives      []string // Multiple values grouped by OR on same field
	IsComputed        bool     // Always false for Sigma (no computed fields)
	SourceField       string   // Always empty for Sigma
}

// ParseResult holds the complete extraction result from a Sigma rule.
type ParseResult struct {
	Conditions     []Condition       // Extracted conditions
	Expression     *Expression       // Lossless boolean expression tree for the detection condition
	GroupByFields  []string          // Fields from aggregation group-by clauses
	ComputedFields map[string]string // Always empty for Sigma
	Commands       []string          // Aggregation commands detected (e.g., "count", "sum")
	Joins          []JoinInfo        // Always empty for Sigma (no joins)
	Errors         []string          // Parse errors: the rule is not valid Sigma
	Warnings       []string          // Valid Sigma that likely does not match as meant, such as CommandLine: -NoProfile

	// Sigma-specific metadata (additive — doesn't break adapter compatibility)
	LogSource *LogSource // Log source from the rule
	Level     string     // Rule severity: informational, low, medium, high, critical
	Status    string     // Rule status: experimental, test, stable, deprecated, unsupported
	Title     string     // Rule title
	ID        string     // Rule id
	Name      string     // Rule name, by which correlations may reference the rule
	Tags      []string   // MITRE ATT&CK tags and other tags
	Timeframe string     // Detection timeframe, e.g. "5m"
}

// ExpressionKind identifies a node in a Sigma detection expression tree.
type ExpressionKind string

const (
	ExpressionCondition ExpressionKind = "condition"
	ExpressionAnd       ExpressionKind = "and"
	ExpressionOr        ExpressionKind = "or"
	ExpressionNot       ExpressionKind = "not"
	ExpressionThreshold ExpressionKind = "threshold"
)

// Expression preserves boolean grouping and threshold quantifiers from a
// Sigma detection condition. Threshold is used for expressions such as
// "2 of selection_*"; it is ignored for other node kinds.
type Expression struct {
	Kind      ExpressionKind
	Condition *Condition
	Children  []*Expression
	Threshold int
}

// LogSource describes the log source specified in a Sigma rule.
type LogSource struct {
	Category string // e.g., "process_creation", "file_event"
	Product  string // e.g., "windows", "linux"
	Service  string // e.g., "sysmon", "security"
}

// JoinInfo is a stub for API parity with other parsers. Sigma has no joins.
type JoinInfo struct {
	Type          string
	JoinFields    []string
	Options       map[string]string
	Subsearch     string
	PipeStage     int
	IsAppend      bool
	ExposedFields []string
}

// FieldProvenance classifies where a field originates.
type FieldProvenance string

const (
	ProvenanceMain      FieldProvenance = "main"
	ProvenanceJoined    FieldProvenance = "joined"
	ProvenanceJoinKey   FieldProvenance = "join_key"
	ProvenanceAmbiguous FieldProvenance = "ambiguous"
)

// ClassifyFieldProvenance returns "main" for all Sigma fields (no joins).
func ClassifyFieldProvenance(_ *ParseResult, _ string) FieldProvenance {
	return ProvenanceMain
}

// File is a parsed Sigma file: one rule, a Sigma 1.0 rule collection, or
// Sigma correlation rules with the rules they reference.
type File struct {
	// Rules are the detection rules that match on their own: every rule of
	// a plain file or collection, minus the rules only correlations use.
	Rules []*ParseResult
	// Correlations are the outermost correlations of the file; the rules and
	// correlations they reference hang off them.
	Correlations []*Correlation
	// Errors holds every problem in the file, including its rules' own
	// parse errors.
	Errors []string
	// Warnings holds what the file's rules likely do not match as meant,
	// such as CommandLine: -NoProfile, which only matches a command line
	// that is exactly -NoProfile.
	Warnings []string
}

// CorrelationType is the kind of a Sigma correlation rule.
type CorrelationType string

const (
	// CorrelationEventCount counts the events of the referenced rules.
	CorrelationEventCount CorrelationType = "event_count"
	// CorrelationValueCount counts the distinct values of Field.
	CorrelationValueCount CorrelationType = "value_count"
	// CorrelationValueSum sums the numeric field Field.
	CorrelationValueSum CorrelationType = "value_sum"
	// CorrelationValueAvg averages the numeric field Field.
	CorrelationValueAvg CorrelationType = "value_avg"
	// CorrelationValuePercentile compares the share, in percent, of the
	// group's events that carry each value of Field.
	CorrelationValuePercentile CorrelationType = "value_percentile"
	// CorrelationTemporal requires the referenced rules to match within the
	// timespan, in any order.
	CorrelationTemporal CorrelationType = "temporal"
	// CorrelationTemporalOrdered requires the referenced rules to match
	// within the timespan in the order they are listed.
	CorrelationTemporalOrdered CorrelationType = "temporal_ordered"
)

// Correlation is a Sigma correlation rule (Sigma 2): it matches when the
// events of the rules it references, grouped by GroupBy, meet its conditions
// within Timespan. A Sigma 1 "near" aggregation is read as a temporal
// correlation of its searches.
type Correlation struct {
	Title  string
	ID     string
	Name   string
	Level  string
	Status string
	Tags   []string

	Type  CorrelationType
	Rules []CorrelationRule
	// GroupBy may name aliases; GroupByFor resolves them per rule.
	GroupBy []string
	Aliases map[string]map[string]string // alias -> rule name -> field
	// Timespan is a number and a unit: s, m, h or d. It is empty for a
	// Sigma 1 near rule without timeframe, which spans the query's time range.
	Timespan string
	// Field is the field value_count and the value metrics read.
	Field string
	// Conditions compare the correlation's value with thresholds: one
	// comparison, or two for a range. Temporal correlations without
	// conditions require all their rules.
	Conditions []CorrelationCondition
	// Generate reports that the referenced rules also match on their own.
	Generate bool
}

// CorrelationRule is a rule a correlation references: a detection rule or a
// correlation.
type CorrelationRule struct {
	Name        string // the rule's name, or its id when it has none
	Rule        *ParseResult
	Correlation *Correlation
	// Absent marks a "near ... and not" search: no event may match it.
	Absent bool
}

// CorrelationCondition compares a correlation's value with a threshold.
type CorrelationCondition struct {
	Operator string // gt, gte, lt, lte, eq or neq
	Value    float64
}

// GroupByFor returns the group-by fields of the given referenced rule, with
// aliases resolved to that rule's field names.
func (c *Correlation) GroupByFor(rule string) []string {
	fields := make([]string, len(c.GroupBy))
	for i, field := range c.GroupBy {
		fields[i] = field
		if aliased, ok := c.Aliases[field][rule]; ok {
			fields[i] = aliased
		}
	}
	return fields
}
