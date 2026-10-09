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
	Errors         []string          // Parse errors and warnings

	// Sigma-specific metadata (additive — doesn't break adapter compatibility)
	LogSource *LogSource // Log source from the rule
	Level     string     // Rule severity: informational, low, medium, high, critical
	Status    string     // Rule status: experimental, test, stable, deprecated, unsupported
	Title     string     // Rule title
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
