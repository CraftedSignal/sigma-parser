package sigma

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// timespanRe is a correlation timespan: a number and a unit.
var timespanRe = regexp.MustCompile(`^[1-9][0-9]*[smhd]$`)

// correlationOperators are the comparisons a correlation condition may use.
var correlationOperators = []string{"gt", "gte", "lt", "lte", "eq", "neq"}

// ExtractFile parses a Sigma file: one rule, a Sigma 1.0 rule collection, or
// Sigma correlation rules with the rules they reference, which may be
// referenced by name or id. Includes the parse timeout and panic recovery.
func ExtractFile(yamlContent string) *File {
	return guarded(yamlContent, func() *File {
		return extractFile(yamlContent)
	}, func(message string) *File {
		return &File{Errors: []string{message}}
	})
}

// fileNode is a rule or correlation of a file while references resolve.
type fileNode struct {
	rule        *ParseResult
	correlation *Correlation
	refs        []string // the rules a correlation document references
	referenced  bool
}

func (n *fileNode) key() string {
	if n.rule != nil {
		return firstNonEmpty(n.rule.Name, n.rule.ID, n.rule.Title)
	}
	return firstNonEmpty(n.correlation.Name, n.correlation.ID, n.correlation.Title)
}

func extractFile(yamlContent string) *File {
	documents, err := yamlDocuments(yamlContent)
	if err != nil {
		return &File{Errors: []string{fmt.Sprintf("YAML parse error: %v", err)}}
	}
	documents, err = collectionDocuments(documents)
	if err != nil {
		return &File{Errors: []string{err.Error()}}
	}
	file := &File{}
	var nodes []*fileNode
	for _, document := range documents {
		if isCorrelationDocument(document) {
			correlation, refs, errs := parseCorrelation(document)
			file.Errors = append(file.Errors, errs...)
			nodes = append(nodes, &fileNode{correlation: correlation, refs: refs})
			continue
		}
		rule, err := ruleFromDocument(document)
		if err != nil {
			file.Errors = append(file.Errors, err.Error())
			continue
		}
		result := extractRule(rule)
		correlation, errs := nearCorrelation(rule, result)
		file.Errors = append(file.Errors, errs...)
		if correlation != nil {
			nodes = append(nodes, &fileNode{correlation: correlation})
			continue
		}
		nodes = append(nodes, &fileNode{rule: result})
	}
	if len(nodes) == 0 && len(file.Errors) == 0 {
		file.Errors = append(file.Errors, "sigma rule missing 'detection' block")
	}
	file.Errors = append(file.Errors, resolveReferences(nodes)...)
	if len(file.Errors) > 0 {
		return file
	}

	generated := map[*ParseResult]bool{}
	for _, n := range nodes {
		if n.correlation == nil {
			continue
		}
		if !n.referenced {
			file.Correlations = append(file.Correlations, n.correlation)
		}
		if n.correlation.Generate {
			for _, ref := range n.correlation.Rules {
				if ref.Rule != nil {
					generated[ref.Rule] = true
				}
			}
		}
	}
	var ruleNodes []*fileNode
	for _, n := range nodes {
		if n.rule == nil {
			continue
		}
		ruleNodes = append(ruleNodes, n)
		if !n.referenced || generated[n.rule] {
			file.Rules = append(file.Rules, n.rule)
		}
	}
	// Report the rules' own errors too, naming the rule when there are several.
	for _, n := range ruleNodes {
		if len(ruleNodes) == 1 {
			file.Errors = append(file.Errors, n.rule.Errors...)
			continue
		}
		file.Errors = append(file.Errors, prefixed(n.key(), n.rule.Errors)...)
	}
	return file
}

// DetectionRules returns every detection rule of the file: the rules that
// match on their own and the rules its correlations reference.
func (f *File) DetectionRules() []*ParseResult {
	rules := append([]*ParseResult(nil), f.Rules...)
	var collect func(c *Correlation)
	collect = func(c *Correlation) {
		for _, ref := range c.Rules {
			switch {
			case ref.Correlation != nil:
				collect(ref.Correlation)
			case ref.Rule != nil && !slices.Contains(rules, ref.Rule):
				rules = append(rules, ref.Rule)
			}
		}
	}
	for _, c := range f.Correlations {
		collect(c)
	}
	return rules
}

// isCorrelationDocument reports whether a document is a correlation rule.
func isCorrelationDocument(document orderedMap) bool {
	_, ok := document.get("correlation")
	return ok
}

// parseCorrelation reads a correlation document. It returns the correlation,
// the names or ids of the rules it references, and what is wrong with it.
func parseCorrelation(document orderedMap) (*Correlation, []string, []string) {
	c := &Correlation{
		Title:  documentString(document, "title"),
		ID:     documentString(document, "id"),
		Name:   documentString(document, "name"),
		Level:  documentString(document, "level"),
		Status: documentString(document, "status"),
		Tags:   documentStrings(document, "tags"),
	}
	label := firstNonEmpty(c.Name, c.ID, c.Title, "correlation")
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf("correlation %q: ", label)+fmt.Sprintf(format, args...))
	}
	section, ok := mustGet(document, "correlation").(orderedMap)
	if !ok {
		fail("correlation must be a mapping")
		return c, nil, errs
	}

	c.Type = CorrelationType(documentString(section, "type"))
	switch c.Type {
	case CorrelationEventCount, CorrelationValueCount, CorrelationValueSum, CorrelationValueAvg,
		CorrelationValuePercentile, CorrelationTemporal, CorrelationTemporalOrdered:
	case "":
		fail("missing type")
	default:
		fail("unknown type %q", c.Type)
	}

	refs := documentStrings(section, "rules")
	if len(refs) == 0 {
		fail("references no rules")
	}
	c.GroupBy = documentStrings(section, "group-by")
	c.Timespan = documentString(section, "timespan")
	if !timespanRe.MatchString(c.Timespan) {
		fail("timespan %q is not a number followed by s, m, h or d", c.Timespan)
	}
	c.Generate = documentBool(section, "generate") || documentBool(document, "generate")

	c.Field = documentString(section, "field")
	if raw, ok := section.get("condition"); ok {
		condition, isMap := raw.(orderedMap)
		if !isMap {
			fail("condition must be a mapping of comparisons")
		}
		for _, entry := range condition {
			if entry.key == "field" {
				c.Field = fmt.Sprintf("%v", entry.value)
				continue
			}
			if !slices.Contains(correlationOperators, entry.key) {
				fail("unknown condition operator %q", entry.key)
				continue
			}
			value, isNumber := number(entry.value)
			if !isNumber {
				fail("condition %s needs a number, got %v", entry.key, entry.value)
				continue
			}
			c.Conditions = append(c.Conditions, CorrelationCondition{Operator: entry.key, Value: value})
		}
	}
	switch c.Type {
	case CorrelationTemporal, CorrelationTemporalOrdered:
		if len(c.Conditions) > 1 {
			fail("a temporal correlation takes at most one condition")
		}
	default:
		if len(c.Conditions) == 0 {
			fail("missing condition")
		}
		if len(c.Conditions) > 2 {
			fail("a condition holds one comparison, or two for a range")
		}
	}
	needsField := c.Type == CorrelationValueCount || c.Type == CorrelationValueSum ||
		c.Type == CorrelationValueAvg || c.Type == CorrelationValuePercentile
	if needsField && c.Field == "" {
		fail("%s needs a field", c.Type)
	}
	if !needsField && c.Field != "" {
		fail("%s takes no field", c.Type)
	}

	if raw, ok := section.get("aliases"); ok {
		aliases, isMap := raw.(orderedMap)
		if !isMap {
			fail("aliases must be a mapping")
		}
		c.Aliases = map[string]map[string]string{}
		for _, alias := range aliases {
			fields, isMap := alias.value.(orderedMap)
			if !isMap {
				fail("alias %q must map rule names to fields", alias.key)
				continue
			}
			c.Aliases[alias.key] = map[string]string{}
			for _, field := range fields {
				c.Aliases[alias.key][field.key] = fmt.Sprintf("%v", field.value)
			}
		}
	}
	return c, refs, errs
}

// resolveReferences links each correlation to the rules and correlations it
// references by name or id, and checks aliases and reference cycles.
func resolveReferences(nodes []*fileNode) []string {
	var errs []string
	// Rules of a Sigma 1.0 collection often share the id of their global
	// document, so a key only has to be unique when a correlation uses it.
	byKey := map[string][]*fileNode{}
	for _, n := range nodes {
		for _, key := range n.keys() {
			byKey[key] = append(byKey[key], n)
		}
	}
	for _, n := range nodes {
		c := n.correlation
		if c == nil {
			continue
		}
		for _, ref := range n.refs {
			targets := byKey[ref]
			if len(targets) != 1 {
				problem := "is not defined in this file"
				if len(targets) > 1 {
					problem = "names more than one rule"
				}
				errs = append(errs, fmt.Sprintf("correlation %q references rule %q, which %s", n.key(), ref, problem))
				continue
			}
			target := targets[0]
			target.referenced = true
			c.Rules = append(c.Rules, CorrelationRule{Name: target.key(), Rule: target.rule, Correlation: target.correlation})
		}
		for alias, fields := range c.Aliases {
			for rule := range fields {
				if !slices.ContainsFunc(c.Rules, func(r CorrelationRule) bool { return r.Name == rule }) {
					errs = append(errs, fmt.Sprintf("correlation %q: alias %q maps rule %q, which the correlation does not reference", n.key(), alias, rule))
				}
			}
		}
	}
	for _, n := range nodes {
		if n.correlation != nil && referencesItself(n.correlation, n.correlation, map[*Correlation]bool{}) {
			errs = append(errs, fmt.Sprintf("correlation %q references itself", n.key()))
		}
	}
	return errs
}

func (n *fileNode) keys() []string {
	var name, id string
	if n.rule != nil {
		name, id = n.rule.Name, n.rule.ID
	} else {
		name, id = n.correlation.Name, n.correlation.ID
	}
	var keys []string
	for _, key := range []string{name, id} {
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func referencesItself(root, c *Correlation, seen map[*Correlation]bool) bool {
	if seen[c] {
		return false
	}
	seen[c] = true
	for _, ref := range c.Rules {
		if ref.Correlation == root || (ref.Correlation != nil && referencesItself(root, ref.Correlation, seen)) {
			return true
		}
	}
	return false
}

// nearCorrelation reads a Sigma 1 "near" aggregation (condition: A | near B
// and not C) as a temporal correlation: within the timeframe, events match
// the condition before the pipe and each search after "near", and none match
// a search after "and not". Like other Sigma 1 aggregations, a rule without a
// timeframe spans the query's time range. It returns nil for rules without
// "near".
func nearCorrelation(rule *sigmaRule, result *ParseResult) (*Correlation, []string) {
	condition, _ := rule.Detection.get("condition")
	text, _ := condition.(string)
	anchor, aggregation, found := strings.Cut(text, "|")
	aggregation = strings.TrimSpace(aggregation)
	if !found || !strings.EqualFold(firstWord(aggregation), "near") {
		return nil, nil
	}
	c := &Correlation{
		Title:    rule.Title,
		ID:       rule.ID,
		Name:     rule.Name,
		Level:    rule.Level,
		Status:   rule.Status,
		Tags:     rule.Tags,
		Type:     CorrelationTemporal,
		Timespan: result.Timeframe,
	}
	label := firstNonEmpty(rule.Name, rule.ID, rule.Title, "rule")
	var errs []string
	if c.Timespan != "" && !timespanRe.MatchString(c.Timespan) {
		errs = append(errs, fmt.Sprintf("rule %q: near timeframe %q is not a number followed by s, m, h or d", label, c.Timespan))
	}

	anchorName := "anchor"
	for _, exists := rule.Detection.get(anchorName); exists; _, exists = rule.Detection.get(anchorName) {
		anchorName = "_" + anchorName
	}
	main := extractRule(withCondition(rule, strings.TrimSpace(anchor)))
	errs = append(errs, prefixed(label, main.Errors)...)
	c.Rules = append(c.Rules, CorrelationRule{Name: anchorName, Rule: main})

	for _, item := range splitOnAnd(strings.TrimSpace(aggregation[len("near"):])) {
		name, absent := strings.CutPrefix(strings.TrimSpace(item), "not ")
		name = strings.TrimSpace(name)
		if _, defined := rule.Detection.get(name); !defined || name == "condition" || name == "timeframe" {
			errs = append(errs, fmt.Sprintf("rule %q: near references %q, which is not a search identifier of the rule", label, item))
			continue
		}
		search := extractRule(withCondition(rule, name))
		errs = append(errs, prefixed(label, search.Errors)...)
		c.Rules = append(c.Rules, CorrelationRule{Name: name, Rule: search, Absent: absent})
	}
	if len(c.Rules) < 2 {
		errs = append(errs, fmt.Sprintf("rule %q: near needs at least one search", label))
	}
	return c, errs
}

func withCondition(rule *sigmaRule, condition string) *sigmaRule {
	copied := *rule
	copied.Detection = rule.Detection.with("condition", condition).without("timeframe")
	return &copied
}

func prefixed(label string, errs []string) []string {
	out := make([]string, len(errs))
	for i, err := range errs {
		out[i] = fmt.Sprintf("rule %q: %s", label, err)
	}
	return out
}

func firstWord(s string) string {
	word, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	return word
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func mustGet(m orderedMap, key string) any {
	value, _ := m.get(key)
	return value
}

// documentStrings reads a string or a list of strings.
func documentStrings(m orderedMap, key string) []string {
	switch value := mustGet(m, key).(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	default:
		return []string{fmt.Sprintf("%v", value)}
	}
}

func documentBool(m orderedMap, key string) bool {
	value, _ := mustGet(m, key).(bool)
	return value
}

func number(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}
