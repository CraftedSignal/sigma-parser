package sigma

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// sigmaRule is the internal representation of a parsed Sigma YAML rule.
type sigmaRule struct {
	Title     string
	ID        string
	Name      string
	Status    string
	Level     string
	Tags      []string
	LogSource logSource
	// Detection is the detection block with its key order preserved.
	Detection orderedMap
}

// logSource maps the Sigma logsource block.
type logSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// parseSigmaRules parses the detection rules of a Sigma rule file. A file may
// be a Sigma 1.0 rule collection: YAML documents where "action: global" sets
// attributes shared by the rules that follow, "action: reset" clears them,
// and "action: repeat" repeats the previous rule with its keys changed.
// Correlation documents are not detection rules and are skipped.
func parseSigmaRules(yamlContent string, budgets ...*parseBudget) ([]*sigmaRule, error) {
	b := budgetFrom(budgets)
	documents, err := yamlDocuments(yamlContent, b)
	if err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	documents, err = collectionDocuments(documents, b)
	if err != nil {
		return nil, err
	}
	var rules []*sigmaRule
	for _, document := range documents {
		b.step(1)
		if isCorrelationDocument(document) {
			continue
		}
		rule, err := ruleFromDocument(document, b)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("sigma rule missing 'detection' block")
	}
	return rules, nil
}

// parseSigmaRule parses a rule file as one rule. A collection's rules match
// together, so their detections are ORed; the log source is kept only when
// all rules share it.
func parseSigmaRule(yamlContent string, budgets ...*parseBudget) (*sigmaRule, error) {
	b := budgetFrom(budgets)
	rules, err := parseSigmaRules(yamlContent, b)
	if err != nil {
		return nil, err
	}
	rule := rules[0]
	for _, next := range rules[1:] {
		b.step(1)
		rule.Detection = orDetections(rule.Detection, next.Detection, b)
		if next.LogSource != rule.LogSource {
			rule.LogSource = logSource{}
		}
	}
	return rule, nil
}

func yamlDocuments(content string, budgets ...*parseBudget) ([]orderedMap, error) {
	b := budgetFrom(budgets)
	b.input(content)
	decoder := yaml.NewDecoder(budgetReader{reader: strings.NewReader(content), budget: b})
	var documents []orderedMap
	for {
		b.check()
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			return documents, nil
		}
		if err != nil {
			return nil, err
		}
		b.take(&b.documents, 1, b.limits.documents, "documents")
		value, err := decodeOrdered(&node, b)
		if err != nil {
			return nil, err
		}
		document, ok := value.(orderedMap)
		if !ok {
			if value == nil {
				continue
			}
			return nil, fmt.Errorf("document is not a mapping")
		}
		documents = append(documents, document)
	}
}

// collectionDocuments applies Sigma collection actions and returns the rule
// and correlation documents, each merged with the global attributes in
// effect.
func collectionDocuments(documents []orderedMap, budgets ...*parseBudget) ([]orderedMap, error) {
	b := budgetFrom(budgets)
	var global, previous orderedMap
	var rules []orderedMap
	for _, document := range documents {
		b.step(len(document) + 1)
		action, _ := document.get("action")
		body := document.without("action")
		switch action {
		case nil:
			previous = mergeDocuments(global, body, b)
			rules = append(rules, previous)
		case "global":
			global = mergeDocuments(global, body, b)
		case "reset":
			global = nil
		case "repeat":
			if previous == nil {
				return nil, fmt.Errorf("sigma collection repeats a rule before defining one")
			}
			previous = mergeDocuments(previous, body, b)
			rules = append(rules, previous)
		default:
			return nil, fmt.Errorf("unsupported sigma collection action %v", action)
		}
	}
	return rules, nil
}

// mergeDocuments overlays update on base, merging nested mappings key by key.
func mergeDocuments(base, update orderedMap, budgets ...*parseBudget) orderedMap {
	b := budgetFrom(budgets)
	defer b.enter()()
	b.node(len(base))
	out := append(orderedMap(nil), base...)
	for _, entry := range update {
		b.step(len(out) + 1)
		b.node(len(out) + 1)
		existing, found := out.get(entry.key)
		baseMap, baseIsMap := existing.(orderedMap)
		updateMap, updateIsMap := entry.value.(orderedMap)
		value := entry.value
		if found && baseIsMap && updateIsMap {
			value = mergeDocuments(baseMap, updateMap, b)
		}
		out = out.with(entry.key, value)
	}
	return out
}

func ruleFromDocument(document orderedMap, budgets ...*parseBudget) (*sigmaRule, error) {
	b := budgetFrom(budgets)
	rule := &sigmaRule{}
	if value, ok := document.get("detection"); ok {
		rule.Detection, _ = value.(orderedMap)
	}
	if rule.Detection == nil {
		return nil, fmt.Errorf("sigma rule missing 'detection' block")
	}
	if _, ok := rule.Detection.get("condition"); !ok {
		return nil, fmt.Errorf("sigma rule missing 'detection.condition'")
	}
	rule.Title = documentString(document, "title", b)
	rule.ID = documentString(document, "id", b)
	rule.Name = documentString(document, "name", b)
	rule.Status = documentString(document, "status", b)
	rule.Level = documentString(document, "level", b)
	rule.Tags = documentStrings(document, "tags", b)
	if value, ok := document.get("logsource"); ok {
		source, _ := value.(orderedMap)
		rule.LogSource = logSource{
			Category: documentString(source, "category", b),
			Product:  documentString(source, "product", b),
			Service:  documentString(source, "service", b),
		}
	}
	return rule, nil
}

func documentString(document orderedMap, key string, budgets ...*parseBudget) string {
	value, ok := document.get(key)
	if !ok || value == nil {
		return ""
	}
	return budgetFrom(budgets).formatValue(value)
}

// orDetections combines the detections of two collection rules into one
// that matches either: the second rule's search identifiers are renamed so
// they cannot collide, and the conditions are ORed.
func orDetections(first, second orderedMap, budgets ...*parseBudget) orderedMap {
	b := budgetFrom(budgets)
	b.step(len(first) + len(second))
	b.node(len(first) + len(second))
	firstCondition, _ := first.get("condition")
	secondCondition, _ := second.get("condition")
	prefix := uniquePrefix(first, b)
	renames := make(map[string]string, len(second))
	out := first.without("condition")
	for _, entry := range second {
		b.step(1)
		switch strings.ToLower(entry.key) {
		case "condition", "timeframe":
			continue
		}
		b.output(2 * (len(prefix) + len(entry.key)))
		renames[entry.key] = prefix + entry.key
		out = append(out, mapEntry{key: prefix + entry.key, value: entry.value})
	}
	left := conditionText(firstCondition, b)
	right := renameIdentifiers(conditionText(secondCondition, b), renames, prefix, b)
	b.output(len(left) + len(right) + 10)
	b.step(len(left) + len(right) + 10)
	condition := "(" + left + ") or (" + right + ")"
	return append(out, mapEntry{key: "condition", value: condition})
}

func uniquePrefix(detection orderedMap, budgets ...*parseBudget) string {
	b := budgetFrom(budgets)
	for n := 1; ; n++ {
		b.step(len(detection) + 1)
		prefix := fmt.Sprintf("rule%d_", n)
		clash := false
		for _, entry := range detection {
			if strings.HasPrefix(entry.key, prefix) {
				clash = true
				break
			}
		}
		if !clash {
			return prefix
		}
	}
}

func conditionText(condition any, budgets ...*parseBudget) string {
	b := budgetFrom(budgets)
	if list, ok := condition.([]any); ok {
		b.node(len(list))
		parts := make([]string, len(list))
		for i, item := range list {
			text := b.formatValue(item)
			b.output(len(text) + 6)
			parts[i] = "(" + text + ")"
		}
		joinedBytes := 0
		for _, part := range parts {
			joinedBytes += len(part) + 4
		}
		b.output(joinedBytes)
		return strings.Join(parts, " or ")
	}
	return b.formatValue(condition)
}

// renameIdentifiers rewrites the search identifiers and selector patterns
// of a condition to their renamed form.
func renameIdentifiers(condition string, renames map[string]string, prefix string, budgets ...*parseBudget) string {
	b := budgetFrom(budgets)
	lexer := newConditionLexer(condition, b)
	var out strings.Builder
	last := 0
	for i, tok := range lexer.tokens {
		b.step(1)
		if tok.typ != tokIdent {
			continue
		}
		previousIsOf := i > 0 && lexer.tokens[i-1].typ == tokOf
		renamed, known := renames[tok.val]
		switch {
		case known:
		case previousIsOf:
			// A selector pattern such as selection_* matches renamed names.
			b.output(len(prefix) + len(tok.val))
			renamed = prefix + tok.val
		default:
			continue
		}
		b.output(tok.pos - last + len(renamed))
		out.WriteString(condition[last:tok.pos])
		out.WriteString(renamed)
		last = tok.pos + len(tok.val)
	}
	b.output(len(condition) - last)
	out.WriteString(condition[last:])
	return out.String()
}
