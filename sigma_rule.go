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

// parseSigmaRules parses a Sigma rule file into its rules. A file may be a
// Sigma 1.0 rule collection: YAML documents where "action: global" sets
// attributes shared by the rules that follow, "action: reset" clears them,
// and "action: repeat" repeats the previous rule with its keys changed.
func parseSigmaRules(yamlContent string) ([]*sigmaRule, error) {
	documents, err := yamlDocuments(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	ruleDocuments, err := collectionRules(documents)
	if err != nil {
		return nil, err
	}
	if len(ruleDocuments) == 0 {
		return nil, fmt.Errorf("sigma rule missing 'detection' block")
	}
	rules := make([]*sigmaRule, len(ruleDocuments))
	for i, document := range ruleDocuments {
		if rules[i], err = ruleFromDocument(document); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// parseSigmaRule parses a rule file as one rule. A collection's rules match
// together, so their detections are ORed; the log source is kept only when
// all rules share it.
func parseSigmaRule(yamlContent string) (*sigmaRule, error) {
	rules, err := parseSigmaRules(yamlContent)
	if err != nil {
		return nil, err
	}
	rule := rules[0]
	for _, next := range rules[1:] {
		rule.Detection = orDetections(rule.Detection, next.Detection)
		if next.LogSource != rule.LogSource {
			rule.LogSource = logSource{}
		}
	}
	return rule, nil
}

func yamlDocuments(content string) ([]orderedMap, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var documents []orderedMap
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			return documents, nil
		}
		if err != nil {
			return nil, err
		}
		value, err := decodeOrdered(&node)
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

// collectionRules applies Sigma collection actions and returns the rule
// documents, each merged with the global attributes in effect.
func collectionRules(documents []orderedMap) ([]orderedMap, error) {
	var global, previous orderedMap
	var rules []orderedMap
	for _, document := range documents {
		action, _ := document.get("action")
		body := document.without("action")
		switch action {
		case nil:
			previous = mergeDocuments(global, body)
			rules = append(rules, previous)
		case "global":
			global = mergeDocuments(global, body)
		case "reset":
			global = nil
		case "repeat":
			if previous == nil {
				return nil, fmt.Errorf("sigma collection repeats a rule before defining one")
			}
			previous = mergeDocuments(previous, body)
			rules = append(rules, previous)
		default:
			return nil, fmt.Errorf("unsupported sigma collection action %v", action)
		}
	}
	return rules, nil
}

// mergeDocuments overlays update on base, merging nested mappings key by key.
func mergeDocuments(base, update orderedMap) orderedMap {
	out := append(orderedMap(nil), base...)
	for _, entry := range update {
		existing, found := out.get(entry.key)
		baseMap, baseIsMap := existing.(orderedMap)
		updateMap, updateIsMap := entry.value.(orderedMap)
		value := entry.value
		if found && baseIsMap && updateIsMap {
			value = mergeDocuments(baseMap, updateMap)
		}
		out = out.with(entry.key, value)
	}
	return out
}

func ruleFromDocument(document orderedMap) (*sigmaRule, error) {
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
	rule.Title = documentString(document, "title")
	rule.Status = documentString(document, "status")
	rule.Level = documentString(document, "level")
	if tags, ok := document.get("tags"); ok {
		list, _ := tags.([]any)
		for _, tag := range list {
			rule.Tags = append(rule.Tags, fmt.Sprintf("%v", tag))
		}
	}
	if value, ok := document.get("logsource"); ok {
		source, _ := value.(orderedMap)
		rule.LogSource = logSource{
			Category: documentString(source, "category"),
			Product:  documentString(source, "product"),
			Service:  documentString(source, "service"),
		}
	}
	return rule, nil
}

func documentString(document orderedMap, key string) string {
	value, ok := document.get(key)
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

// orDetections combines the detections of two collection rules into one
// that matches either: the second rule's search identifiers are renamed so
// they cannot collide, and the conditions are ORed.
func orDetections(first, second orderedMap) orderedMap {
	firstCondition, _ := first.get("condition")
	secondCondition, _ := second.get("condition")
	prefix := uniquePrefix(first)
	renames := make(map[string]string, len(second))
	out := first.without("condition")
	for _, entry := range second {
		switch strings.ToLower(entry.key) {
		case "condition", "timeframe":
			continue
		}
		renames[entry.key] = prefix + entry.key
		out = append(out, mapEntry{key: prefix + entry.key, value: entry.value})
	}
	condition := "(" + conditionText(firstCondition) + ") or (" + renameIdentifiers(conditionText(secondCondition), renames, prefix) + ")"
	return append(out, mapEntry{key: "condition", value: condition})
}

func uniquePrefix(detection orderedMap) string {
	for n := 1; ; n++ {
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

func conditionText(condition any) string {
	if list, ok := condition.([]any); ok {
		parts := make([]string, len(list))
		for i, item := range list {
			parts[i] = "(" + fmt.Sprintf("%v", item) + ")"
		}
		return strings.Join(parts, " or ")
	}
	return fmt.Sprintf("%v", condition)
}

// renameIdentifiers rewrites the search identifiers and selector patterns
// of a condition to their renamed form.
func renameIdentifiers(condition string, renames map[string]string, prefix string) string {
	lexer := newConditionLexer(condition)
	lexer.tokenize()
	var out strings.Builder
	last := 0
	for i, tok := range lexer.tokens {
		if tok.typ != tokIdent {
			continue
		}
		previousIsOf := i > 0 && lexer.tokens[i-1].typ == tokOf
		renamed, known := renames[tok.val]
		switch {
		case known:
		case previousIsOf:
			// A selector pattern such as selection_* matches renamed names.
			renamed = prefix + tok.val
		default:
			continue
		}
		out.WriteString(condition[last:tok.pos])
		out.WriteString(renamed)
		last = tok.pos + len(tok.val)
	}
	out.WriteString(condition[last:])
	return out.String()
}
