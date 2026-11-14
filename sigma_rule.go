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
