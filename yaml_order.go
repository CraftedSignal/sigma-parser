package sigma

import (
	"fmt"
	"math/big"
	"strings"

	"gopkg.in/yaml.v3"
)

// mapEntry is one key/value pair of a YAML mapping.
type mapEntry struct {
	key   string
	value any
}

// orderedMap is a YAML mapping decoded in document order. Sigma ANDs the
// fields of a selection, and keeping the authored order makes extraction and
// compiled queries deterministic instead of following Go map iteration.
type orderedMap []mapEntry

func (m orderedMap) get(key string) (any, bool) {
	for _, entry := range m {
		if entry.key == key {
			return entry.value, true
		}
	}
	return nil, false
}

// decodeOrdered converts a YAML node into plain Go values, decoding mappings
// as orderedMap. Timestamps keep their source text: a detection value such as
// 2024-01-02 is a string to match, not a time. An integer too large for
// int64 and uint64 is a *big.Int, as yaml.v3's float64 would lose digits.
func decodeOrdered(node *yaml.Node, budgets ...*parseBudget) (any, error) {
	return decodeOrderedScope(node, budgetFrom(budgets), documentScope)
}

type yamlScope int

const (
	ordinaryScope yamlScope = iota
	documentScope
	detectionScope
	numericScope
	correlationScope
	correlationConditionScope
)

func decodeOrderedScope(node *yaml.Node, b *parseBudget, scope yamlScope) (any, error) {
	defer b.visitYAML(node)()
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return decodeOrderedScope(node.Content[0], b, scope)
	case yaml.AliasNode:
		return decodeOrderedScope(node.Alias, b, scope)
	case yaml.MappingNode:
		b.node(len(node.Content) / 2)
		out := make(orderedMap, 0, len(node.Content)/2)
		seen := make(map[string]struct{}, len(node.Content)/2)
		seenCondition, seenTimeframe := false, false
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, err := decodeOrderedKey(node.Content[i], b)
			if err != nil {
				return nil, err
			}
			_, duplicate := seen[key]
			if scope == detectionScope {
				switch {
				case strings.EqualFold(key, "condition"):
					duplicate = seenCondition
					seenCondition = true
				case strings.EqualFold(key, "timeframe"):
					duplicate = seenTimeframe
					seenTimeframe = true
				}
			}
			if duplicate && !(scope == correlationConditionScope && key == "field") {
				return nil, fmt.Errorf("duplicate YAML mapping key %q", key)
			}
			seen[key] = struct{}{}
			childScope := scope
			switch scope {
			case documentScope:
				childScope = ordinaryScope
				if key == "detection" {
					childScope = detectionScope
				} else if key == "correlation" {
					childScope = correlationScope
				}
			case detectionScope:
				childScope = numericScope
				if strings.EqualFold(key, "condition") || strings.EqualFold(key, "timeframe") {
					childScope = ordinaryScope
				}
			case correlationScope:
				childScope = ordinaryScope
				if key == "condition" {
					childScope = correlationConditionScope
				}
			case correlationConditionScope:
				childScope = ordinaryScope
			}
			value, err := decodeOrderedScope(node.Content[i+1], b, childScope)
			if err != nil {
				return nil, err
			}
			out = append(out, mapEntry{key: key, value: value})
		}
		return out, nil
	case yaml.SequenceNode:
		b.node(len(node.Content))
		out := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := decodeOrderedScope(child, b, scope)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	default:
		if scope == numericScope && (node.Tag == "!!int" || node.Tag == "!!float") {
			return decodeNumber(node, b)
		}
		if node.Tag == "!!timestamp" {
			return node.Value, nil
		}
		if node.Tag == "!!float" && node.Style == 0 {
			if integer, ok := new(big.Int).SetString(strings.ReplaceAll(node.Value, "_", ""), 10); ok {
				return integer, nil
			}
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		return value, nil
	}
}

func (b *parseBudget) visitYAML(node *yaml.Node) func() {
	b.step(1)
	b.node(1)
	leave := b.enter()
	if node == nil {
		panic(parseAbort{fmt.Errorf("invalid YAML alias target")})
	}
	if b.active[node] {
		panic(parseAbort{fmt.Errorf("cyclic YAML alias")})
	}
	b.active[node] = true
	if node.Kind == yaml.ScalarNode {
		b.decoded(len(node.Value))
	}
	return func() { delete(b.active, node); leave() }
}

func decodeOrderedKey(node *yaml.Node, b *parseBudget) (string, error) {
	defer b.visitYAML(node)()
	if node.Kind == yaml.AliasNode {
		return decodeOrderedKey(node.Alias, b)
	}
	var key string
	err := node.Decode(&key)
	return key, err
}

func (m orderedMap) without(key string) orderedMap {
	out := make(orderedMap, 0, len(m))
	for _, entry := range m {
		if entry.key != key {
			out = append(out, entry)
		}
	}
	return out
}

// with sets key to value, replacing an existing entry in place.
func (m orderedMap) with(key string, value any) orderedMap {
	for i, entry := range m {
		if entry.key == key {
			out := append(orderedMap(nil), m...)
			out[i].value = value
			return out
		}
	}
	return append(m, mapEntry{key: key, value: value})
}
