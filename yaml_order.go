package sigma

import "gopkg.in/yaml.v3"

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
// 2024-01-02 is a string to match, not a time.
func decodeOrdered(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return decodeOrdered(node.Content[0])
	case yaml.AliasNode:
		return decodeOrdered(node.Alias)
	case yaml.MappingNode:
		out := make(orderedMap, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			var key string
			if err := node.Content[i].Decode(&key); err != nil {
				return nil, err
			}
			value, err := decodeOrdered(node.Content[i+1])
			if err != nil {
				return nil, err
			}
			out = append(out, mapEntry{key: key, value: value})
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := decodeOrdered(child)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	default:
		if node.Tag == "!!timestamp" {
			return node.Value, nil
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		return value, nil
	}
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
