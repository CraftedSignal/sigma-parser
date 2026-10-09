package sigma

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// sigmaRule is the internal representation of a parsed Sigma YAML rule.
type sigmaRule struct {
	Title         string    `yaml:"title"`
	Status        string    `yaml:"status"`
	Level         string    `yaml:"level"`
	Description   string    `yaml:"description"`
	Author        string    `yaml:"author"`
	Date          string    `yaml:"date"`
	Modified      string    `yaml:"modified"`
	Tags          []string  `yaml:"tags"`
	LogSource     logSource `yaml:"logsource"`
	DetectionNode yaml.Node `yaml:"detection"`
	FalsePos      []string  `yaml:"falsepositives"`
	Fields        []string  `yaml:"fields"`

	// Detection is the detection block with its key order preserved.
	Detection orderedMap `yaml:"-"`
}

// logSource maps the Sigma logsource block.
type logSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// parseSigmaRule parses raw YAML into a sigmaRule.
func parseSigmaRule(yamlContent string) (*sigmaRule, error) {
	var rule sigmaRule
	if err := yaml.Unmarshal([]byte(yamlContent), &rule); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	detection, err := decodeOrdered(&rule.DetectionNode)
	if err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	rule.Detection, _ = detection.(orderedMap)
	if rule.Detection == nil {
		return nil, fmt.Errorf("sigma rule missing 'detection' block")
	}
	if _, ok := rule.Detection.get("condition"); !ok {
		return nil, fmt.Errorf("sigma rule missing 'detection.condition'")
	}
	return &rule, nil
}
