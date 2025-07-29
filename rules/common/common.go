package common

import (
	"fmt"
	"os"

	v1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"gopkg.in/yaml.v3"
)

func LoadRuleFromYAML(ruleYAMLPath string) (*v1.RuleSpec, error) {
	rules := &v1.Rules{}
	bytes, err := os.ReadFile(ruleYAMLPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(bytes, rules)
	if err != nil {
		return nil, err
	}

	if len(rules.Spec) == 0 {
		return nil, fmt.Errorf("no rules found in %s", ruleYAMLPath)
	}

	return &rules.Spec[0], nil
}
