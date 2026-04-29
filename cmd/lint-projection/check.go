package main

import (
	"fmt"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
)

type Finding struct {
	File     string
	Line     int
	RuleID   string
	Severity Severity
	Check    string
	Message  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s: %s: %s", f.File, f.Line, f.RuleID, f.Severity, f.Check, f.Message)
}

// ruleDoc mirrors the relevant fields of a kubescape/rulelibrary rule YAML.
// We only need profileDependency and profileDataRequired here.
type ruleDoc struct {
	Spec struct {
		Rules []struct {
			ID                  string                         `yaml:"id"`
			ProfileDependency   armotypes.ProfileDependency    `yaml:"profileDependency"`
			ProfileDataRequired *armotypes.ProfileDataRequired `yaml:"profileDataRequired,omitempty"`
		} `yaml:"rules"`
	} `yaml:"spec"`
}

func lintFiles(files []string) []Finding {
	var findings []Finding
	for _, path := range files {
		findings = append(findings, lintFile(path)...)
	}
	return findings
}

func lintFile(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{File: path, Line: 0, RuleID: "?", Severity: SeverityError, Check: "C3", Message: fmt.Sprintf("read failed: %v", err)}}
	}
	var doc ruleDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return []Finding{{File: path, Line: 0, RuleID: "?", Severity: SeverityError, Check: "C3", Message: fmt.Sprintf("yaml unmarshal: %v", err)}}
	}
	lineByID := indexRuleLines(data)

	var findings []Finding
	for _, r := range doc.Spec.Rules {
		line := lineByID[r.ID]
		findings = append(findings, checkRule(path, line, r.ID, r.ProfileDependency, r.ProfileDataRequired)...)
	}
	return findings
}

func checkRule(path string, line int, id string, dep armotypes.ProfileDependency, pdr *armotypes.ProfileDataRequired) []Finding {
	var out []Finding
	switch dep {
	case armotypes.Required, armotypes.Optional:
		if pdr == nil || pdr.IsEmpty() {
			out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C1",
				Message: fmt.Sprintf("rule has profileDependency=%v; profileDataRequired must be present and declare at least one surface", profileDependencyName(dep))})
		}
	case armotypes.NotRequired:
		if pdr != nil {
			out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityWarn, Check: "C4",
				Message: "rule has profileDependency=NotRequired but declares profileDataRequired; if the rule does not query profile data, remove the declaration"})
		}
	default:
		out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C5",
			Message: fmt.Sprintf("rule has unrecognized profileDependency value %d; must be 0 (Required), 1 (Optional), or 2 (NotRequired)", int(dep))})
	}
	if pdr != nil && !pdr.IsEmpty() {
		if err := pdr.Validate(); err != nil {
			out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C2", Message: err.Error()})
		}
	}
	return out
}

func profileDependencyName(d armotypes.ProfileDependency) string {
	switch d {
	case armotypes.Required:
		return "Required"
	case armotypes.Optional:
		return "Optional"
	case armotypes.NotRequired:
		return "NotRequired"
	}
	return fmt.Sprintf("Unknown(%d)", d)
}

func indexRuleLines(data []byte) map[string]int {
	out := map[string]int{}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return out
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return out
	}
	root := doc.Content[0]
	spec := findMappingValue(root, "spec")
	rules := findMappingValue(spec, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return out
	}
	for _, ruleMap := range rules.Content {
		if id := findMappingValue(ruleMap, "id"); id != nil {
			out[id.Value] = id.Line
		}
	}
	return out
}

func findMappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
