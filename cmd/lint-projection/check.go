package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
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
// We only need the id, profileDependency, profileDataRequired,
// agentVersionRequirement and the eventType of each rule expression here.
type ruleDoc struct {
	Spec struct {
		Rules []struct {
			ID          string `yaml:"id"`
			Expressions struct {
				RuleExpression []struct {
					EventType string `yaml:"eventType"`
				} `yaml:"ruleExpression"`
			} `yaml:"expressions"`
			ProfileDependency       armotypes.ProfileDependency    `yaml:"profileDependency"`
			ProfileDataRequired     *armotypes.ProfileDataRequired `yaml:"profileDataRequired,omitempty"`
			AgentVersionRequirement string                         `yaml:"agentVersionRequirement,omitempty"`
		} `yaml:"rules"`
	} `yaml:"spec"`
}

// ruleRef records where a rule ID is declared, for the library-wide
// duplicate ID check.
type ruleRef struct {
	ID   string
	File string
	Line int
}

// ruleEventTypes is the set of eventType values a rule expression can be
// selected for. Apart from k8s-admission, whose events come from the
// Kubescape operator's admission webhook, these are the values
// utils.RuleEventType returns in node-agent v0.3.308. "dnsQuery" is the
// rule-only alias for DNS queries and error responses, which node-agent
// forwards only when dnsRuleForwarding is enabled.
var ruleEventTypes = map[string]bool{
	"bpf":           true,
	"capabilities":  true,
	"dns":           true,
	"dnsQuery":      true,
	"exec":          true,
	"exit":          true,
	"fork":          true,
	"hardlink":      true,
	"http":          true,
	"iouring":       true,
	"k8s-admission": true,
	"kmod":          true,
	"network":       true,
	"open":          true,
	"procfs":        true,
	"ptrace":        true,
	"randomx":       true,
	"ssh":           true,
	"symlink":       true,
	"syscall":       true,
	"unshare":       true,
}

// profileDataSurfaces and profileDataPatternFields are the keys the node-agent
// rules watcher accepts in a raw profileDataRequired object. Like
// typesv1.KnownProfileDataSurfaces and KnownProfileDataPatternFields in
// node-agent v0.3.308, they are read from the JSON tags of the armotypes
// structs, so a surface added to armoapi-go is accepted here as well.
var (
	profileDataSurfaces      = jsonFieldNames(reflect.TypeOf(armotypes.ProfileDataRequired{}))
	profileDataPatternFields = jsonFieldNames(reflect.TypeOf(armotypes.ProfileDataPattern{}))
)

func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

func lintFiles(files []string) []Finding {
	var findings []Finding
	var refs []ruleRef
	for _, path := range files {
		fileFindings, fileRefs := lintFileRules(path)
		findings = append(findings, fileFindings...)
		refs = append(refs, fileRefs...)
	}
	return append(findings, checkDuplicateIDs(refs)...)
}

func lintFile(path string) []Finding {
	findings, refs := lintFileRules(path)
	return append(findings, checkDuplicateIDs(refs)...)
}

// lintFileRules runs the per-rule checks on one file and returns the
// findings together with the location of every rule ID it declares.
func lintFileRules(path string) ([]Finding, []ruleRef) {
	data, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{File: path, Line: 0, RuleID: "?", Severity: SeverityError, Check: "C3", Message: fmt.Sprintf("read failed: %v", err)}}, nil
	}
	var doc ruleDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return []Finding{{File: path, Line: 0, RuleID: "?", Severity: SeverityError, Check: "C3", Message: fmt.Sprintf("yaml unmarshal: %v", err)}}, nil
	}
	nodes := ruleNodes(data)

	var findings []Finding
	var refs []ruleRef
	for i, r := range doc.Spec.Rules {
		var node *yaml.Node
		if i < len(nodes) {
			node = nodes[i]
		}
		line := ruleLine(node)
		findings = append(findings, checkRule(path, line, r.ID, r.ProfileDependency, r.ProfileDataRequired)...)
		findings = append(findings, checkProfileDataKeys(path, line, r.ID, findMappingValue(node, "profileDataRequired"))...)
		findings = append(findings, checkAgentVersionRequirement(path, line, r.ID, r.AgentVersionRequirement)...)
		eventTypes := make([]string, 0, len(r.Expressions.RuleExpression))
		for _, expr := range r.Expressions.RuleExpression {
			eventTypes = append(eventTypes, expr.EventType)
		}
		findings = append(findings, checkEventTypes(path, line, r.ID, eventTypes)...)
		refs = append(refs, ruleRef{ID: r.ID, File: path, Line: line})
	}
	return findings, refs
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

// checkProfileDataKeys rejects a profileDataRequired key that is not a profile
// surface or a pattern field, such as "exec" for "execs" or "prefixes" for
// "prefix". Decoding into armotypes drops unknown keys, so C1 and C2 never see
// them. The node-agent rules watcher validates the raw object first
// (ValidateRawProfileDataRequired in node-agent v0.3.308) and, on an unknown
// key, skips the whole Rules object. gen.sh merges every rule into one Rules
// object, so a single unknown key stops the node-agent from loading any rule
// in rules-crd.yaml.
func checkProfileDataKeys(path string, line int, id string, pdr *yaml.Node) []Finding {
	if pdr == nil || pdr.Kind != yaml.MappingNode {
		return nil
	}
	const consequence = "node-agent rejects the whole Rules object that contains it, so no rule in rules-crd.yaml loads"
	var out []Finding
	for i := 0; i+1 < len(pdr.Content); i += 2 {
		surface, patterns := pdr.Content[i].Value, pdr.Content[i+1]
		if !profileDataSurfaces[surface] {
			out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C9",
				Message: fmt.Sprintf("profileDataRequired has unknown surface %q (must be one of: %s); %s", surface, sortedNames(profileDataSurfaces), consequence)})
			continue
		}
		if patterns.Kind != yaml.SequenceNode {
			continue
		}
		for j, pattern := range patterns.Content {
			if pattern.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(pattern.Content); k += 2 {
				if field := pattern.Content[k].Value; !profileDataPatternFields[field] {
					out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C9",
						Message: fmt.Sprintf("profileDataRequired.%s[%d] has unknown pattern field %q (must be one of: %s); %s", surface, j, field, sortedNames(profileDataPatternFields), consequence)})
				}
			}
		}
	}
	return out
}

// checkAgentVersionRequirement rejects an agentVersionRequirement that
// Masterminds/semver, the library the node-agent rules watcher uses, cannot
// parse. The watcher fails open on a parse error: it logs a warning and
// loads the rule on every agent version, so the gate silently stops
// protecting older agents from expressions they cannot compile.
func checkAgentVersionRequirement(path string, line int, id, requirement string) []Finding {
	if requirement == "" {
		return nil
	}
	if _, err := semver.NewConstraint(requirement); err != nil {
		return []Finding{{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C6",
			Message: fmt.Sprintf("agentVersionRequirement %q is not a valid semver constraint (%v); node-agent loads a rule with an unparseable constraint on every agent version", requirement, err)}}
	}
	return nil
}

// checkEventTypes rejects a rule expression whose eventType is not one an
// event source emits. The node-agent selects expressions by comparing
// eventType with the event's type as an exact string, so a misspelled or
// unsupported value, such as "Exec" or "file", loads without any error and
// the expression never runs.
func checkEventTypes(path string, line int, id string, eventTypes []string) []Finding {
	var out []Finding
	for i, eventType := range eventTypes {
		if ruleEventTypes[eventType] {
			continue
		}
		out = append(out, Finding{File: path, Line: line, RuleID: id, Severity: SeverityError, Check: "C7",
			Message: fmt.Sprintf("ruleExpression[%d] has unknown eventType %q (must be one of: %s); node-agent matches eventType exactly, so this expression never runs", i, eventType, sortedNames(ruleEventTypes))})
	}
	return out
}

func sortedNames(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// checkDuplicateIDs rejects a rule ID that more than one rule declares.
// gen.sh merges every rule into one Rules object, and the node-agent rule
// creator keys the rules it loads by ID (RuleCreatorImpl.SyncRules in
// node-agent v0.3.308), so only one rule per ID is loaded and the others are
// dropped without a warning. Rules without an ID are left to the other checks.
func checkDuplicateIDs(refs []ruleRef) []Finding {
	var out []Finding
	first := map[string]ruleRef{}
	for _, r := range refs {
		if r.ID == "" {
			continue
		}
		prev, seen := first[r.ID]
		if !seen {
			first[r.ID] = r
			continue
		}
		out = append(out, Finding{File: r.File, Line: r.Line, RuleID: r.ID, Severity: SeverityError, Check: "C8",
			Message: fmt.Sprintf("rule ID is already declared at %s:%d; node-agent loads only one rule per ID, so one of them is silently dropped", prev.File, prev.Line)})
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

// ruleNodes returns the mapping node of each entry of spec.rules, in order.
func ruleNodes(data []byte) []*yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	spec := findMappingValue(root, "spec")
	rules := findMappingValue(spec, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil
	}
	return rules.Content
}

// ruleLine returns the line of a rule's id (or of the rule entry itself when
// it has no id), so that two rules with the same ID in one file are reported
// at their own lines.
func ruleLine(rule *yaml.Node) int {
	if rule == nil {
		return 0
	}
	if id := findMappingValue(rule, "id"); id != nil {
		return id.Line
	}
	return rule.Line
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
