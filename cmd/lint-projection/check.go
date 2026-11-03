package main

import (
	"fmt"
	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"os"
	"strings"

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
// DNS-only profile calls use an always-retained baseline rather than selective projection.
type ruleDoc struct {
	Spec struct {
		Rules []struct {
			Expressions struct {
				Message        string `yaml:"message"`
				UniqueID       string `yaml:"uniqueId"`
				RuleExpression []struct {
					Expression string `yaml:"expression"`
				} `yaml:"ruleExpression"`
			} `yaml:"expressions"`
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
		ruleFindings := checkRule(path, line, r.ID, r.ProfileDependency, r.ProfileDataRequired)
		expressions := make([]string, 0, len(r.Expressions.RuleExpression))
		for _, expression := range r.Expressions.RuleExpression {
			expressions = append(expressions, expression.Expression)
		}
		for _, expression := range []string{r.Expressions.Message, r.Expressions.UniqueID} {
			if expression != "" {
				expressions = append(expressions, expression)
			}
		}
		// DNS is always retained by the agent and has no selective projection declaration.
		if usesOnlyDNSProfile(expressions) {
			filtered := ruleFindings[:0]
			for _, finding := range ruleFindings {
				if finding.Check != "C1" {
					filtered = append(filtered, finding)
				}
			}
			ruleFindings = filtered
		}
		findings = append(findings, ruleFindings...)
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

// usesOnlyDNSProfile parses calls rather than matching text: comments and string
// literals cannot exempt a rule that still needs selective profile projection.
func usesOnlyDNSProfile(expressions []string) bool {
	env, err := cel.NewEnv()
	if err != nil {
		return false
	}
	dns, projected := false, false
	var qualifiedName func(*exprpb.Expr) string
	qualifiedName = func(expression *exprpb.Expr) string {
		if expression == nil {
			return ""
		}
		if ident := expression.GetIdentExpr(); ident != nil {
			return ident.Name
		}
		if selectExpr := expression.GetSelectExpr(); selectExpr != nil {
			prefix := qualifiedName(selectExpr.Operand)
			if prefix != "" {
				return prefix + "." + selectExpr.Field
			}
		}
		return ""
	}
	var visit func(*exprpb.Expr)
	visit = func(expression *exprpb.Expr) {
		if expression == nil {
			return
		}
		switch node := expression.ExprKind.(type) {
		case *exprpb.Expr_CallExpr:
			name := node.CallExpr.Function
			if prefix := qualifiedName(node.CallExpr.Target); prefix != "" {
				name = prefix + "." + name
			}
			name = strings.TrimPrefix(name, ".")
			if name == "cp.was_dns_resolved" || name == "cp.was_dns_resolved_by_process" {
				dns = true
			} else if strings.HasPrefix(name, "cp.") || strings.HasPrefix(name, "ap.") || strings.HasPrefix(name, "nn.") {
				projected = true
			}
			visit(node.CallExpr.Target)
			for _, arg := range node.CallExpr.Args {
				visit(arg)
			}
		case *exprpb.Expr_SelectExpr:
			visit(node.SelectExpr.Operand)
		case *exprpb.Expr_ListExpr:
			for _, element := range node.ListExpr.Elements {
				visit(element)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range node.StructExpr.Entries {
				visit(entry.GetMapKey())
				visit(entry.Value)
			}
		case *exprpb.Expr_ComprehensionExpr:
			c := node.ComprehensionExpr
			visit(c.IterRange)
			visit(c.AccuInit)
			visit(c.LoopCondition)
			visit(c.LoopStep)
			visit(c.Result)
		}
	}
	for _, expression := range expressions {
		ast, issues := env.Parse(expression)
		if issues.Err() != nil {
			return false
		}
		visit(ast.Expr())
	}
	return dns && !projected
}
