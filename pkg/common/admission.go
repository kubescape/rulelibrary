package common

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	v1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

// AdmissionEventType is the event type the operator's admission webhook
// evaluates rules against. Mirrors kubescape/operator admission/cel.
const AdmissionEventType = "k8s-admission"

// AdmissionEvent is a test-side model of the operator's AdmissionCelEvent.
// The operator exposes a native struct; here the same field names are
// exposed as a map so expressions written against `event.Kind`,
// `event.Operation`, `event.UserInfo.Username` and friends evaluate the
// same way without pulling the operator module into this repository.
type AdmissionEvent struct {
	Kind        string
	Name        string
	Namespace   string
	Operation   string
	Resource    string
	Subresource string
	Username    string
	Groups      []string
	DryRun      bool
	Object      map[string]any
	OldObject   map[string]any
	Options     map[string]any
}

// AdmissionResult is what EvaluateAdmissionRule returns for one rule.
type AdmissionResult struct {
	Matched  bool
	Message  string
	UniqueID string
}

// JSONObject decodes a JSON document into the unstructured map shape the
// operator hands to CEL as `object` and `oldObject`. It panics on invalid
// JSON because it is only meant for test fixtures.
func JSONObject(doc string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		panic(fmt.Sprintf("JSONObject: %v", err))
	}
	return m
}

func newAdmissionEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("eventType", cel.StringType),
		cel.Variable("object", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("oldObject", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("options", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
	)
}

func (e AdmissionEvent) activation() map[string]any {
	groups := e.Groups
	if groups == nil {
		groups = []string{}
	}
	nonNil := func(m map[string]any) map[string]any {
		if m == nil {
			return map[string]any{}
		}
		return m
	}
	return map[string]any{
		"event": map[string]any{
			"Kind":        e.Kind,
			"Group":       "",
			"Version":     "",
			"Name":        e.Name,
			"Namespace":   e.Namespace,
			"Operation":   e.Operation,
			"Subresource": e.Subresource,
			"Resource":    e.Resource,
			"DryRun":      e.DryRun,
			"UserInfo": map[string]any{
				"Username": e.Username,
				"Groups":   groups,
				"UID":      "",
			},
			"Object":    nonNil(e.Object),
			"OldObject": nonNil(e.OldObject),
			"Options":   nonNil(e.Options),
		},
		"eventType": AdmissionEventType,
		"object":    nonNil(e.Object),
		"oldObject": nonNil(e.OldObject),
		"options":   nonNil(e.Options),
		"params":    map[string]any{},
	}
}

func evalExpr(env *cel.Env, expr string, act map[string]any) (any, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compile: %w", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	return out.Value(), nil
}

// EvaluateAdmissionRule evaluates one rule's k8s-admission expressions
// against the event with the operator's contract
// (kubescape/operator admission/cel.AdmissionCEL.EvaluateRuleWithContext):
// every expression for the event type must be true (AND), a rule with no
// admission expression never matches, a non-bool expression is an error.
// On a match the message and uniqueId templates are evaluated too and must
// return strings, as EvaluateStringExpression requires.
func EvaluateAdmissionRule(rule v1.Rule, event AdmissionEvent) (AdmissionResult, error) {
	env, err := newAdmissionEnv()
	if err != nil {
		return AdmissionResult{}, err
	}
	act := event.activation()

	sawExpression := false
	for _, ex := range rule.Expressions.RuleExpression {
		if string(ex.EventType) != AdmissionEventType {
			continue
		}
		sawExpression = true
		out, err := evalExpr(env, ex.Expression, act)
		if err != nil {
			return AdmissionResult{}, fmt.Errorf("rule %s expression: %w", rule.ID, err)
		}
		b, ok := out.(bool)
		if !ok {
			return AdmissionResult{}, fmt.Errorf("rule %s expression returned %T, expected bool", rule.ID, out)
		}
		if !b {
			return AdmissionResult{}, nil
		}
	}
	if !sawExpression {
		return AdmissionResult{}, nil
	}

	res := AdmissionResult{Matched: true}
	if rule.Expressions.Message != "" {
		res.Message, err = evalStringExpr(env, rule.Expressions.Message, act)
		if err != nil {
			return res, fmt.Errorf("rule %s message: %w", rule.ID, err)
		}
	}
	if rule.Expressions.UniqueID != "" {
		res.UniqueID, err = evalStringExpr(env, rule.Expressions.UniqueID, act)
		if err != nil {
			return res, fmt.Errorf("rule %s uniqueId: %w", rule.ID, err)
		}
	}
	return res, nil
}

func evalStringExpr(env *cel.Env, expr string, act map[string]any) (string, error) {
	out, err := evalExpr(env, expr, act)
	if err != nil {
		return "", err
	}
	s, ok := out.(string)
	if !ok {
		return "", fmt.Errorf("expression returned %T, expected string", out)
	}
	return s, nil
}

var admissionKindConstraint = regexp.MustCompile(`event\.Kind\s*==\s*"[^"]+"`)

// CheckAdmissionPrefilterConstraints enforces what the operator's Kind
// pre-filter needs from every loaded admission expression: no `||` anywhere
// (one occurrence disables the pre-filter for all rules) and at least one
// literal `event.Kind == "..."` so the rule can be narrowed to its kinds.
func CheckAdmissionPrefilterConstraints(rule v1.Rule) error {
	for i, ex := range rule.Expressions.RuleExpression {
		if string(ex.EventType) != AdmissionEventType {
			continue
		}
		if strings.Contains(ex.Expression, "||") {
			return fmt.Errorf("rule %s expression %d contains ||, which disables the operator Kind pre-filter for every rule", rule.ID, i)
		}
		if !admissionKindConstraint.MatchString(ex.Expression) {
			return fmt.Errorf("rule %s expression %d has no literal event.Kind == \"...\" constraint", rule.ID, i)
		}
	}
	return nil
}
