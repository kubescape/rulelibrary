package common

import (
	"strings"
	"testing"

	v1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func admissionRule(message, uniqueID string, exprs ...string) v1.Rule {
	r := v1.Rule{ID: "R9999"}
	r.Expressions.Message = message
	r.Expressions.UniqueID = uniqueID
	for _, e := range exprs {
		r.Expressions.RuleExpression = append(r.Expressions.RuleExpression,
			v1.RuleExpression{EventType: AdmissionEventType, Expression: e})
	}
	return r
}

var podCreateEvent = AdmissionEvent{Kind: "Pod", Name: "p", Namespace: "default", Operation: "CREATE", Username: "alice",
	Object: JSONObject(`{"metadata":{"name":"p"},"spec":{"containers":[{"name":"c"}]}}`)}

func TestEvaluateAdmissionRule_ANDsExpressions(t *testing.T) {
	rule := admissionRule("", "", `event.Kind == "Pod"`, `event.Operation == "CREATE"`)

	res, err := EvaluateAdmissionRule(rule, podCreateEvent)
	if err != nil || !res.Matched {
		t.Fatalf("both true: matched=%v err=%v, want match", res.Matched, err)
	}

	update := podCreateEvent
	update.Operation = "UPDATE"
	res, err = EvaluateAdmissionRule(rule, update)
	if err != nil || res.Matched {
		t.Fatalf("one false: matched=%v err=%v, want no match (operator ANDs expressions)", res.Matched, err)
	}
}

func TestEvaluateAdmissionRule_NoAdmissionExpressionNeverMatches(t *testing.T) {
	r := v1.Rule{ID: "R9999"}
	r.Expressions.RuleExpression = []v1.RuleExpression{{EventType: "exec", Expression: "true"}}
	res, err := EvaluateAdmissionRule(r, podCreateEvent)
	if err != nil || res.Matched {
		t.Fatalf("matched=%v err=%v, want no match for a rule without k8s-admission expressions", res.Matched, err)
	}
}

func TestEvaluateAdmissionRule_NonBoolExpressionIsError(t *testing.T) {
	_, err := EvaluateAdmissionRule(admissionRule("", "", `event.Kind`), podCreateEvent)
	if err == nil || !strings.Contains(err.Error(), "expected bool") {
		t.Fatalf("err=%v, want expected bool", err)
	}
}

func TestEvaluateAdmissionRule_NonStringTemplatesAreErrors(t *testing.T) {
	_, err := EvaluateAdmissionRule(admissionRule("42", "", "true"), podCreateEvent)
	if err == nil || !strings.Contains(err.Error(), "message") || !strings.Contains(err.Error(), "expected string") {
		t.Fatalf("message err=%v, want expected string", err)
	}
	_, err = EvaluateAdmissionRule(admissionRule("", "object.spec.containers.size()", "true"), podCreateEvent)
	if err == nil || !strings.Contains(err.Error(), "uniqueId") || !strings.Contains(err.Error(), "expected string") {
		t.Fatalf("uniqueId err=%v, want expected string", err)
	}
}

func TestEvaluateAdmissionRule_TemplatesEvaluated(t *testing.T) {
	res, err := EvaluateAdmissionRule(admissionRule(`'pod ' + event.Name + ' by ' + event.UserInfo.Username`, `event.Namespace + '/' + event.Name`, "true"), podCreateEvent)
	if err != nil || !res.Matched {
		t.Fatalf("matched=%v err=%v", res.Matched, err)
	}
	if res.Message != "pod p by alice" || res.UniqueID != "default/p" {
		t.Fatalf("message=%q uniqueId=%q", res.Message, res.UniqueID)
	}
}

func TestCheckAdmissionPrefilterConstraints(t *testing.T) {
	if err := CheckAdmissionPrefilterConstraints(admissionRule("", "", `event.Kind == "Pod" && true`)); err != nil {
		t.Fatalf("valid expression rejected: %v", err)
	}
	if err := CheckAdmissionPrefilterConstraints(admissionRule("", "", `event.Kind == "Pod" || event.Kind == "Role"`)); err == nil {
		t.Fatal("|| accepted")
	}
	if err := CheckAdmissionPrefilterConstraints(admissionRule("", "", `event.Operation == "CREATE"`)); err == nil {
		t.Fatal("expression without a literal Kind accepted")
	}
}
