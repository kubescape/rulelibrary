package r0003unexpectedsystemcall

import (
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0003UnexpectedSystemCall(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-system-call.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a syscall event
	e := &types.SyscallEvent{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:        "test",
		SyscallName: "test_syscall",
		Pid:         1234,
	}

	objCache := &profilevalidator.RuleObjectCacheMock{}

	celEngine, err := celengine.NewCEL(objCache)
	if err != nil {
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	fullEvent := types.EventWithChecks{
		Event: e,
		ProfileChecks: profilevalidator.ProfileValidationResult{
			Checks: []profilevalidator.ProfileValidationCheck{
				{
					Name:   "syscall_whitelisted",
					Result: false,
				},
			},
		},
	}

	// Evaluate the rule
	ok, err := celEngine.EvaluateRule(fullEvent.CelEvaluationMap(), ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(fullEvent.CelEvaluationMap(), ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected system call detected: test_syscall with PID 1234" {
		t.Fatalf("Message evaluation failed: %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(fullEvent.CelEvaluationMap(), ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test_syscall" {
		t.Fatalf("Unique id evaluation failed: %s", uniqueId)
	}
}
