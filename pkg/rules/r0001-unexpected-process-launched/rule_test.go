package r0001unexpectedprocesslaunched

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0001UnexpectedProcessLaunched(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-launched.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}
	// Create a process exec event
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
						},
					},
				},
			},
			Pid:     1234,
			Comm:    "test-process",
			Pcomm:   "test-process",
			ExePath: "/usr/bin/test-process",
			Args:    []string{"test-process", "arg1"},
		},
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
					Name:   "exec_path",
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
	if message != "Unexpected process launched: test-process with PID 1234" {
		t.Fatalf("Message evaluation failed")
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(fullEvent.CelEvaluationMap(), ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test-process_1234_/usr/bin/test-process" {
		t.Fatalf("Unique id evaluation failed")
	}

}
