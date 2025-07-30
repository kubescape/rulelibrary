package r0002unexpectedfileaccess

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0002UnexpectedFileAccess(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-file-access.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}
	// Create a file access event
	e := &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
						},
					},
				},
			},
			Pid:      0,
			Comm:     "test",
			Path:     "/test",
			FullPath: "/test",
			Flags:    []string{"O_RDONLY"},
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
					Name:   "open_dynamic_path",
					Result: false,
				},
			},
		},
	}

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
	if message != "Unexpected file access detected: test with PID 0 to /test" {
		t.Fatalf("Message evaluation failed %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(fullEvent.CelEvaluationMap(), ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test_/test" {
		t.Fatalf("Unique id evaluation failed %s", uniqueId)
	}
}
