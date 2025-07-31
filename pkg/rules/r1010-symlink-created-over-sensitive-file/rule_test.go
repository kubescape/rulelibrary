package r1010symlinkcreatedoversensitivefile

import (
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR1010SymlinkCreatedOverSensitiveFile(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("symlink-created-over-sensitive-file.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a symlink event
	e := &tracersymlinktype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:    "test",
		OldPath: "/etc/shadow",
		NewPath: "/etc/abc",
	}

	objCache := &profilevalidator.RuleObjectCacheMock{}

	celEngine, err := celengine.NewCEL(objCache)
	if err != nil {
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	celSerializer := celengine.CelEventSerializer{}

	eventMap := celSerializer.Serialize(e)

	// Evaluate the rule
	ok, err := celEngine.EvaluateRule(eventMap, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed for sensitive file symlink")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Symlink created over sensitive file: /etc/shadow -> /etc/abc"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	expectedUniqueId := "test_/etc/shadow"
	if uniqueId != expectedUniqueId {
		t.Fatalf("Unique id evaluation failed. Expected: %s, Got: %s", expectedUniqueId, uniqueId)
	}

	// Test with non-sensitive file path
	e.OldPath = "/tmp/test"
	e.NewPath = "/tmp/abc"

	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for non-sensitive file symlink")
	}
}
