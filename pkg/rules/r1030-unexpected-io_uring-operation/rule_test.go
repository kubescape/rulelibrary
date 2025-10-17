package r1030_unexpected_io_uring_operation

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR1030UnexpectedIouringOperation(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-io_uring-operation.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create an io_uring event
	e := &utils.StructEvent{
		Comm:        "test-process",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.IoUringEventType,
		FlagsRaw:    0x0,
		Identifier:  "test-process",
		Opcode:      1, // IORING_OP_NOP
		UserData:    123,
	}

	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test",
				},
			},
		},
	})

	celEngine, err := celengine.NewCEL(objCache, config.Config{
		CelConfigCache: cache.FunctionCacheConfig{
			MaxSize: 1000,
			TTL:     1 * time.Microsecond,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	// Serialize event
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}

	// Evaluate the rule - should always return true for io_uring events
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation should always return true for io_uring events")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Unexpected io_uring operation detected: (opcode=1) flags=0x0 in test-process."
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	expectedUniqueId := "1_test-process"
	if uniqueId != expectedUniqueId {
		t.Fatalf("Unique id evaluation failed. Expected: %s, Got: %s", expectedUniqueId, uniqueId)
	}

	// Test with different opcode
	e.Opcode = 2 // Different opcode

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation should always return true for io_uring events regardless of opcode")
	}

	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R1030": {
					AllowedProcesses: []string{"/usr/bin/allowed-process"},
				},
			},
		})
	}

	objCache.SetApplicationProfile(profile)

	e.Comm = "/usr/bin/allowed-process"

	v := rulemanager.NewRulePolicyValidator(objCache)
	ok, err = v.Validate(ruleSpec.Rules[0].ID, e.Comm, &profile.Spec.Containers[0])
	if err != nil {
		t.Fatalf("Failed to validate rule policy: %v", err)
	}
	if !ok {
		t.Fatalf("Rule policy validation should return true for whitelisted process")
	}
}
