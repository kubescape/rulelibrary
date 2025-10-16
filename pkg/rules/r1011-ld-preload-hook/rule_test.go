package r1011ldpreloadhook

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

func TestR1011LdPreloadHook(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("ld-preload-hook.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
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

	// Test open event with ld.so.preload file opened with write flag - SHOULD TRIGGER
	openEvent := &utils.StructEvent{
		Container:   "test",
		ContainerID: "test",
		Pod:         "test-pod",
		Namespace:   "default",
		Comm:        "test",
		Path:        "/etc/ld.so.preload",
		FlagsRaw:    1, // Write flag
		EventType:   utils.OpenEventType,
	}

	// Serialize open event
	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.OpenEventType,
		Event:     openEvent,
	}

	// Evaluate the rule for open event - should trigger for write access to ld.so.preload
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation should trigger for write access to ld.so.preload")
	}

	// Test with read flag - SHOULD NOT TRIGGER
	openEvent.FlagsRaw = 0

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should not trigger for read access to ld.so.preload")
	}

	// Test with different file - SHOULD NOT TRIGGER
	openEvent.Path = "/etc/passwd"
	openEvent.FlagsRaw = 1

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should not trigger for non-ld.so.preload file")
	}

	// Test exec events - just verify expression compiles and returns false (can't mock PID)
	execEvent := &utils.StructEvent{
		Container:   "test",
		ContainerID: "test",
		Pod:         "test-pod",
		Namespace:   "default",
		Comm:        "java",
		Pid:         1234,
		EventType:   utils.ExecveEventType,
	}

	enrichedEvent2 := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
		Event:     execEvent,
	}

	// For exec events, just verify the expression compiles and returns false
	// (since we can't mock process.get_ld_hook_var for a real PID)
	ok, err = celEngine.EvaluateRule(enrichedEvent2, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate exec rule expression: %v", err)
	}
	// Should return false since process.get_ld_hook_var likely returns empty for non-existent/test PIDs
	if ok {
		t.Fatalf("Rule evaluation should return false for exec events with test PIDs")
	}

	// Test exec event with matlab container - should not trigger due to container check
	execEvent.Comm = "test-process"
	execEvent.Container = "matlab"

	ok, err = celEngine.EvaluateRule(enrichedEvent2, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should not trigger for matlab container")
	}

	// Test with profile - policy validation for open events
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R1011": {
					AllowedProcesses: []string{"test"},
				},
			},
		})
	}

	objCache.SetApplicationProfile(profile)

	// Test policy validation with whitelisted process
	openEvent.Comm = "test"
	openEvent.Path = "/etc/ld.so.preload"
	openEvent.FlagsRaw = 1

	v := rulemanager.NewRulePolicyValidator(objCache)
	ok, err = v.Validate(ruleSpec.Rules[0].ID, openEvent.Comm, &profile.Spec.Containers[0])
	if err != nil {
		t.Fatalf("Failed to validate rule policy: %v", err)
	}
	if !ok {
		t.Fatalf("Rule policy validation should return true for whitelisted process")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "The dynamic linker configuration file (/etc/ld.so.preload) was modified by process (test)" {
		t.Fatalf("Message evaluation failed")
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "open_/etc/ld.so.preload" {
		t.Fatalf("Unique id evaluation failed")
	}
}
