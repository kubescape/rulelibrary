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
		Comm:        "test",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.OpenEventType,
		FlagsRaw:    1, // Write flag
		Namespace:   "default",
		Path:        "/etc/ld.so.preload",
		Pod:         "test-pod",
	}

	// Serialize open event
	enrichedEvent := &events.EnrichedEvent{
		Event: openEvent,
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

	// Only the access mode (the low two bits) decides whether the file is
	// being written; other flag bits such as O_CLOEXEC must not count.
	// The dynamic loader opens the file with O_RDONLY|O_CLOEXEC on every
	// exec once it exists.
	const (
		oWronly  = 0x1
		oRdwr    = 0x2
		oAccmode = 0x3
		oCreat   = 0x40
		oTrunc   = 0x200
		oAppend  = 0x400
		oCloexec = 0x80000
	)
	for _, tc := range []struct {
		name     string
		flagsRaw uint32
		want     bool
	}{
		{"O_RDONLY|O_CLOEXEC", oCloexec, false},
		{"O_ACCMODE", oAccmode, false},
		{"O_WRONLY|O_CREAT|O_TRUNC", oWronly | oCreat | oTrunc, true},
		{"O_WRONLY|O_APPEND|O_CLOEXEC", oWronly | oAppend | oCloexec, true},
		{"O_RDWR", oRdwr, true},
		{"O_RDWR|O_CLOEXEC", oRdwr | oCloexec, true},
	} {
		openEvent.FlagsRaw = tc.flagsRaw
		ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
		if err != nil {
			t.Fatalf("Failed to evaluate rule for %s: %v", tc.name, err)
		}
		if ok != tc.want {
			t.Fatalf("Rule evaluation for ld.so.preload opened with %s = %v, want %v", tc.name, ok, tc.want)
		}
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
		Comm:        "java",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		Namespace:   "default",
		Pid:         1234,
		Pod:         "test-pod",
	}

	enrichedEvent2 := &events.EnrichedEvent{
		Event: execEvent,
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
	profile := objCache.GetContainerProfile("test")
	if profile == nil {
		profile = &v1beta1.ContainerProfile{Spec: v1beta1.ContainerProfileSpec{
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R1011": {
					AllowedProcesses: []string{"test"},
				},
			},
		}}
	}

	objCache.SetContainerProfile(profile)

	// Test policy validation with whitelisted process
	openEvent.Comm = "test"
	openEvent.Path = "/etc/ld.so.preload"
	openEvent.FlagsRaw = 1

	v := rulemanager.NewRulePolicyValidator(objCache)
	ok, err = v.Validate(ruleSpec.Rules[0].ID, openEvent.Comm, &objectcache.ProjectedContainerProfile{PolicyByRuleId: profile.Spec.PolicyByRuleId})
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
