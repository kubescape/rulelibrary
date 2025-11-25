package r1005filelessexecution

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
)

func TestR1005FilelessExecution(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("fileless-execution.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a mock exec event for fileless execution via memfd
	e := &utils.StructEvent{
		Args:        []string{"/memfd:test", "arg1"},
		Comm:        "/memfd:test",
		Container:   "test",
		ContainerID: "test-container",
		EventType:   utils.ExecveEventType,
		ExePath:     "/memfd:test",
		Gid:         1000,
		Namespace:   "test-namespace",
		Pcomm:       "/memfd:test",
		Pid:         1234,
		Pod:         "test-pod",
		Uid:         1000,
	}

	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container", &objectcache.WatchedContainerData{
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

	// Test with memfd execution - should trigger alert
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution via memfd")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Fileless execution detected: exec call \"/memfd:test\" is from a malicious source"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "/memfd:test_/memfd:test_/memfd:test" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Test with /proc/self/fd execution - should trigger alert
	e.Comm = "/proc/self/fd/3"
	e.ExePath = "/proc/self/fd/3"
	e.Args = []string{"/proc/self/fd/3", "arg1"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution via /proc/self/fd")
	}

	// Test with /proc/[pid]/fd execution - should trigger alert
	e.Comm = "/proc/1234/fd/5"
	e.ExePath = "/proc/1234/fd/5"
	e.Args = []string{"/proc/1234/fd/5", "arg1"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution via /proc/[pid]/fd")
	}

	// Test with normal file execution - should not trigger
	e.Comm = "/usr/bin/ls"
	e.ExePath = "/usr/bin/ls"
	e.Args = []string{"/usr/bin/ls", "-la"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for normal file execution")
	}

	// Test with /proc/self/maps (not fd) - should not trigger
	e.Comm = "/proc/self/maps"
	e.ExePath = "/proc/self/maps"
	e.Args = []string{"/proc/self/maps"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for /proc/self/maps (not fd)")
	}

	// Test with /proc/1234/status (not fd) - should not trigger
	e.Comm = "/proc/1234/status"
	e.ExePath = "/proc/1234/status"
	e.Args = []string{"/proc/1234/status"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for /proc/1234/status (not fd)")
	}

	// Test with different memfd pattern
	e.Comm = "/memfd:malware"
	e.ExePath = "/memfd:malware"
	e.Args = []string{"/memfd:malware"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution with different memfd name")
	}

	// Test with different fd number
	e.Comm = "/proc/5678/fd/10"
	e.ExePath = "/proc/5678/fd/10"
	e.Args = []string{"/proc/5678/fd/10"}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution with different fd number")
	}
}
