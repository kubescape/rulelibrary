package r1005filelessexecution

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR1005FilelessExecution(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("fileless-execution.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a mock exec event for fileless execution via memfd
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
							PodName:       "test-pod",
							Namespace:     "test-namespace",
						},
					},
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID:   "test-container",
						ContainerName: "test",
					},
				},
			},
			Comm:    "/memfd:test",
			ExePath: "/memfd:test",
			Pcomm:   "/memfd:test",
			Args:    []string{"/memfd:test", "arg1"},
			Pid:     1234,
			Uid:     1000,
			Gid:     1000,
		},
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
	adapterFactory := ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok := adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Test with memfd execution - should trigger alert
	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution via memfd")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Fileless execution detected: exec call \"/memfd:test\" is from a malicious source"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected fileless execution with different fd number")
	}
}

// BenchmarkR1005CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR1005CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("fileless-execution.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create an exec event for fileless execution
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
						},
					},
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID: "test",
					},
				},
			},
			Pid:     1234,
			Comm:    "/proc/1234/fd/5",
			ExePath: "/proc/1234/fd/5",
			Args:    []string{"/proc/1234/fd/5"},
		},
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
		b.Fatalf("Failed to create CEL engine: %v", err)
	}

	adapterFactory := ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok := adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		b.Fatalf("Failed to get event adapter")
	}

	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		// Benchmark CEL rule evaluation
		_, err := celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
		if err != nil {
			b.Fatalf("Failed to evaluate rule: %v", err)
		}

		// Also benchmark message and unique ID expressions
		_, err = celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
		if err != nil {
			b.Fatalf("Failed to evaluate message: %v", err)
		}

		_, err = celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
		if err != nil {
			b.Fatalf("Failed to evaluate unique id: %v", err)
		}
	}
}
