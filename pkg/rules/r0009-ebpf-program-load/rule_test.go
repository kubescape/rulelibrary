package r0009ebpfprogramload

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0009EbpfProgramLoad(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("ebpf-program-load.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a syscall event with bpf syscall
	e := &types.SyscallEvent{
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
		Pid:         1234,
		Comm:        "test-process",
		SyscallName: "bpf",
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
	adapterFactory := ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok := adapterFactory.GetAdapter(utils.SyscallEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Test without profile - should trigger alert
	ok, err = celEngine.EvaluateRule(eventMap, utils.SyscallEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected bpf syscall")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "bpf system call executed in test" {
		t.Fatalf("Message evaluation failed, got: %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test-process_bpf" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Test with whitelisted bpf syscall in profile
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name:     "test",
			Syscalls: []string{"bpf"},
		})

		objCache.SetApplicationProfile(profile)
	}

	ok, err = celEngine.EvaluateRule(eventMap, utils.SyscallEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since bpf syscall is whitelisted")
	}

	// Test with non-bpf syscall (should not trigger)
	e.SyscallName = "open"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.SyscallEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.SyscallEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for non-bpf syscall")
	}
}

// BenchmarkR0009CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR0009CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("ebpf-program-load.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create a syscall event with bpf syscall
	e := &types.SyscallEvent{
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
		Pid:         1234,
		Comm:        "test-process",
		SyscallName: "bpf",
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
	adapter, ok := adapterFactory.GetAdapter(utils.SyscallEventType)
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
		_, err := celEngine.EvaluateRule(eventMap, utils.SyscallEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
