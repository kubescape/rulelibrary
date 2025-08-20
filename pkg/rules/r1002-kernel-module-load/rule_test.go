package r1002_kernel_module_load

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
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// createTestSyscallEvent creates a test SyscallEvent
func createTestSyscallEvent(containerName, containerID, comm, syscallName string, pid uint32) *types.SyscallEvent {
	return &types.SyscallEvent{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: containerName,
					},
				},
				Runtime: eventtypes.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
		},
		Comm:        comm,
		SyscallName: syscallName,
		Pid:         pid,
	}
}

func TestR1002KernelModuleLoad(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("kernel-module-load.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		event         *types.SyscallEvent
		expectTrigger bool
		description   string
	}{
		{
			name:          "init_module syscall",
			event:         createTestSyscallEvent("test", "container123", "test-process", "init_module", uint32(1234)),
			expectTrigger: true,
			description:   "Should trigger for init_module syscall",
		},
		{
			name:          "finit_module syscall",
			event:         createTestSyscallEvent("test", "container123", "test-process", "finit_module", uint32(1234)),
			expectTrigger: true,
			description:   "Should trigger for finit_module syscall",
		},
		{
			name:          "other syscall",
			event:         createTestSyscallEvent("test", "container123", "test-process", "open", uint32(1234)),
			expectTrigger: false,
			description:   "Should not trigger for non-kernel-module syscall",
		},
		{
			name:          "other syscall name",
			event:         createTestSyscallEvent("test", "container123", "test-process", "read", uint32(1234)),
			expectTrigger: false,
			description:   "Should not trigger for non-kernel-module syscall",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create object cache
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("container123", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{
							Name: tt.event.Event.K8s.BasicK8sMetadata.ContainerName,
						},
					},
				},
			})

			// Create CEL engine
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
				Event: tt.event,
			})

			// Evaluate the rule
			triggered, err := celEngine.EvaluateRule(eventMap, utils.SyscallEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}

			if triggered != tt.expectTrigger {
				t.Errorf("Test %s failed: expected trigger=%v, got trigger=%v. %s",
					tt.name, tt.expectTrigger, triggered, tt.description)
			}

			// If the rule was triggered, also test message and unique ID generation
			if triggered {
				// Test message evaluation
				message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
				if err != nil {
					t.Fatalf("Failed to evaluate message: %v", err)
				}
				expectedMessage := "Kernel module load syscall (" + tt.event.SyscallName + ") was called"
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
				if err != nil {
					t.Fatalf("Failed to evaluate unique ID: %v", err)
				}
				expectedUniqueID := tt.event.SyscallName
				if uniqueID != expectedUniqueID {
					t.Errorf("Unique ID evaluation failed. Expected: %s, Got: %s", expectedUniqueID, uniqueID)
				}
			}
		})
	}
}

// BenchmarkR1002CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR1002CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("kernel-module-load.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create a syscall event for kernel module load
	e := createTestSyscallEvent("test", "container123", "test-process", "init_module", uint32(1234))

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
