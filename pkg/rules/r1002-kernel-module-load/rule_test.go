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
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
)

// createTestSyscallEvent creates a test SyscallEvent
func createTestSyscallEvent(containerName, containerID, comm, syscallName string, pid uint32) *utils.StructEvent {
	return &utils.StructEvent{
		Container:   containerName,
		ContainerID: containerID,
		Comm:        comm,
		Syscall:     syscallName,
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
		event         *utils.StructEvent
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
							//Name: tt.event.Event.K8s.BasicK8sMetadata.ContainerName,
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
			enrichedEvent := &events.EnrichedEvent{
				EventType: utils.SyscallEventType,
				Event:     tt.event,
			}

			// Evaluate the rule
			triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
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
				message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
				if err != nil {
					t.Fatalf("Failed to evaluate message: %v", err)
				}
				expectedMessage := "Kernel module load syscall (" + tt.event.Syscall + ") was called"
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
				if err != nil {
					t.Fatalf("Failed to evaluate unique ID: %v", err)
				}
				expectedUniqueID := tt.event.Syscall
				if uniqueID != expectedUniqueID {
					t.Errorf("Unique ID evaluation failed. Expected: %s, Got: %s", expectedUniqueID, uniqueID)
				}
			}
		})
	}
}
