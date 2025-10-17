package r1001_exec_binary_not_in_base_image

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
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// createTestExecEvent creates a test ExecEvent
func createTestExecEvent(containerName, containerID, comm, exePath, cwd string, args []string, upperLayer, pupperLayer bool) *utils.StructEvent {
	return &utils.StructEvent{
		Args:        args,
		Comm:        comm,
		Container:   containerName,
		ContainerID: containerID,
		Cwd:         cwd,
		EventType:   utils.ExecveEventType,
		ExePath:     exePath,
		Gid:         0,
		Pcomm:       "parent-process",
		Pid:         1234,
		Ppid:        123,
		PupperLayer: pupperLayer,
		Uid:         0,
		UpperLayer:  upperLayer,
	}
}

// createTestProfile creates a test ApplicationProfile
func createTestProfile(containerName string, execCalls []v1beta1.ExecCalls) *v1beta1.ApplicationProfile {
	return &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  containerName,
					Execs: execCalls,
				},
			},
		},
	}
}

func TestR1001ExecBinaryNotInBaseImage(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("exec-binary-not-in-base-image.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		event         *utils.StructEvent
		profile       *v1beta1.ApplicationProfile
		expectTrigger bool
		description   string
	}{
		{
			name:          "execution from base image",
			event:         createTestExecEvent("test", "container123", "/bin/ls", "/bin/ls", "/", []string{"/bin/ls", "-la"}, false, false),
			expectTrigger: false,
			description:   "Should not trigger for executions from base image (UpperLayer=false, PupperLayer=false)",
		},
		{
			name:          "execution from upper layer",
			event:         createTestExecEvent("test", "container123", "/tmp/malicious", "/tmp/malicious", "/", []string{"/tmp/malicious"}, true, false),
			expectTrigger: true,
			description:   "Should trigger for executions from upper layer (UpperLayer=true)",
		},
		{
			name:          "execution with parent from upper layer",
			event:         createTestExecEvent("test", "container123", "/usr/bin/legitimate", "/usr/bin/legitimate", "/", []string{"/usr/bin/legitimate"}, false, true),
			expectTrigger: true,
			description:   "Should trigger for executions with parent from upper layer (PupperLayer=true)",
		},
		{
			name:          "execution with both upper layer flags",
			event:         createTestExecEvent("test", "container123", "/opt/malicious", "/opt/malicious", "/", []string{"/opt/malicious"}, true, true),
			expectTrigger: true,
			description:   "Should trigger for executions with both upper layer flags set",
		},
		{
			name:  "execution from upper layer with profile",
			event: createTestExecEvent("test", "container123", "/tmp/whitelisted", "/tmp/whitelisted", "/", []string{"/tmp/whitelisted"}, true, false),
			profile: createTestProfile("test", []v1beta1.ExecCalls{
				{Path: "/tmp/whitelisted", Args: []string{"/tmp/whitelisted"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when upper layer execution is whitelisted in profile",
		},
		{
			name:  "execution from base image with profile",
			event: createTestExecEvent("test", "container123", "/bin/ls", "/bin/ls", "/", []string{"/bin/ls", "-la"}, false, false),
			profile: createTestProfile("test", []v1beta1.ExecCalls{
				{Path: "/bin/ls", Args: []string{"/bin/ls", "-la"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger for base image execution even with profile",
		},
		{
			name:  "execution from upper layer with non-matching profile",
			event: createTestExecEvent("test", "container123", "/tmp/malicious", "/tmp/malicious", "/", []string{"/tmp/malicious"}, true, false),
			profile: createTestProfile("test", []v1beta1.ExecCalls{
				{Path: "/bin/ls", Args: []string{"/bin/ls"}},
			}),
			expectTrigger: true,
			description:   "Should trigger when upper layer execution is not in profile",
		},
		{
			name:          "different container name",
			event:         createTestExecEvent("test2", "container123", "/tmp/malicious", "/tmp/malicious", "/", []string{"/tmp/malicious"}, true, false),
			profile:       createTestProfile("test", []v1beta1.ExecCalls{{Path: "/tmp/malicious", Args: []string{"/tmp/malicious"}}}),
			expectTrigger: true,
			description:   "Should trigger when no profile exists for the container",
		},
		{
			name:          "no application profile",
			event:         createTestExecEvent("test", "container123", "/tmp/malicious", "/tmp/malicious", "/", []string{"/tmp/malicious"}, true, false),
			profile:       nil,
			expectTrigger: true,
			description:   "Should trigger for upper layer execution without application profile",
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
							Name: tt.event.Container,
						},
					},
				},
			})

			// Set application profile if provided
			if tt.profile != nil {
				objCache.SetApplicationProfile(tt.profile)
			}

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
				Event: tt.event,
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
				expectedMessage := "Process (" + tt.event.Comm + ") was executed and is not part of the image"
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
				if err != nil {
					t.Fatalf("Failed to evaluate unique ID: %v", err)
				}
				expectedUniqueID := tt.event.Comm + "_" + tt.event.ExePath + "_" + tt.event.Pcomm
				if uniqueID != expectedUniqueID {
					t.Errorf("Unique ID evaluation failed. Expected: %s, Got: %s", expectedUniqueID, uniqueID)
				}
			}
		})
	}
}

func TestR1001UpperLayerVariants(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("exec-binary-not-in-base-image.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		upperLayer    bool
		pupperLayer   bool
		expectTrigger bool
		description   string
	}{
		{
			name:          "both flags false",
			upperLayer:    false,
			pupperLayer:   false,
			expectTrigger: false,
			description:   "Should not trigger when both upper layer flags are false",
		},
		{
			name:          "only upperLayer true",
			upperLayer:    true,
			pupperLayer:   false,
			expectTrigger: true,
			description:   "Should trigger when only UpperLayer is true",
		},
		{
			name:          "only pupperLayer true",
			upperLayer:    false,
			pupperLayer:   true,
			expectTrigger: true,
			description:   "Should trigger when only PupperLayer is true",
		},
		{
			name:          "both flags true",
			upperLayer:    true,
			pupperLayer:   true,
			expectTrigger: true,
			description:   "Should trigger when both upper layer flags are true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create event
			event := createTestExecEvent("test", "container123", "test-process", "/tmp/test", "/", []string{"/tmp/test"}, tt.upperLayer, tt.pupperLayer)

			// Create object cache
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("container123", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{
							Name: event.Container,
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

			// Serialize event and evaluate
			enrichedEvent := &events.EnrichedEvent{
				Event: event,
			}

			triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}

			if triggered != tt.expectTrigger {
				t.Errorf("Test %s failed: expected trigger=%v, got trigger=%v. %s",
					tt.name, tt.expectTrigger, triggered, tt.description)
			}
		})
	}
}
