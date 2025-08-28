package r0008_read_environment_variables_procfs

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// createTestEvent creates a test OpenEvent
func createTestEvent(containerName, containerID, path string, flags []string) *events.OpenEvent {
	return &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID: containerID,
					},
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: containerName,
						},
					},
				},
			},
			Comm:     "test-process",
			Path:     path,
			FullPath: path,
			Flags:    flags,
			Pid:      1234,
			Uid:      0,
			Gid:      0,
		},
	}
}

// createTestProfile creates a test ApplicationProfile
func createTestProfile(containerName string, openCalls []v1beta1.OpenCalls) *v1beta1.ApplicationProfile {
	return &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  containerName,
					Opens: openCalls,
				},
			},
		},
	}
}

func TestR0008ReadEnvironmentVariablesProcFS(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("read-environment-variables-procfs.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		event         *events.OpenEvent
		profile       *v1beta1.ApplicationProfile
		expectTrigger bool
		description   string
	}{
		{
			name:          "non-procfs file access",
			event:         createTestEvent("test", "container123", "/home/user/file.txt", []string{"O_RDONLY"}),
			expectTrigger: false,
			description:   "Should not trigger for non-procfs paths",
		},
		{
			name:          "procfs non-environ file access",
			event:         createTestEvent("test", "container123", "/proc/1/cmdline", []string{"O_RDONLY"}),
			expectTrigger: false,
			description:   "Should not trigger for procfs files that are not environ",
		},
		{
			name:          "procfs environ access without profile",
			event:         createTestEvent("test", "container123", "/proc/1/environ", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for procfs environ access without application profile",
		},
		{
			name:          "procfs environ access with different PID without profile",
			event:         createTestEvent("test", "container123", "/proc/12345/environ", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for any PID environ access without application profile",
		},
		{
			name:  "procfs environ access with matching profile",
			event: createTestEvent("test", "container123", "/proc/1/environ", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/proc/1234/environ", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when procfs environ access is in application profile",
		},
		{
			name:  "procfs environ access with dynamic identifier profile",
			event: createTestEvent("test", "container123", "/proc/567/environ", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/proc/" + dynamicpathdetector.DynamicIdentifier + "/environ", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when procfs environ access with dynamic identifier is in application profile",
		},
		{
			name:  "procfs environ access with non-matching profile",
			event: createTestEvent("test", "container123", "/proc/1/environ", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/home/user/file.txt", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: true,
			description:   "Should trigger when procfs environ path is not in application profile",
		},
		{
			name:  "procfs environ access with procfs non-environ profile",
			event: createTestEvent("test", "container123", "/proc/1/environ", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/proc/1/cmdline", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: true,
			description:   "Should trigger when only non-environ procfs files are in application profile",
		},
		{
			name:          "different container name",
			event:         createTestEvent("test2", "container123", "/proc/1/environ", []string{"O_RDONLY"}),
			profile:       createTestProfile("test", []v1beta1.OpenCalls{{Path: "/proc/1/environ", Flags: []string{"O_RDONLY"}}}),
			expectTrigger: false,
			description:   "Should not trigger when no profile exists for the container",
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
							Name: "test",
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
				EventType: utils.OpenEventType,
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
				expectedMessage := "Reading environment variables from procfs: " + tt.event.FullPath + " by process " + tt.event.Comm
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
				if err != nil {
					t.Fatalf("Failed to evaluate unique ID: %v", err)
				}
				expectedUniqueID := tt.event.Comm
				if uniqueID != expectedUniqueID {
					t.Errorf("Unique ID evaluation failed. Expected: %s, Got: %s", expectedUniqueID, uniqueID)
				}
			}
		})
	}
}

func TestR0008VariousProcFSPaths(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("read-environment-variables-procfs.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		path          string
		expectTrigger bool
		description   string
	}{
		{
			name:          "simple proc environ",
			path:          "/proc/1/environ",
			expectTrigger: true,
			description:   "Should trigger for /proc/1/environ",
		},
		{
			name:          "multi-digit PID environ",
			path:          "/proc/12345/environ",
			expectTrigger: true,
			description:   "Should trigger for multi-digit PID environ",
		},
		{
			name:          "proc self environ",
			path:          "/proc/self/environ",
			expectTrigger: true,
			description:   "Should trigger for /proc/self/environ",
		},
		{
			name:          "proc path not environ",
			path:          "/proc/1/cmdline",
			expectTrigger: false,
			description:   "Should not trigger for non-environ procfs files",
		},
		{
			name:          "environ but not proc",
			path:          "/home/user/environ",
			expectTrigger: false,
			description:   "Should not trigger for environ files outside procfs",
		},
		{
			name:          "contains proc but wrong path",
			path:          "/home/proc/1/environ",
			expectTrigger: false,
			description:   "Should not trigger for paths containing proc but not starting with /proc/",
		},
		{
			name:          "proc environ with subdirectory",
			path:          "/proc/1/task/2/environ",
			expectTrigger: true,
			description:   "Should trigger for environ in task subdirectories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create event
			event := createTestEvent("test", "container123", tt.path, []string{"O_RDONLY"})

			// Create object cache without profile (to test basic detection)
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("container123", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{
							Name: "test",
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
				EventType: utils.OpenEventType,
				Event:     event,
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
