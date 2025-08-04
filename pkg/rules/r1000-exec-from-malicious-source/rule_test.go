package r1000_exec_from_malicious_source

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
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
)

// createTestExecEvent creates a test ExecEvent
func createTestExecEvent(containerName, containerID, comm, exePath, cwd string, args []string) *events.ExecEvent {
	return &events.ExecEvent{
		Event: tracerexectype.Event{
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
			Comm:    comm,
			ExePath: exePath,
			Cwd:     cwd,
			Args:    args,
			Pid:     1234,
			Ppid:    123,
			Pcomm:   "parent-process",
			Uid:     0,
			Gid:     0,
		},
	}
}

func TestR1000ExecFromMaliciousSource(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("exec-from-malicious-source.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		event         *events.ExecEvent
		expectTrigger bool
		description   string
	}{
		{
			name:          "normal execution",
			event:         createTestExecEvent("test", "container123", "/test", "/usr/bin/test", "/", []string{"/usr/bin/test"}),
			expectTrigger: false,
			description:   "Should not trigger for normal execution paths",
		},
		{
			name:          "execution from /bin",
			event:         createTestExecEvent("test", "container123", "/run.sh", "/bin/sh", "/", []string{"/bin/sh", "/run.sh"}),
			expectTrigger: false,
			description:   "Should not trigger for execution from legitimate system paths",
		},
		{
			name:          "execution with ExePath from /dev/shm",
			event:         createTestExecEvent("test", "container123", "malicious", "/dev/shm/malicious", "/", []string{"/dev/shm/malicious"}),
			expectTrigger: true,
			description:   "Should trigger when ExePath starts with /dev/shm",
		},
		{
			name:          "execution with Cwd in /dev/shm",
			event:         createTestExecEvent("test", "container123", "./run.sh", "/bin/sh", "/dev/shm", []string{"/bin/sh", "./run.sh"}),
			expectTrigger: true,
			description:   "Should trigger when current working directory is /dev/shm",
		},
		{
			name:          "execution with args path from /dev/shm",
			event:         createTestExecEvent("test", "container123", "/dev/shm/run.sh", "/dev/shm/run.sh", "/", []string{"/dev/shm/run.sh"}),
			expectTrigger: true,
			description:   "Should trigger when ExePath starts with /dev/shm",
		},
		{
			name:          "execution with relative path in /dev/shm cwd",
			event:         createTestExecEvent("test", "container123", "./run.sh", "/bin/sh", "/dev/shm", []string{"/bin/sh", "./run.sh"}),
			expectTrigger: true,
			description:   "Should trigger when executing relative path in /dev/shm directory",
		},
		{
			name:          "legitimate motd execution",
			event:         createTestExecEvent("test", "container123", "50-motd-news", "/bin/sh", "/", []string{"/bin/sh", "/etc/update-motd.d/50-motd-news", "--force"}),
			expectTrigger: false,
			description:   "Should not trigger for legitimate system processes like motd",
		},
		{
			name:          "execution with /dev/shm in subdirectory",
			event:         createTestExecEvent("test", "container123", "script", "/dev/shm/subdir/script", "/", []string{"/dev/shm/subdir/script"}),
			expectTrigger: true,
			description:   "Should trigger for executions from /dev/shm subdirectories",
		},
		{
			name:          "execution with cwd /dev/shm subdirectory",
			event:         createTestExecEvent("test", "container123", "./test", "/usr/bin/test", "/dev/shm/temp", []string{"/usr/bin/test", "./test"}),
			expectTrigger: true,
			description:   "Should trigger when cwd is a subdirectory of /dev/shm",
		},
		{
			name:          "execution containing dev/shm but not starting with it",
			event:         createTestExecEvent("test", "container123", "test", "/home/user/dev/shm/test", "/", []string{"/home/user/dev/shm/test"}),
			expectTrigger: false,
			description:   "Should not trigger for paths containing but not starting with /dev/shm",
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
			celSerializer := celengine.CelEventSerializer{}
			eventMap := celSerializer.Serialize(tt.event)

			// Evaluate the rule
			triggered, err := celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
				expectedMessage := "Execution from malicious source: " + tt.event.ExePath + " in directory " + tt.event.Cwd
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
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

func TestR1000MaliciousPathVariants(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("exec-from-malicious-source.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		exePath       string
		cwd           string
		args          []string
		expectTrigger bool
		description   string
	}{
		{
			name:          "dev shm exact match",
			exePath:       "/dev/shm/script",
			cwd:           "/",
			args:          []string{"/dev/shm/script"},
			expectTrigger: true,
			description:   "Should trigger for exact /dev/shm path",
		},
		{
			name:          "dev shm with trailing content",
			exePath:       "/dev/shm_fake/script",
			cwd:           "/",
			args:          []string{"/dev/shm_fake/script"},
			expectTrigger: false,
			description:   "Should not trigger for similar but different paths",
		},
		{
			name:          "cwd in dev shm",
			exePath:       "/usr/bin/script",
			cwd:           "/dev/shm",
			args:          []string{"/usr/bin/script"},
			expectTrigger: true,
			description:   "Should trigger when cwd is /dev/shm",
		},
		{
			name:          "cwd similar to dev shm",
			exePath:       "/usr/bin/script",
			cwd:           "/dev/shm_temp",
			args:          []string{"/usr/bin/script"},
			expectTrigger: false,
			description:   "Should not trigger for cwd similar to but not /dev/shm",
		},
		{
			name:          "args path in dev shm",
			exePath:       "/bin/sh",
			cwd:           "/",
			args:          []string{"/bin/sh", "/dev/shm/malicious.sh"},
			expectTrigger: false,
			description:   "Should not trigger when only script argument path is in /dev/shm (not checking args)",
		},
		{
			name:          "multiple malicious conditions",
			exePath:       "/dev/shm/exe",
			cwd:           "/dev/shm",
			args:          []string{"/dev/shm/exe"},
			expectTrigger: true,
			description:   "Should trigger when multiple conditions match /dev/shm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create event
			event := createTestExecEvent("test", "container123", "test-process", tt.exePath, tt.cwd, tt.args)

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
			celSerializer := celengine.CelEventSerializer{}
			eventMap := celSerializer.Serialize(event)

			triggered, err := celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
