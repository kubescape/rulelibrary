package r0001unexpectedprocesslaunched

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/events"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"

	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0001UnexpectedProcessLaunched(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-launched.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}
	// Create a process exec event
	e := &utils.StructEvent{
		Args:        []string{"test-process", "arg1"},
		Comm:        "test-process",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		ExePath:     "/usr/bin/test-process",
		Pcomm:       "test-process",
		Pid:         1234,
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
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}

	// Evaluate the rule
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected process launched: test-process with PID 1234" {
		t.Fatalf("Message evaluation failed")
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test-process_/usr/bin/test-process" {
		t.Fatalf("Unique id evaluation failed")
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Create profile
	profile := objCache.GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Execs: []v1beta1.ExecCalls{
				{
					Path: "test-process",
					Args: []string{"test-process", "arg1"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed")
	}
}

// TestR0001ExepathFallback verifies the rule's exepath fallback logic.
//
// parse.get_exec_path(event.args, event.comm) returns argv[0] verbatim, which
// can disagree with the kernel-authoritative event.exepath in two real cases:
//   - relative argv[0] (e.g. "./python") — exepath is the resolved absolute path
//   - empty argv[0] from fexecve / AT_EMPTY_PATH — exepath is the resolved path
//
// The rule now also checks event.exepath (with an empty-string guard) so the
// rule's AP lookup matches the recorder's storage key.
func TestR0001ExepathFallback(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-launched.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	tests := []struct {
		name          string
		event         *utils.StructEvent
		profileExecs  []v1beta1.ExecCalls
		expectTrigger bool
		description   string
	}{
		{
			name: "relative argv[0] suppressed via exepath",
			event: &utils.StructEvent{
				Args:        []string{"./python"},
				Comm:        "python",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/usr/bin/python3",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/python3", Args: []string{"./python"}},
			},
			expectTrigger: false,
			description:   "argv[0]='./python' misses AP, but exepath '/usr/bin/python3' matches",
		},
		{
			name: "empty argv[0] (fexecve) suppressed via exepath",
			event: &utils.StructEvent{
				Args:        []string{"", "root"},
				Comm:        "unix_chkpwd",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/usr/sbin/unix_chkpwd",
				Pcomm:       "sshd",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/sbin/unix_chkpwd", Args: []string{"", "root"}},
			},
			expectTrigger: false,
			description:   "argv[0]='' misses AP, but exepath '/usr/sbin/unix_chkpwd' matches",
		},
		{
			name: "empty exepath fallback guard — argv[0] match suppresses",
			event: &utils.StructEvent{
				Args:        []string{"/usr/bin/foo"},
				Comm:        "foo",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/foo", Args: []string{"/usr/bin/foo"}},
			},
			expectTrigger: false,
			description:   "exepath='' must not poll the AP; argv[0] '/usr/bin/foo' alone suffices to suppress",
		},
		{
			name: "both miss — rule still fires",
			event: &utils.StructEvent{
				Args:        []string{"./newbinary"},
				Comm:        "newbinary",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/tmp/newbinary",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/something-else", Args: []string{"/usr/bin/something-else"}},
			},
			expectTrigger: true,
			description:   "neither argv[0] nor exepath match the AP — must still fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("test", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{Name: "test"},
					},
				},
			})

			profile := &v1beta1.ApplicationProfile{}
			profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
				Name:  "test",
				Execs: tt.profileExecs,
			})
			objCache.SetApplicationProfile(profile)

			celEngine, err := celengine.NewCEL(objCache, config.Config{
				CelConfigCache: cache.FunctionCacheConfig{
					MaxSize: 1000,
					TTL:     1 * time.Microsecond,
				},
			})
			if err != nil {
				t.Fatalf("Failed to create CEL engine: %v", err)
			}

			enrichedEvent := &events.EnrichedEvent{Event: tt.event}

			// Sleep to ensure the cache from prior test runs is expired.
			time.Sleep(1 * time.Millisecond)

			triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}
			if triggered != tt.expectTrigger {
				t.Errorf("expected trigger=%v, got trigger=%v. %s", tt.expectTrigger, triggered, tt.description)
			}
		})
	}
}

func BenchmarkEvaluateRuleNative(b *testing.B) {
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
	e := &utils.StructEvent{
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		Pid:         1234,
		Comm:        "test-process",
		Pcomm:       "test-process",
		ExePath:     "/usr/bin/test-process",
		Args:        []string{"test-process", "arg1"},
	}
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-launched.yaml")
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		_, _ = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	}
}
