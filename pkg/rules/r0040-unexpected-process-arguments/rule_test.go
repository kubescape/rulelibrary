package r0040unexpectedprocessarguments

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/events"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
)

// recordedExecs is the learned baseline shared by the tests: the binary
// /usr/bin/curl is allowed, and was observed during learning with exactly one
// argv vector. R0040 must stay silent when that vector is replayed and fire
// when /usr/bin/curl is invoked with any other argv.
func recordedExecs() []v1beta1.ExecCalls {
	return []v1beta1.ExecCalls{
		{Path: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "--fail", "https://api.internal/health"}},
	}
}

func newObjCacheWithProfile() *objectcachev1.RuleObjectCacheMock {
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
		Execs: recordedExecs(),
	})
	objCache.SetApplicationProfile(profile)
	return objCache
}

// TestR0040UnexpectedProcessArguments pins the core behavior: a known,
// allowed binary fires only when its argv vector was never recorded.
func TestR0040UnexpectedProcessArguments(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-arguments.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	tests := []struct {
		name          string
		args          []string
		expectTrigger bool
		description   string
	}{
		{
			name:          "matching argv stays silent",
			args:          []string{"/usr/bin/curl", "--fail", "https://api.internal/health"},
			expectTrigger: false,
			description:   "argv matches the only recorded vector for an allowed path — no alert",
		},
		{
			name:          "unexpected argv fires",
			args:          []string{"/usr/bin/curl", "https://evil.example/x"},
			expectTrigger: true,
			description:   "path /usr/bin/curl is allowed, but this argv was never recorded — must fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &utils.StructEvent{
				Args:        tt.args,
				Comm:        "curl",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/usr/bin/curl",
				Pcomm:       "bash",
				Pid:         1234,
			}

			objCache := newObjCacheWithProfile()

			celEngine, err := celengine.NewCEL(objCache, config.Config{
				CelConfigCache: cache.FunctionCacheConfig{
					MaxSize: 1000,
					TTL:     1 * time.Microsecond,
				},
			})
			if err != nil {
				t.Fatalf("Failed to create CEL engine: %v", err)
			}

			enrichedEvent := &events.EnrichedEvent{Event: e}

			// Sleep to ensure any cache from prior runs is expired.
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

// TestR0040UnknownPathStaysSilent verifies the R0001/R0040 boundary: when the
// path itself is not in the profile, R0040 does not fire (that is R0001's job).
func TestR0040UnknownPathStaysSilent(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-arguments.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	e := &utils.StructEvent{
		Args:        []string{"/usr/bin/nmap", "-sS", "10.0.0.0/8"},
		Comm:        "nmap",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		ExePath:     "/usr/bin/nmap",
		Pcomm:       "bash",
		Pid:         1234,
	}

	objCache := newObjCacheWithProfile()

	celEngine, err := celengine.NewCEL(objCache, config.Config{
		CelConfigCache: cache.FunctionCacheConfig{
			MaxSize: 1000,
			TTL:     1 * time.Microsecond,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	enrichedEvent := &events.EnrichedEvent{Event: e}
	time.Sleep(1 * time.Millisecond)

	triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if triggered {
		t.Errorf("R0040 must stay silent for an unknown path (/usr/bin/nmap); that case belongs to R0001")
	}
}

// TestR0040MessageAndUniqueID pins the rendered message and unique id.
func TestR0040MessageAndUniqueID(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-process-arguments.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	e := &utils.StructEvent{
		Args:        []string{"/usr/bin/curl", "https://evil.example/x"},
		Comm:        "curl",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		ExePath:     "/usr/bin/curl",
		Pcomm:       "bash",
		Pid:         1234,
	}

	objCache := newObjCacheWithProfile()

	celEngine, err := celengine.NewCEL(objCache, config.Config{
		CelConfigCache: cache.FunctionCacheConfig{
			MaxSize: 1000,
			TTL:     1 * time.Microsecond,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	enrichedEvent := &events.EnrichedEvent{Event: e}

	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected process arguments: curl with PID 1234 argv=/usr/bin/curl https://evil.example/x" {
		t.Fatalf("Message evaluation failed: %q", message)
	}

	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "curl_/usr/bin/curl_/usr/bin/curl https://evil.example/x" {
		t.Fatalf("Unique id evaluation failed: %q", uniqueId)
	}
}
