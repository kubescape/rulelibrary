package r1012hardlinkcreatedoversensitivefile

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR1012HardlinkCreatedOverSensitiveFile(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("hardlink-created-over-sensitive-file.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a hardlink event
	e := &tracerhardlinktype.Event{
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
		Comm:    "test",
		OldPath: "test",
		NewPath: "test",
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
	adapter, ok := adapterFactory.GetAdapter(utils.HardlinkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Evaluate the rule - should not trigger for non-sensitive file
	ok, err = celEngine.EvaluateRule(eventMap, utils.HardlinkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should not trigger for non-sensitive file")
	}

	// Test with sensitive file path
	e.OldPath = "/etc/shadow"
	e.NewPath = "/etc/abc"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.HardlinkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.HardlinkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation should trigger for sensitive file")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Hardlink created over sensitive file: /etc/shadow - /etc/abc"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	expectedUniqueId := "test_/etc/shadow"
	if uniqueId != expectedUniqueId {
		t.Fatalf("Unique id evaluation failed. Expected: %s, Got: %s", expectedUniqueId, uniqueId)
	}

	// Test with another sensitive file
	e.OldPath = "/etc/sudoers"
	e.NewPath = "/etc/xyz"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.HardlinkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.HardlinkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation should trigger for /etc/sudoers")
	}

	// Test with non-sensitive file (should not trigger)
	e.OldPath = "/etc/abc"
	e.NewPath = "/etc/xyz"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.HardlinkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.HardlinkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should not trigger for non-sensitive file")
	}

	// Test with profile - since profile is optional, we can test policy validation
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R1012": {
					AllowedProcesses: []string{"/usr/sbin/groupadd"},
				},
			},
		})
	}

	objCache.SetApplicationProfile(profile)

	// Test with whitelisted process
	e.Comm = "/usr/sbin/groupadd"
	e.OldPath = "/etc/shadow"
	e.NewPath = "/etc/abc"

	v := rulemanager.NewRulePolicyValidator(objCache)
	ok, err = v.Validate(ruleSpec.Rules[0].ID, e.Comm, &profile.Spec.Containers[0])
	if err != nil {
		t.Fatalf("Failed to validate rule policy: %v", err)
	}
	if !ok {
		t.Fatalf("Rule policy validation should return true for whitelisted process")
	}
}

// BenchmarkR1012CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR1012CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("hardlink-created-over-sensitive-file.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create a hardlink event for sensitive file
	e := &tracerhardlinktype.Event{
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
		Comm:    "test",
		OldPath: "/etc/shadow",
		NewPath: "/etc/abc",
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
	adapter, ok := adapterFactory.GetAdapter(utils.HardlinkEventType)
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
		_, err := celEngine.EvaluateRule(eventMap, utils.HardlinkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
