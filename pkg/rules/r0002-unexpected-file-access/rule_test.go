package r0002unexpectedfileaccess

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0002UnexpectedFileAccess(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-file-access.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}
	// Create a file access event
	e := &events.OpenEvent{
		Event: traceropentype.Event{
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
			Pid:      1234,
			Comm:     "test",
			Path:     "/etc/test",
			FullPath: "/etc/test",
			Flags:    []string{"O_RDONLY"},
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
		t.Fatalf("Failed to create CEL engine: %v", err)
	}

	adapterFactory := ruleadapters.NewEventRuleAdapterFactory()

	adapter, ok := adapterFactory.GetAdapter(utils.OpenEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter: %v", err)
	}

	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.OpenEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected file access detected: test with PID 1234 to /etc/test" {
		t.Fatalf("Message evaluation failed %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test_/etc/test" {
		t.Fatalf("Unique id evaluation failed %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Create profile
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Opens: []v1beta1.OpenCalls{
				{
					Path:  "/etc/test",
					Flags: []string{"O_RDONLY"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	ok, err = celEngine.EvaluateRule(eventMap, utils.OpenEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed")
	}
}

// BenchmarkR0002CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR0002CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-file-access.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create a file access event
	e := &events.OpenEvent{
		Event: traceropentype.Event{
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
			Pid:      1234,
			Comm:     "test",
			Path:     "/etc/test",
			FullPath: "/etc/test",
			Flags:    []string{"O_RDONLY"},
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
	adapter, ok := adapterFactory.GetAdapter(utils.OpenEventType)
	if !ok {
		b.Fatalf("Failed to get event adapter: %v", err)
	}

	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		// Benchmark CEL rule evaluation
		_, err := celEngine.EvaluateRule(eventMap, utils.OpenEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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
