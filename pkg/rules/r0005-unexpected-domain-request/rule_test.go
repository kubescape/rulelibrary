package r0005unexpecteddomainrequest

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

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0005UnexpectedDomainRequest(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-domain-request.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a DNS event
	e := &tracerdnstype.Event{
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
		Pid:     1234,
		Comm:    "test-process",
		DNSName: "test.com",
		Qr:      tracerdnstype.DNSPktTypeQuery,
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

	adapter, ok := adapterFactory.GetAdapter(utils.DnsEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter: %v", err)
	}

	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Test without profile - should trigger alert
	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected unexpected domain")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected domain communication: test.com from: test" {
		t.Fatalf("Message evaluation failed, got: %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test-process_test.com" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Test with whitelisted domain in profile
	profile := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test")
	if profile == nil {
		profile = &v1beta1.NetworkNeighborhood{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",
			Egress: []v1beta1.NetworkNeighbor{
				{
					DNSNames: []string{"test.com"},
				},
			},
		})

		objCache.SetNetworkNeighborhood(profile)
	}

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since domain is whitelisted")
	}

	// Test with in-cluster communication (should be ignored)
	e.DNSName = "kubernetes.default.svc.cluster.local."
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for in-cluster communication")
	}
}

// BenchmarkR0005CELEvaluation benchmarks the CEL rule evaluation performance
func BenchmarkR0005CELEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-domain-request.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create a DNS event
	e := &tracerdnstype.Event{
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
		Pid:     1234,
		Comm:    "test-process",
		DNSName: "test.com",
		Qr:      tracerdnstype.DNSPktTypeQuery,
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
	adapter, ok := adapterFactory.GetAdapter(utils.DnsEventType)
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
		_, err := celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
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

// BenchmarkR0005CompleteEventProcessing benchmarks the complete event processing cost
// This gives you the real "cost" of processing one event through the entire pipeline
func BenchmarkR0005CompleteEventProcessing(b *testing.B) {
	// Load rule once outside the loop to simulate production scenario
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-domain-request.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
	}

	// Create CEL engine once outside the loop (like in production)
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
	adapter, ok := adapterFactory.GetAdapter(utils.DnsEventType)
	if !ok {
		b.Fatalf("Failed to get event adapter: %v", err)
	}

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark - each iteration represents processing one complete event
	for i := 0; i < b.N; i++ {
		// Create a new event for each iteration (simulates real event processing)
		e := &tracerdnstype.Event{
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
			Pid:     1234,
			Comm:    "test-process",
			DNSName: "test.com",
			Qr:      tracerdnstype.DNSPktTypeQuery,
		}

		// Convert event to map (this is part of the real cost)
		eventMap := adapter.ToMap(&events.EnrichedEvent{
			Event: e,
		})

		// Evaluate the rule (main cost)
		_, err := celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
		if err != nil {
			b.Fatalf("Failed to evaluate rule: %v", err)
		}

		// Evaluate message and unique ID (part of complete event processing)
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

// BenchmarkR0005SingleRuleEvaluation benchmarks just the rule evaluation cost
// This isolates the CEL evaluation performance from other overhead
func BenchmarkR0005SingleRuleEvaluation(b *testing.B) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-domain-request.yaml")
	if err != nil {
		b.Fatalf("Failed to load rule: %v", err)
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
	adapter, ok := adapterFactory.GetAdapter(utils.DnsEventType)
	if !ok {
		b.Fatalf("Failed to get event adapter: %v", err)
	}

	e := &tracerdnstype.Event{
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
		Pid:     1234,
		Comm:    "test-process",
		DNSName: "test.com",
		Qr:      tracerdnstype.DNSPktTypeQuery,
	}

	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	b.ResetTimer()

	// Only measure the rule evaluation itself
	for i := 0; i < b.N; i++ {
		_, err := celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
		if err != nil {
			b.Fatalf("Failed to evaluate rule: %v", err)
		}
	}
}
