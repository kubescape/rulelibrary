package r1008cryptominingdomaincommunication

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"
)

func TestR1008CryptoMiningDomainCommunication(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("crypto-mining-domain-communication.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a DNS event for crypto mining domain communication
	e := &tracerdnstype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
						PodName:       "test-pod",
						Namespace:     "test-namespace",
					},
				},
				Runtime: eventtypes.BasicRuntimeMetadata{
					ContainerID:   "test-container",
					ContainerName: "test",
				},
			},
		},
		DNSName: "xmr.gntl.uk.",
		Comm:    "xmrig",
		Exepath: "/usr/bin/xmrig",
		Pid:     1234,
		Uid:     1000,
		Gid:     1000,
		Ppid:    1,
		Pcomm:   "bash",
		Cwd:     "/tmp",
	}

	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container", &objectcache.WatchedContainerData{
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
	adapter, ok := adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Test with crypto mining domain - should trigger alert
	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected crypto mining domain communication")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Communication with a known crypto mining domain: xmr.gntl.uk."
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "xmr.gntl.uk._xmrig" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Test with different crypto mining domain
	e.DNSName = "pool.minexmr.com."
	e.Comm = "xmr-stak"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected different crypto mining domain")
	}

	// Test with another crypto mining domain
	e.DNSName = "eth.antpool.com."
	e.Comm = "ethminer"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected another crypto mining domain")
	}

	// Test with legitimate domain - should not trigger
	e.DNSName = "google.com"
	e.Comm = "curl"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for legitimate domain")
	}

	// Test with another legitimate domain
	e.DNSName = "github.com"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for legitimate domain")
	}

	// Test with different process but same crypto mining domain
	e.DNSName = "xmr.2miners.com."
	e.Comm = "monero-miner"
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.NetworkEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.DnsEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected crypto mining domain with different process")
	}
}
