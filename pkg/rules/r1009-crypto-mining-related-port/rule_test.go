package r1009cryptominingrelatedport

import (
	"testing"
	"time"

	"github.com/goradd/maps"
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
)

func TestR1009CryptoMiningRelatedPort(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("crypto-mining-related-port.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a network event for crypto mining port communication
	e := &utils.StructEvent{
		Comm:        "xmrig",
		Container:   "test",
		ContainerID: "test-container",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1",
		},
		DstPort:   3333,
		EventType: utils.NetworkEventType,
		Gid:       1000,
		Namespace: "test-namespace",
		Pid:       1234,
		PktType:   "OUTGOING",
		Pod:       "test-pod",
		Proto:     "TCP",
		Uid:       1000,
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
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}

	// Test with crypto mining port - should trigger alert
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected crypto mining port communication")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Detected crypto mining related port communication on port 3333 to 1.1.1.1 with protocol TCP"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "xmrig_3333" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Test with different crypto mining port
	e.DstPort = 45700
	e.Comm = "xmr-stak"
	e.DstEndpoint.Addr = "2.2.2.2"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected different crypto mining port")
	}

	// Test with non-crypto mining port - should not trigger
	e.DstPort = 80
	e.Comm = "curl"
	e.DstEndpoint.Addr = "3.3.3.3"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for non-crypto mining port")
	}

	// Test with UDP protocol - should not trigger
	e.DstPort = 3333
	e.Proto = "UDP"
	e.Comm = "xmrig"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for UDP protocol")
	}

	// Test with incoming packet - should not trigger
	e.Proto = "TCP"
	e.PktType = "INCOMING"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for incoming packet")
	}

	// Test with whitelisted address in network neighborhood
	e.PktType = "OUTGOING"
	e.DstPort = 3333
	e.DstEndpoint.Addr = "4.4.4.4"

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test-container")
	if nn == nil {
		nn = &v1beta1.NetworkNeighborhood{}
		nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",
			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS:       "test.com",
					DNSNames:  []string{"test.com"},
					IPAddress: "4.4.4.4",
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since address is whitelisted in network neighborhood")
	}

	// Test with non-whitelisted address
	e.DstEndpoint.Addr = "5.5.5.5"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected crypto mining port communication to non-whitelisted address")
	}
}
