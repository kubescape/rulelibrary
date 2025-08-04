package r0011unexpectedegressnetworktraffic

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0011UnexpectedEgressNetworkTraffic(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-egress-network-traffic.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a network event for outgoing traffic to external IP
	e := &tracernetworktype.Event{
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
		PktType: "OUTGOING",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1", // External IP
		},
		Port:  80,
		Proto: "TCP",
		Comm:  "curl",
		Pid:   1234,
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

	celSerializer := celengine.CelEventSerializer{}
	eventMap := celSerializer.Serialize(e)

	// Test without network neighborhood - should trigger alert
	ok, err := celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected unexpected egress traffic")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Unexpected egress network communication to: 1.1.1.1:80 using TCP from: test"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "1.1.1.1_80_TCP" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Test with whitelisted address in network neighborhood
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test")
	if nn == nil {
		nn = &v1beta1.NetworkNeighborhood{}
		nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",
			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS:       "cloudflare.com",
					DNSNames:  []string{"cloudflare.com"},
					IPAddress: "1.1.1.1",
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since address is whitelisted in network neighborhood")
	}

	// Test with non-whitelisted address
	e.DstEndpoint.Addr = "2.2.2.2"
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected unexpected egress traffic to non-whitelisted address")
	}

	// Test with incoming packet (should not trigger)
	e.PktType = "INCOMING"
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for incoming packet")
	}

	// Test with private IP address (should not trigger)
	e.PktType = "OUTGOING"
	e.DstEndpoint.Addr = "10.0.0.1" // Private IP
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for private IP address")
	}

	// Test with different port and protocol
	e.DstEndpoint.Addr = "3.3.3.3" // External IP
	e.Port = 443
	e.Proto = "TCP"
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected unexpected egress traffic on different port")
	}

	// Test with UDP protocol
	e.Proto = "UDP"
	e.Port = 53
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.NetworkEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected unexpected egress traffic with UDP")
	}
}
