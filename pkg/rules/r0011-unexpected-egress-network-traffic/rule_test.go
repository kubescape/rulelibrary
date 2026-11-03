package r0011unexpectedegressnetworktraffic

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestR0011UnexpectedEgressNetworkTraffic(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-egress-network-traffic.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	e := &utils.StructEvent{
		Comm:        "curl",
		Container:   "test",
		ContainerID: "test",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1",
		},
		DstPort:   80,
		EventType: utils.NetworkEventType,
		Pid:       1234,
		PktType:   "OUTGOING",
		Proto:     "TCP",
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

	evaluate := func() bool {
		t.Helper()
		time.Sleep(1 * time.Millisecond) // expire the function cache
		ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
		if err != nil {
			t.Fatalf("Failed to evaluate rule: %v", err)
		}
		return ok
	}

	// No profile: nothing is allowlisted, the connection alerts.
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - should have detected unexpected egress traffic")
	}

	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Unexpected egress network communication to: 1.1.1.1:80 using TCP from: test"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "1.1.1.1_80_TCP" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Profile: 1.1.1.1 on TCP/80 only, 10.0.0.50 with no ports (any port),
	// and an internal peer allowlisted by podSelector on TCP/6379.
	cp := &v1beta1.ContainerProfile{}
	cp.Name = "test"
	cp.Namespace = "prod"
	cp.Spec = v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{
			{
				Identifier: "cloudflare",
				IPAddress:  "1.1.1.1",
				DNSNames:   []string{"cloudflare.com"},
				Ports: []v1beta1.NetworkPort{
					{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
				},
			},
			{
				Identifier: "any-port-peer",
				IPAddress:  "10.0.0.50",
			},
			{
				Identifier:  "redis",
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis"}},
				Ports: []v1beta1.NetworkPort{
					{Name: "TCP-6379", Protocol: "TCP", Port: ptr.To(int32(6379))},
				},
			},
		},
	}
	objCache.SetContainerProfile(cp)

	// Allowlisted address on its allowlisted port and protocol: no alert.
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since address:port:proto is allowlisted")
	}

	// Same address, different port: port-aware matching alerts.
	e.DstPort = 443
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - allowlisted address on an unlisted port must alert")
	}

	// Same address and port, different protocol: alerts.
	e.DstPort = 80
	e.Proto = "UDP"
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - allowlisted address on an unlisted protocol must alert")
	}
	e.Proto = "TCP"

	// Address entry without ports allows any port.
	e.DstEndpoint.Addr = "10.0.0.50"
	e.DstPort = 9999
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since an entry without ports allows any port")
	}

	// Private, unlisted internal address: no private-IP exemption, alerts.
	e.DstEndpoint.Addr = "10.0.0.1"
	e.DstPort = 80
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - unlisted private address must alert (no private-IP exemption)")
	}

	// Unlisted address but the peer matches an allowlisted podSelector on its port: no alert.
	e.DstEndpoint.Addr = "10.244.3.7"
	e.DstEndpoint.Namespace = "prod"
	e.DstEndpoint.PodLabels = map[string]string{"app": "redis", "tier": "cache"}
	e.DstPort = 6379
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since the peer matches an allowlisted podSelector")
	}

	// Selector match on an unlisted port: alerts.
	e.DstPort = 22
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - selector peer on an unlisted port must alert")
	}

	// Selector match from a different namespace (podSelector alone is namespace-local): alerts.
	e.DstPort = 6379
	e.DstEndpoint.Namespace = "other"
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - selector peer in another namespace must alert")
	}

	// Labels that do not match any selector: alerts.
	e.DstEndpoint.Namespace = "prod"
	e.DstEndpoint.PodLabels = map[string]string{"app": "other"}
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - peer with non-matching labels must alert")
	}

	// Incoming packet: not this rule.
	e.PktType = "INCOMING"
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed for incoming packet")
	}
	e.PktType = "HOST"
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed for ingress (HOST) packet")
	}
}
