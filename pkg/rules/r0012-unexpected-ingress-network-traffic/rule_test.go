package r0012unexpectedingressnetworktraffic

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

func TestR0012UnexpectedIngressNetworkTraffic(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-ingress-network-traffic.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Inbound connection from an unknown internal peer to the container's TCP/8080.
	e := &utils.StructEvent{
		Comm:        "server",
		Container:   "test",
		ContainerID: "test",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "10.244.1.9",
		},
		DstPort:   8080,
		EventType: utils.NetworkEventType,
		Pid:       1234,
		PktType:   "HOST",
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
		t.Fatalf("Rule evaluation failed - should have detected unexpected ingress traffic")
	}

	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Unexpected ingress network communication from: 10.244.1.9:8080 using TCP to: test"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "10.244.1.9_8080_TCP" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Profile ingress: a fixed-address peer on TCP/8080 only, a scraper with no
	// ports (any port), and the frontend tier allowlisted by podSelector on TCP/8080.
	cp := &v1beta1.ContainerProfile{}
	cp.Name = "test"
	cp.Namespace = "prod"
	cp.Spec = v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{
			{
				Identifier: "gateway",
				IPAddress:  "10.244.1.9",
				Ports: []v1beta1.NetworkPort{
					{Name: "TCP-8080", Protocol: "TCP", Port: ptr.To(int32(8080))},
				},
			},
			{
				Identifier: "scraper",
				IPAddress:  "10.244.0.3",
			},
			{
				Identifier:  "frontend",
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
				Ports: []v1beta1.NetworkPort{
					{Name: "TCP-8080", Protocol: "TCP", Port: ptr.To(int32(8080))},
				},
			},
		},
		// Egress entries must not open ingress.
		Egress: []v1beta1.NetworkNeighbor{
			{
				Identifier: "egress-only",
				IPAddress:  "10.244.5.5",
			},
			{
				Identifier:  "egress-only-selector",
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis"}},
			},
		},
	}
	objCache.SetContainerProfile(cp)

	// Allowlisted peer on the allowlisted local port and protocol: no alert.
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since peer:port:proto is allowlisted")
	}

	// Known peer on a port it never used: port-aware matching alerts.
	e.DstPort = 22
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - allowlisted peer on an unlisted port must alert")
	}

	// Known peer, known port, different protocol: alerts.
	e.DstPort = 8080
	e.Proto = "UDP"
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - allowlisted peer on an unlisted protocol must alert")
	}
	e.Proto = "TCP"

	// Peer entry without ports allows any port.
	e.DstEndpoint.Addr = "10.244.0.3"
	e.DstPort = 9100
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since an entry without ports allows any port")
	}

	// Unlisted private peer: no private-IP exemption, alerts.
	e.DstEndpoint.Addr = "10.244.7.7"
	e.DstPort = 8080
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - unlisted private peer must alert (no private-IP exemption)")
	}

	// Egress-only address must not open ingress.
	e.DstEndpoint.Addr = "10.244.5.5"
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - an egress-only address must not allowlist ingress")
	}

	// Unlisted address, but the peer matches an allowlisted ingress podSelector on this port: no alert.
	e.DstEndpoint.Addr = "10.244.3.7"
	e.DstEndpoint.Namespace = "prod"
	e.DstEndpoint.PodLabels = map[string]string{"app": "frontend", "tier": "web"}
	e.DstPort = 8080
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed since the peer matches an allowlisted ingress podSelector")
	}

	// Selector peer on an unlisted port: alerts.
	e.DstPort = 22
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - selector peer on an unlisted port must alert")
	}

	// Selector peer from another namespace (podSelector alone is namespace-local): alerts.
	e.DstPort = 8080
	e.DstEndpoint.Namespace = "other"
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - selector peer in another namespace must alert")
	}

	// Egress-only selector must not open ingress.
	e.DstEndpoint.Namespace = "prod"
	e.DstEndpoint.PodLabels = map[string]string{"app": "redis"}
	if !evaluate() {
		t.Fatalf("Rule evaluation failed - an egress-only selector must not allowlist ingress")
	}

	// Outbound packets are not this rule.
	e.PktType = "OUTGOING"
	if evaluate() {
		t.Fatalf("Rule evaluation should have failed for outgoing packet")
	}
}
