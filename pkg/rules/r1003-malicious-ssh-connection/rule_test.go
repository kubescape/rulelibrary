package r1003malicioussshconnection

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/utils"
	common "github.com/kubescape/rulelibrary/pkg/common"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR1003MaliciousSSHConnection(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("malicious-ssh-connection.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a mock SSH event for outgoing connection to disallowed port
	e := &tracersshtype.Event{
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
		SrcIP:   "192.168.1.100",
		DstIP:   "1.1.1.1",
		SrcPort: 33333, // Ephemeral port
		DstPort: 1234,  // Disallowed port
		Comm:    "ssh",
		Pid:     1234,
		Uid:     1000,
		Gid:     1000,
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

	celSerializer := celengine.CelEventSerializer{}
	eventMap := celSerializer.Serialize(e)

	// Test without network neighborhood - should trigger alert for disallowed port
	ok, err := celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected malicious SSH connection to disallowed port")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Malicious SSH connection attempt to 1.1.1.1:1234"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "ssh_1.1.1.1_1234" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Test with allowed port (22) - should not trigger
	e.DstPort = 22
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for allowed port 22")
	}

	// Test with another allowed port (2022) - should not trigger
	e.DstPort = 2022
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for allowed port 2022")
	}

	// Test with non-ephemeral source port - should not trigger
	e.DstPort = 1234 // Disallowed port
	e.SrcPort = 22   // Non-ephemeral port
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for non-ephemeral source port")
	}

	// Test with whitelisted address in network neighborhood
	e.SrcPort = 33333 // Ephemeral port
	e.DstPort = 1234  // Disallowed port
	e.DstIP = "2.2.2.2"

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
					IPAddress: "2.2.2.2",
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since address is whitelisted in network neighborhood")
	}

	// Test with non-whitelisted address
	e.DstIP = "3.3.3.3"
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected malicious SSH connection to non-whitelisted address")
	}

	// Test with different disallowed port
	e.DstPort = 2222
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected malicious SSH connection to different disallowed port")
	}

	// Test with different process name
	e.Comm = "openssh"
	e.DstPort = 1234
	eventMap = celSerializer.Serialize(e)

	ok, err = celEngine.EvaluateRule(eventMap, utils.SSHEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected malicious SSH connection with different process name")
	}
}
