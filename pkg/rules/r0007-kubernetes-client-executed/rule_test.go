package r0007kubernetesclientexecuted

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/rulelibrary/pkg/common"
)

func TestR0007KubernetesClientExecuted(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("kubernetes-client-executed.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a kubectl exec event
	e := &utils.StructEvent{
		Args:        []string{"kubectl", "get", "pods"},
		Comm:        "kubectl",
		Container:   "test",
		ContainerID: "test",
		EventType:   utils.ExecveEventType,
		ExePath:     "/usr/bin/kubectl",
		Pcomm:       "test-process",
		Pid:         1234,
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

	// Test without profile - should trigger alert
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected kubectl execution")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Kubernetes client (kubectl) was executed with PID 1234" {
		t.Fatalf("Message evaluation failed, got: %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "exec_kubectl" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Test with whitelisted kubectl in profile
	profile := objCache.GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Execs: []v1beta1.ExecCalls{
				{
					Path: "kubectl",
					Args: []string{"kubectl", "get", "pods"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since kubectl is whitelisted")
	}

	// Test with non-kubectl process (should not trigger)
	e.Comm = "nginx"
	e.ExePath = "/usr/bin/nginx"

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for non-kubectl process")
	}
}

func TestR0007ExepathFallback(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("kubernetes-client-executed.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	tests := []struct {
		name          string
		event         *utils.StructEvent
		profileExecs  []v1beta1.ExecCalls
		expectTrigger bool
		description   string
	}{
		{
			name: "relative argv[0] kubectl — exepath suppresses",
			event: &utils.StructEvent{
				Args:        []string{"./kubectl", "get", "pods"},
				Comm:        "kubectl",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/usr/local/bin/kubectl",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/local/bin/kubectl", Args: []string{"./kubectl", "get", "pods"}},
			},
			expectTrigger: false,
			description:   "argv[0]='./kubectl' must not poll; exepath='/usr/local/bin/kubectl' matches AP entry",
		},
		{
			name: "empty argv[0] (fexecve) kubectl — exepath suppresses",
			event: &utils.StructEvent{
				Args:        []string{"", "get", "pods"},
				Comm:        "kubectl",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/usr/bin/kubectl",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/usr/bin/kubectl", Args: []string{"kubectl", "get", "pods"}},
			},
			expectTrigger: false,
			description:   "fexecve produces empty argv[0]; exepath fallback must catch the AP entry",
		},
		{
			name: "empty exepath fallback guard — argv[0] match suppresses",
			event: &utils.StructEvent{
				Args:        []string{"kubectl", "get", "pods"},
				Comm:        "kubectl",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "kubectl", Args: []string{"kubectl", "get", "pods"}},
			},
			expectTrigger: false,
			description:   "exepath='' must not poll the AP; argv[0] 'kubectl' alone suffices to suppress",
		},
		{
			name: "both miss — rule still fires",
			event: &utils.StructEvent{
				Args:        []string{"./kubectl"},
				Comm:        "kubectl",
				Container:   "test",
				ContainerID: "test",
				EventType:   utils.ExecveEventType,
				ExePath:     "/tmp/kubectl",
				Pcomm:       "bash",
				Pid:         1234,
			},
			profileExecs:  nil,
			expectTrigger: true,
			description:   "neither argv[0] nor exepath in AP — rule must still fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("test", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {{Name: "test"}},
				},
			})

			if tt.profileExecs != nil {
				profile := &v1beta1.ApplicationProfile{
					Spec: v1beta1.ApplicationProfileSpec{
						Containers: []v1beta1.ApplicationProfileContainer{
							{Name: "test", Execs: tt.profileExecs},
						},
					},
				}
				objCache.SetApplicationProfile(profile)
			}

			celEngine, err := celengine.NewCEL(objCache, config.Config{
				CelConfigCache: cache.FunctionCacheConfig{
					MaxSize: 1000,
					TTL:     1 * time.Microsecond,
				},
			})
			if err != nil {
				t.Fatalf("Failed to create CEL engine: %v", err)
			}

			time.Sleep(1 * time.Millisecond)

			enrichedEvent := &events.EnrichedEvent{Event: tt.event}
			triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}
			if triggered != tt.expectTrigger {
				t.Errorf("%s: expected trigger=%v, got=%v. %s",
					tt.name, tt.expectTrigger, triggered, tt.description)
			}
		})
	}
}

func TestR0007KubernetesClientExecutedNetwork(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("kubernetes-client-executed.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	e := &utils.StructEvent{
		Container:   "test",
		ContainerID: "test",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1",
		},
		DstPort:   80,
		EventType: utils.NetworkEventType,
		PktType:   "OUTGOING",
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
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Network connection to Kubernetes API server from container test" {
		t.Fatalf("Message evaluation failed")
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "network_1.1.1.1" {
		t.Fatalf("Unique id evaluation failed")
	}
}
