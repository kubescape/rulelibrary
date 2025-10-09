package r0004unexpectedcapabilityused

import (
	"testing"
	"time"

	"github.com/goradd/maps"
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

func TestR0004UnexpectedCapabilityUsed(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-capability-used.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a capabilities event
	e := &utils.StructEvent{
		Container:   "test",
		ContainerID: "test",
		Comm:        "test",
		CapName:     "test_cap",
		Syscall:     "test_syscall",
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
		EventType: utils.CapabilitiesEventType,
		Event:     e,
	}

	// Evaluate the rule
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	if message != "Unexpected capability used: test_cap in syscall test_syscall with PID 1234" {
		t.Fatalf("Message evaluation failed: %s", message)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "test_test_cap" {
		t.Fatalf("Unique id evaluation failed: %s", uniqueId)
	}

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	// Create profile
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Capabilities: []string{
				"test_cap",
			},
		})
	}

	objCache.SetApplicationProfile(profile)

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed")
	}
}
