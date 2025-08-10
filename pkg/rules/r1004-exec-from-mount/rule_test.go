package r1004execfrommount

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
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
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

func TestR1004ExecFromMount(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("exec-from-mount.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a mock exec event
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
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
			Comm:    "/var/test1/test",
			ExePath: "/var/test1/test",
			Args:    []string{"/var/test1/test", "arg1"},
			Pid:     1234,
			Uid:     1000,
			Gid:     1000,
		},
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

	// Set up pod spec with mounted volume
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "test",
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "test-volume",
						MountPath: "/var/test1",
					},
					{
						Name:      "test-volume-2",
						MountPath: "/var/test2",
					},
				},
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "test-volume",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/test1",
					},
				},
			},
			{
				Name: "test-volume-2",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/test2",
					},
				},
			},
		},
	}

	objCache.SetPodSpec(podSpec)

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
	adapter, ok := adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap := adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	// Test without application profile - should trigger alert for exec from mounted path
	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected exec from mounted path")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Process (/var/test1/test) was executed from a mounted path"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "/var/test1/test_/var/test1/test_" {
		t.Fatalf("Unique id evaluation failed, got: %s", uniqueId)
	}

	// Test with application profile that whitelists the exec
	profile := &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "test",
					Execs: []v1beta1.ExecCalls{
						{
							Path: "/var/test1/test",
							Args: []string{"/var/test1/test", "arg1"},
						},
					},
				},
			},
		},
	}

	objCache.SetApplicationProfile(profile)

	// Sleep for 1 millisecond to make sure the cache is expired
	time.Sleep(1 * time.Millisecond)

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed since exec is whitelisted in application profile")
	}

	// Test with different exec path that is not mounted
	e.Comm = "/usr/bin/ls"
	e.ExePath = "/usr/bin/ls"
	e.Args = []string{"/usr/bin/ls", "-la"}
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for exec not from mounted path")
	}

	// Test with exec from different mounted path
	e.Comm = "/var/test2/another"
	e.ExePath = "/var/test2/another"
	e.Args = []string{"/var/test2/another"}
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected exec from different mounted path")
	}

	// Test with exec from subdirectory of mounted path
	e.Comm = "/var/test1/subdir/script"
	e.ExePath = "/var/test1/subdir/script"
	e.Args = []string{"/var/test1/subdir/script"}
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected exec from subdirectory of mounted path")
	}

	// Test with exec from system path (not mounted)
	e.Comm = "/bin/bash"
	e.ExePath = "/bin/bash"
	e.Args = []string{"/bin/bash", "-c", "echo hello"}
	// Serialize event
	adapterFactory = ruleadapters.NewEventRuleAdapterFactory()
	adapter, ok = adapterFactory.GetAdapter(utils.ExecveEventType)
	if !ok {
		t.Fatalf("Failed to get event adapter")
	}
	eventMap = adapter.ToMap(&events.EnrichedEvent{
		Event: e,
	})

	ok, err = celEngine.EvaluateRule(eventMap, utils.ExecveEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for exec from system path")
	}
}
