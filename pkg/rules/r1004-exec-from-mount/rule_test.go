package r1004execfrommount

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
	corev1 "k8s.io/api/core/v1"
)

func TestR1004ExecFromMount(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("exec-from-mount.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	// Create a mock exec event
	e := &utils.StructEvent{
		Args:        []string{"/var/test1/test", "arg1"},
		Comm:        "/var/test1/test",
		Container:   "test",
		ContainerID: "test-container",
		EventType:   utils.ExecveEventType,
		ExePath:     "/var/test1/test",
		Gid:         1000,
		Namespace:   "test-namespace",
		Pid:         1234,
		Pod:         "test-pod",
		Uid:         1000,
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
	enrichedEvent := &events.EnrichedEvent{
		Event: e,
	}

	// Test without application profile - should trigger alert for exec from mounted path
	ok, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if !ok {
		t.Fatalf("Rule evaluation failed - should have detected exec from mounted path")
	}

	// Evaluate the message
	message, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.Message)
	if err != nil {
		t.Fatalf("Failed to evaluate message: %v", err)
	}
	expectedMessage := "Process (/var/test1/test) was executed from a mounted path"
	if message != expectedMessage {
		t.Fatalf("Message evaluation failed, got: %s, expected: %s", message, expectedMessage)
	}

	// Evaluate the unique id
	uniqueId, err := celEngine.EvaluateExpression(enrichedEvent, ruleSpec.Rules[0].Expressions.UniqueID)
	if err != nil {
		t.Fatalf("Failed to evaluate unique id: %v", err)
	}
	if uniqueId != "/var/test1/test" {
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

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
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

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
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

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
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

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
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

	ok, err = celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
	if err != nil {
		t.Fatalf("Failed to evaluate rule: %v", err)
	}
	if ok {
		t.Fatalf("Rule evaluation should have failed for exec from system path")
	}
}

// TestR1004ExepathFallback verifies the rule's exepath fallback for the AP lookup.
// All cases use mount paths /var/test1 or /var/test2 so the mount clause is satisfied;
// the test isolates the AP lookup behavior. See R0001 ExepathFallback test for full motivation.
func TestR1004ExepathFallback(t *testing.T) {
	ruleSpec, err := common.LoadRuleFromYAML("exec-from-mount.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule: %v", err)
	}

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "test",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "test-volume", MountPath: "/var/test1"},
					{Name: "test-volume-2", MountPath: "/var/test2"},
				},
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "test-volume",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/test1"},
				},
			},
			{
				Name: "test-volume-2",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/test2"},
				},
			},
		},
	}

	tests := []struct {
		name          string
		event         *utils.StructEvent
		profileExecs  []v1beta1.ExecCalls
		expectTrigger bool
		description   string
	}{
		{
			name: "relative argv[0] suppressed via exepath (both under mount)",
			event: &utils.StructEvent{
				Args:        []string{"./python"},
				Comm:        "python",
				Container:   "test",
				ContainerID: "test-container",
				EventType:   utils.ExecveEventType,
				ExePath:     "/var/test1/python3",
				Namespace:   "test-namespace",
				Pid:         1234,
				Pod:         "test-pod",
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/var/test1/python3", Args: []string{"./python"}},
			},
			expectTrigger: false,
			description:   "argv[0]='./python' misses AP, but exepath '/var/test1/python3' matches",
		},
		{
			name: "empty argv[0] (fexecve) suppressed via exepath",
			event: &utils.StructEvent{
				Args:        []string{"", "root"},
				Comm:        "unix_chkpwd",
				Container:   "test",
				ContainerID: "test-container",
				EventType:   utils.ExecveEventType,
				ExePath:     "/var/test1/unix_chkpwd",
				Namespace:   "test-namespace",
				Pid:         1234,
				Pod:         "test-pod",
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/var/test1/unix_chkpwd", Args: []string{"", "root"}},
			},
			expectTrigger: false,
			description:   "argv[0]='' misses AP, but exepath '/var/test1/unix_chkpwd' matches",
		},
		{
			name: "empty exepath fallback guard — argv[0] match suppresses",
			event: &utils.StructEvent{
				Args:        []string{"/var/test2/foo"},
				Comm:        "foo",
				Container:   "test",
				ContainerID: "test-container",
				EventType:   utils.ExecveEventType,
				ExePath:     "",
				Namespace:   "test-namespace",
				Pid:         1234,
				Pod:         "test-pod",
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/var/test2/foo", Args: []string{"/var/test2/foo"}},
			},
			expectTrigger: false,
			description:   "exepath='' must not poll the AP; argv[0] '/var/test2/foo' alone suffices to suppress (mount clause satisfied via argv[0])",
		},
		{
			name: "both miss — rule still fires",
			event: &utils.StructEvent{
				Args:        []string{"./newbinary"},
				Comm:        "newbinary",
				Container:   "test",
				ContainerID: "test-container",
				EventType:   utils.ExecveEventType,
				ExePath:     "/var/test1/newbinary",
				Namespace:   "test-namespace",
				Pid:         1234,
				Pod:         "test-pod",
			},
			profileExecs: []v1beta1.ExecCalls{
				{Path: "/var/test1/something-else", Args: []string{"/var/test1/something-else"}},
			},
			expectTrigger: true,
			description:   "neither argv[0] nor exepath match AP; mount clause satisfied via exepath — must still fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objCache := &objectcachev1.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("test-container", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{Name: "test"},
					},
				},
			})
			objCache.SetPodSpec(podSpec)

			profile := &v1beta1.ApplicationProfile{
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name:  "test",
							Execs: tt.profileExecs,
						},
					},
				},
			}
			objCache.SetApplicationProfile(profile)

			celEngine, err := celengine.NewCEL(objCache, config.Config{
				CelConfigCache: cache.FunctionCacheConfig{
					MaxSize: 1000,
					TTL:     1 * time.Microsecond,
				},
			})
			if err != nil {
				t.Fatalf("Failed to create CEL engine: %v", err)
			}

			enrichedEvent := &events.EnrichedEvent{Event: tt.event}

			time.Sleep(1 * time.Millisecond)

			triggered, err := celEngine.EvaluateRule(enrichedEvent, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}
			if triggered != tt.expectTrigger {
				t.Errorf("expected trigger=%v, got trigger=%v. %s", tt.expectTrigger, triggered, tt.description)
			}
		})
	}
}
