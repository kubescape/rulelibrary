package r0006_unexpected_service_account_token_access

import (
	"testing"
	"time"

	"github.com/goradd/maps"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	celengine "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/rulelibrary/pkg/common"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// createTestEvent creates a test OpenEvent
func createTestEvent(containerName, containerID, path string, flags []string) *events.OpenEvent {
	return &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID: containerID,
					},
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: containerName,
						},
					},
				},
			},
			Comm:     "test-process",
			Path:     path,
			FullPath: path,
			Flags:    flags,
			Pid:      1234,
			Uid:      0,
			Gid:      0,
		},
	}
}

// createTestProfile creates a test ApplicationProfile
func createTestProfile(containerName string, openCalls []v1beta1.OpenCalls) *v1beta1.ApplicationProfile {
	return &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  containerName,
					Opens: openCalls,
				},
			},
		},
	}
}

func TestR0006UnexpectedServiceAccountTokenAccess(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-service-account-token-access.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		event         *events.OpenEvent
		profile       *v1beta1.ApplicationProfile
		expectTrigger bool
		description   string
	}{
		{
			name:          "non-token path access",
			event:         createTestEvent("test", "container123", "/home/user/file.txt", []string{"O_RDONLY"}),
			expectTrigger: false,
			description:   "Should not trigger for non-service account token paths",
		},
		{
			name:          "kubernetes service account token access without profile",
			event:         createTestEvent("test", "container123", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for service account token access without application profile",
		},
		{
			name:          "var run kubernetes service account token access without profile",
			event:         createTestEvent("test", "container123", "/var/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for var/run service account token access without application profile",
		},
		{
			name:          "eks service account token access without profile",
			event:         createTestEvent("test", "container123", "/run/secrets/eks.amazonaws.com/serviceaccount/token", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for EKS service account token access without application profile",
		},
		{
			name:          "var run eks service account token access without profile",
			event:         createTestEvent("test", "container123", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", []string{"O_RDONLY"}),
			expectTrigger: true,
			description:   "Should trigger for var/run EKS service account token access without application profile",
		},
		{
			name:  "kubernetes service account token access with matching profile",
			event: createTestEvent("test", "container123", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/run/secrets/kubernetes.io/serviceaccount/namespace", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when kubernetes service account path is in application profile",
		},
		{
			name:  "eks service account token access with matching profile",
			event: createTestEvent("test", "container123", "/run/secrets/eks.amazonaws.com/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/run/secrets/eks.amazonaws.com/serviceaccount/ca.crt", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when EKS service account path is in application profile",
		},
		{
			name:  "service account token access with different profile path",
			event: createTestEvent("test", "container123", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/home/user/file.txt", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: true,
			description:   "Should trigger when service account token path is not in application profile",
		},
		{
			name:  "service account namespace access with matching profile",
			event: createTestEvent("test", "container123", "/run/secrets/kubernetes.io/serviceaccount/namespace", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/run/secrets/kubernetes.io/serviceaccount/token", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger when service account directory is whitelisted",
		},
		{
			name:  "similar path but not service account token",
			event: createTestEvent("test", "container123", "/run/secrets/kubernetes.io/other/token", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []v1beta1.OpenCalls{
				{Path: "/run/secrets/kubernetes.io/serviceaccount/token", Flags: []string{"O_RDONLY"}},
			}),
			expectTrigger: false,
			description:   "Should not trigger for paths that look similar but are not service account tokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create object cache
			objCache := &profilevalidator.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("container123", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{
							Name: "test",
						},
					},
				},
			})
			// Set application profile if provided
			if tt.profile != nil {
				objCache.SetApplicationProfile(tt.profile)
			}

			// Create CEL engine
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
			celSerializer := celengine.CelEventSerializer{}
			eventMap := celSerializer.Serialize(tt.event)

			// Evaluate the rule
			triggered, err := celEngine.EvaluateRule(eventMap, utils.OpenEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}

			if triggered != tt.expectTrigger {
				t.Errorf("Test %s failed: expected trigger=%v, got trigger=%v. %s",
					tt.name, tt.expectTrigger, triggered, tt.description)
			}

			// If the rule was triggered, also test message and unique ID generation
			if triggered {
				// Test message evaluation
				message, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.Message)
				if err != nil {
					t.Fatalf("Failed to evaluate message: %v", err)
				}
				expectedMessage := "Unexpected access to service account token: " + tt.event.FullPath + " with flags: " + tt.event.Flags[0]
				if message != expectedMessage {
					t.Errorf("Message evaluation failed. Expected: %s, Got: %s", expectedMessage, message)
				}

				// Test unique ID evaluation
				uniqueID, err := celEngine.EvaluateExpression(eventMap, ruleSpec.Rules[0].Expressions.UniqueID)
				if err != nil {
					t.Fatalf("Failed to evaluate unique ID: %v", err)
				}
				expectedUniqueID := tt.event.Comm
				if uniqueID != expectedUniqueID {
					t.Errorf("Unique ID evaluation failed. Expected: %s, Got: %s", expectedUniqueID, uniqueID)
				}
			}
		})
	}
}

func TestR0006WithTimestampPaths(t *testing.T) {
	// Load rule spec
	ruleSpec, err := common.LoadRuleFromYAML("unexpected-service-account-token-access.yaml")
	if err != nil {
		t.Fatalf("Failed to load rule spec: %v", err)
	}

	tests := []struct {
		name          string
		accessPath    string
		profilePath   string
		expectTrigger bool
		description   string
	}{
		{
			name:          "kubernetes token access with timestamp",
			accessPath:    "/run/secrets/kubernetes.io/serviceaccount/..2024_11_24_09_06_53.3676909075/token",
			profilePath:   "/run/secrets/kubernetes.io/serviceaccount/..2024_11_21_04_30_58.850095521/namespace",
			expectTrigger: false,
			description:   "Should not trigger when service account directory is whitelisted despite different timestamps",
		},
		{
			name:          "eks token access with timestamp",
			accessPath:    "/run/secrets/eks.amazonaws.com/serviceaccount/..2024_11_1111_24_34_58.850095521/token",
			profilePath:   "/run/secrets/eks.amazonaws.com/serviceaccount/..2024_11_21_04_30_58.850095521/ca.crt",
			expectTrigger: false,
			description:   "Should not trigger when EKS service account directory is whitelisted despite different timestamps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create event and profile
			event := createTestEvent("test", "container123", tt.accessPath, []string{"O_RDONLY"})
			profile := createTestProfile("test", []v1beta1.OpenCalls{
				{Path: tt.profilePath, Flags: []string{"O_RDONLY"}},
			})

			// Create object cache and set profile
			objCache := &profilevalidator.RuleObjectCacheMock{
				ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
			}
			objCache.SetSharedContainerData("container123", &objectcache.WatchedContainerData{
				ContainerType: objectcache.Container,
				ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
					objectcache.Container: {
						{
							Name: "test",
						},
					},
				},
			})
			objCache.SetApplicationProfile(profile)

			// Create CEL engine
			celEngine, err := celengine.NewCEL(objCache, config.Config{
				CelConfigCache: cache.FunctionCacheConfig{
					MaxSize: 1000,
					TTL:     1 * time.Microsecond,
				},
			})
			if err != nil {
				t.Fatalf("Failed to create CEL engine: %v", err)
			}

			// Serialize event and evaluate
			celSerializer := celengine.CelEventSerializer{}
			eventMap := celSerializer.Serialize(event)

			triggered, err := celEngine.EvaluateRule(eventMap, utils.OpenEventType, ruleSpec.Rules[0].Expressions.RuleExpression)
			if err != nil {
				t.Fatalf("Failed to evaluate rule: %v", err)
			}

			if triggered != tt.expectTrigger {
				t.Errorf("Test %s failed: expected trigger=%v, got trigger=%v. %s",
					tt.name, tt.expectTrigger, triggered, tt.description)
			}
		})
	}
}
