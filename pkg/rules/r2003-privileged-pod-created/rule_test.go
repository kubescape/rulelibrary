package r2003privilegedpodcreated

import (
	"strings"
	"testing"

	"github.com/kubescape/rulelibrary/pkg/common"
)

func podCreate(ns, spec string) common.AdmissionEvent {
	return common.AdmissionEvent{Kind: "Pod", Name: "p1", Namespace: ns, Operation: "CREATE", Resource: "pods", Username: "alice",
		Object: common.JSONObject(`{"metadata":{"name":"p1","namespace":"` + ns + `","ownerReferences":[{"kind":"ReplicaSet","name":"web-abc"}]},"spec":` + spec + `}`)}
}

func TestR2003PrivilegedPodCreated(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("privileged-pod-created.yaml")
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	rule := spec.Rules[0]
	if err := common.CheckAdmissionPrefilterConstraints(rule); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		event common.AdmissionEvent
		want  bool
	}{
		{"privileged container", podCreate("default", `{"containers":[{"name":"c","securityContext":{"privileged":true}}]}`), true},
		{"privileged init container", podCreate("default", `{"initContainers":[{"name":"i","securityContext":{"privileged":true}}],"containers":[{"name":"c"}]}`), true},
		{"second container privileged", podCreate("default", `{"containers":[{"name":"a"},{"name":"b","securityContext":{"privileged":true}}]}`), true},
		{"SYS_ADMIN", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"add":["NET_BIND_SERVICE","SYS_ADMIN"]}}}]}`), true},
		{"ALL", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"add":["ALL"]}}}]}`), true},
		{"SYS_PTRACE", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"add":["SYS_PTRACE"]}}}]}`), true},
		{"BPF", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"add":["BPF"]}}}]}`), true},
		{"benign capability", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"add":["NET_BIND_SERVICE"]}}}]}`), false},
		{"capabilities drop only", podCreate("default", `{"containers":[{"name":"c","securityContext":{"capabilities":{"drop":["ALL"]}}}]}`), false},
		{"privileged false", podCreate("default", `{"containers":[{"name":"c","securityContext":{"privileged":false}}]}`), false},
		{"allowPrivilegeEscalation alone", podCreate("default", `{"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":true}}]}`), false},
		{"no securityContext", podCreate("default", `{"containers":[{"name":"c"}]}`), false},
		{"pod-level securityContext only", podCreate("default", `{"securityContext":{"runAsUser":0},"containers":[{"name":"c"}]}`), false},
		{"kubescape ns excluded", podCreate("kubescape", `{"containers":[{"name":"c","securityContext":{"privileged":true}}]}`), false},
		{"kube-system excluded", podCreate("kube-system", `{"containers":[{"name":"c","securityContext":{"privileged":true}}]}`), false},
		{"UPDATE ignored", func() common.AdmissionEvent {
			e := podCreate("default", `{"containers":[{"name":"c","securityContext":{"privileged":true}}]}`)
			e.Operation = "UPDATE"
			return e
		}(), false},
		{"other kind", common.AdmissionEvent{Kind: "Deployment", Name: "d", Namespace: "default", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"d"},"spec":{"template":{"spec":{"containers":[{"name":"c","securityContext":{"privileged":true}}]}}}}`)}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := common.EvaluateAdmissionRule(rule, tc.event)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Matched != tc.want {
				t.Fatalf("matched=%v want %v", res.Matched, tc.want)
			}
			if res.Matched {
				if !strings.Contains(res.Message, "alice") {
					t.Fatalf("unexpected message %q", res.Message)
				}
				if res.UniqueID != "default/ReplicaSet/web-abc" {
					t.Fatalf("unexpected uniqueId %q", res.UniqueID)
				}
			}
		})
	}
}

func TestR2003GenerateNameFallback(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("privileged-pod-created.yaml")
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	ev := common.AdmissionEvent{Kind: "Pod", Namespace: "default", Operation: "CREATE", Resource: "pods", Username: "alice",
		Object: common.JSONObject(`{"metadata":{"generateName":"debug-","namespace":"default"},"spec":{"containers":[{"name":"c","securityContext":{"privileged":true}}]}}`)}
	res, err := common.EvaluateAdmissionRule(spec.Rules[0], ev)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.UniqueID != "default/debug-" {
		t.Fatalf("uniqueId %q want default/debug-", res.UniqueID)
	}
	if !strings.Contains(res.Message, "debug-") {
		t.Fatalf("message %q should name the generateName prefix", res.Message)
	}
}
