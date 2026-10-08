package r2002podshareshostnamespace

import (
	"strings"
	"testing"

	"github.com/kubescape/rulelibrary/pkg/common"
)

func podCreate(ns, spec string) common.AdmissionEvent {
	return common.AdmissionEvent{Kind: "Pod", Name: "p1", Namespace: ns, Operation: "CREATE", Resource: "pods", Username: "alice",
		Object: common.JSONObject(`{"metadata":{"name":"p1","namespace":"` + ns + `","ownerReferences":[{"kind":"DaemonSet","name":"agent"}]},"spec":` + spec + `}`)}
}

func TestR2002PodSharesHostNamespace(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("pod-shares-host-namespace.yaml")
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
		{"hostPID", podCreate("default", `{"hostPID":true,"containers":[{"name":"c"}]}`), true},
		{"hostIPC", podCreate("default", `{"hostIPC":true,"containers":[{"name":"c"}]}`), true},
		{"hostNetwork", podCreate("default", `{"hostNetwork":true,"containers":[{"name":"c"}]}`), true},
		{"all three", podCreate("default", `{"hostPID":true,"hostIPC":true,"hostNetwork":true,"containers":[{"name":"c"}]}`), true},
		{"plain pod", podCreate("default", `{"containers":[{"name":"c"}]}`), false},
		{"hostPID false", podCreate("default", `{"hostPID":false,"containers":[{"name":"c"}]}`), false},
		{"shareProcessNamespace is not hostPID", podCreate("default", `{"shareProcessNamespace":true,"containers":[{"name":"c"}]}`), false},
		{"hostPort is not hostNetwork", podCreate("default", `{"containers":[{"name":"c","ports":[{"containerPort":80,"hostPort":80}]}]}`), false},
		{"kube-system excluded", podCreate("kube-system", `{"hostPID":true,"containers":[{"name":"c"}]}`), false},
		{"kubescape excluded", podCreate("kubescape", `{"hostNetwork":true,"containers":[{"name":"c"}]}`), false},
		{"UPDATE ignored", func() common.AdmissionEvent {
			e := podCreate("default", `{"hostPID":true,"containers":[{"name":"c"}]}`)
			e.Operation = "UPDATE"
			return e
		}(), false},
		{"other kind", common.AdmissionEvent{Kind: "ClusterRoleBinding", Name: "x", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"x"},"spec":{"hostPID":true}}`)}, false},
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
				if res.UniqueID != "default/DaemonSet/agent" {
					t.Fatalf("unexpected uniqueId %q", res.UniqueID)
				}
			}
		})
	}
}
