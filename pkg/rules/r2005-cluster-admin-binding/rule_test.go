package r2005clusteradminbinding

import (
	"strings"
	"testing"

	"github.com/kubescape/rulelibrary/pkg/common"
)

func binding(kind, ns, name, op, roleRef, subjects, oldSubjects string) common.AdmissionEvent {
	ev := common.AdmissionEvent{Kind: kind, Name: name, Namespace: ns, Operation: op, Username: "alice",
		Object: common.JSONObject(`{"metadata":{"name":"` + name + `"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"` + roleRef + `"},"subjects":` + subjects + `}`)}
	if oldSubjects != "" {
		ev.OldObject = common.JSONObject(`{"metadata":{"name":"` + name + `"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"` + roleRef + `"},"subjects":` + oldSubjects + `}`)
	}
	return ev
}

func TestR2005ClusterAdminBinding(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("cluster-admin-binding.yaml")
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	rule := spec.Rules[0]
	if err := common.CheckAdmissionPrefilterConstraints(rule); err != nil {
		t.Fatal(err)
	}

	sa := `[{"kind":"ServiceAccount","name":"sa","namespace":"default"}]`
	bob := `[{"kind":"User","name":"bob"}]`
	bobEve := `[{"kind":"User","name":"bob"},{"kind":"User","name":"eve"}]`

	cases := []struct {
		name      string
		event     common.AdmissionEvent
		want      bool
		wantInMsg string
		wantUID   string
	}{
		{"CRB cluster-admin to SA", binding("ClusterRoleBinding", "", "evil", "CREATE", "cluster-admin", sa, ""), true, "ServiceAccount:default/sa", "ClusterRoleBinding/evil"},
		{"RB cluster-admin to user", binding("RoleBinding", "default", "evil", "CREATE", "cluster-admin", bob, ""), true, "User:bob", "RoleBinding/default/evil"},
		{"CRB no subjects yet", common.AdmissionEvent{Kind: "ClusterRoleBinding", Name: "empty", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"empty"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"}}`)}, true, "no subjects", "ClusterRoleBinding/empty"},
		{"UPDATE adds subject", binding("ClusterRoleBinding", "", "evil", "UPDATE", "cluster-admin", bobEve, bob), true, "User:eve", "ClusterRoleBinding/evil"},
		{"CRB view role", binding("ClusterRoleBinding", "", "ok", "CREATE", "view", bob, ""), false, "", ""},
		{"CRB admin role is not cluster-admin", binding("ClusterRoleBinding", "", "ok", "CREATE", "admin", bob, ""), false, "", ""},
		{"RB to namespaced Role named cluster-admin", common.AdmissionEvent{Kind: "RoleBinding", Name: "rb", Namespace: "default", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"rb"},"roleRef":{"kind":"Role","name":"cluster-admin"},"subjects":` + bob + `}`)}, false, "", ""},
		{"UPDATE label only", func() common.AdmissionEvent {
			e := binding("ClusterRoleBinding", "", "evil", "UPDATE", "cluster-admin", bob, bob)
			e.Object["metadata"].(map[string]any)["labels"] = map[string]any{"x": "y"}
			return e
		}(), false, "", ""},
		{"DELETE ignored", binding("ClusterRoleBinding", "", "evil", "DELETE", "cluster-admin", bob, ""), false, "", ""},
		{"ClusterRole not this rule", common.AdmissionEvent{Kind: "ClusterRole", Name: "god", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"god"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)}, false, "", ""},
		{"privileged pod not this rule", common.AdmissionEvent{Kind: "Pod", Name: "p", Namespace: "default", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"p"},"spec":{"containers":[{"name":"c","securityContext":{"privileged":true}}]}}`)}, false, "", ""},
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
			if !res.Matched {
				return
			}
			if !strings.Contains(res.Message, "cluster-admin granted via") || !strings.Contains(res.Message, tc.wantInMsg) {
				t.Fatalf("message %q does not contain %q", res.Message, tc.wantInMsg)
			}
			if res.UniqueID != tc.wantUID {
				t.Fatalf("uniqueId %q want %q", res.UniqueID, tc.wantUID)
			}
		})
	}
}
