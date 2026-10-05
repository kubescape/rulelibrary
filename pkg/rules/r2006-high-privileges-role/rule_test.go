package r2006highprivilegesrole

import (
	"strings"
	"testing"

	"github.com/kubescape/rulelibrary/pkg/common"
)

const aggregationController = "system:serviceaccount:kube-system:clusterrole-aggregation-controller"

func role(kind, ns, name, op, user, rules, oldRules string) common.AdmissionEvent {
	ev := common.AdmissionEvent{Kind: kind, Name: name, Namespace: ns, Operation: op, Username: user}
	if rules == "" {
		ev.Object = common.JSONObject(`{"metadata":{"name":"` + name + `"},"aggregationRule":{"clusterRoleSelectors":[]}}`)
	} else {
		ev.Object = common.JSONObject(`{"metadata":{"name":"` + name + `"},"rules":` + rules + `}`)
	}
	if oldRules != "" {
		ev.OldObject = common.JSONObject(`{"metadata":{"name":"` + name + `"},"rules":` + oldRules + `}`)
	}
	return ev
}

func TestR2006HighPrivilegesRole(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("high-privileges-role.yaml")
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	rule := spec.Rules[0]
	if err := common.CheckAdmissionPrefilterConstraints(rule); err != nil {
		t.Fatal(err)
	}

	wildcard := `[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`
	readPods := `[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]`

	cases := []struct {
		name      string
		event     common.AdmissionEvent
		want      bool
		wantInMsg string
	}{
		{"CR wildcard verbs", role("ClusterRole", "", "god", "CREATE", "alice", wildcard, ""), true, "granting * on *"},
		{"Role bind on roles", role("Role", "default", "binder", "CREATE", "system:serviceaccount:default:app",
			`[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"verbs":["bind"]}]`, ""), true, "bind on roles"},
		{"CR escalate", role("ClusterRole", "", "esc", "CREATE", "alice",
			`[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"]}]`, ""), true, "escalate"},
		{"CR impersonate users", role("ClusterRole", "", "imp", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["users","groups"],"verbs":["impersonate"]}]`, ""), true, "impersonate"},
		{"CR create CRB", role("ClusterRole", "", "rbac-writer", "CREATE", "alice",
			`[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["get","create"]}]`, ""), true, "create on clusterrolebindings"},
		{"CR create pods/exec", role("ClusterRole", "", "execer", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}]`, ""), true, "pods/exec"},
		{"CR list secrets", role("ClusterRole", "", "secret-dumper", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]`, ""), true, "list on secrets"},
		{"CR watch secrets wildcard group", role("ClusterRole", "", "secret-watcher", "CREATE", "alice",
			`[{"apiGroups":["*"],"resources":["secrets"],"verbs":["watch"]}]`, ""), true, "watch on secrets"},
		{"CR create secrets", role("ClusterRole", "", "secret-writer", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["secrets"],"verbs":["create"]}]`, ""), true, "create on secrets"},
		{"CR create serviceaccounts/token", role("ClusterRole", "", "minter", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]}]`, ""), true, "serviceaccounts/token"},
		{"CR core wildcard resource write", role("ClusterRole", "", "core-all", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["*"],"verbs":["create"]}]`, ""), true, "create on *"},
		// Review finding: wildcard subresource spellings Kubernetes accepts.
		{"CR create */exec", role("ClusterRole", "", "any-exec", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["*/exec"],"verbs":["create"]}]`, ""), true, "*/exec"},
		{"CR create */attach", role("ClusterRole", "", "any-attach", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["*/attach"],"verbs":["create"]}]`, ""), true, "*/attach"},
		{"CR create */token", role("ClusterRole", "", "any-token", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["*/token"],"verbs":["create"]}]`, ""), true, "*/token"},
		{"CR patch */proxy", role("ClusterRole", "", "any-proxy", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["*/proxy"],"verbs":["patch"]}]`, ""), true, "*/proxy"},
		{"UPDATE widened to *", role("ClusterRole", "", "widen", "UPDATE", "alice", wildcard, readPods), true, "updated by alice"},
		{"mixed rules one risky", role("Role", "default", "mixed", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]},{"apiGroups":[""],"resources":["secrets"],"verbs":["list"]}]`, ""), true, "list on secrets"},

		// No fire.
		{"Role get secrets only", role("Role", "default", "reader", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]`, ""), false, ""},
		{"Role get/list/watch pods", role("Role", "default", "viewer", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list","watch"]}]`, ""), false, ""},
		{"Role create pods", role("Role", "default", "deployer", "CREATE", "alice",
			`[{"apiGroups":[""],"resources":["pods"],"verbs":["create","delete"]}]`, ""), false, ""},
		{"apps wildcard resource write", role("Role", "default", "apps-admin", "CREATE", "alice",
			`[{"apiGroups":["apps"],"resources":["*"],"verbs":["create","update","patch"]}]`, ""), false, ""},
		{"custom group secrets resource", role("Role", "default", "custom-secrets", "CREATE", "alice",
			`[{"apiGroups":["vault.example.com"],"resources":["secrets"],"verbs":["list","create"]}]`, ""), false, ""},
		{"custom group roles resource", role("Role", "default", "custom-roles", "CREATE", "alice",
			`[{"apiGroups":["iam.example.com"],"resources":["roles"],"verbs":["create"]}]`, ""), false, ""},
		{"nonResourceURLs only get", role("ClusterRole", "", "metrics", "CREATE", "alice",
			`[{"nonResourceURLs":["/metrics"],"verbs":["get"]}]`, ""), false, ""},
		// Review finding: wildcard verbs on a non-resource rule grant no resource privilege.
		{"nonResourceURLs only wildcard verbs", role("ClusterRole", "", "healthz", "CREATE", "alice",
			`[{"nonResourceURLs":["/healthz"],"verbs":["*"]}]`, ""), false, ""},
		{"aggregationRule no rules", role("ClusterRole", "", "aggr", "CREATE", "alice", "", ""), false, ""},
		{"empty rules", role("ClusterRole", "", "empty", "CREATE", "alice", `[]`, ""), false, ""},
		{"aggregation controller", role("ClusterRole", "", "admin", "UPDATE", aggregationController, wildcard, readPods), false, ""},
		{"UPDATE rules unchanged", role("ClusterRole", "", "god", "UPDATE", "alice", wildcard, wildcard), false, ""},
		{"DELETE ignored", role("ClusterRole", "", "god", "DELETE", "alice", wildcard, ""), false, ""},
		{"ClusterRoleBinding not this rule", common.AdmissionEvent{Kind: "ClusterRoleBinding", Name: "evil", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"evil"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[]}`)}, false, ""},
		{"privileged pod not this rule", common.AdmissionEvent{Kind: "Pod", Name: "p", Namespace: "default", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"p"},"spec":{"containers":[{"name":"c","securityContext":{"privileged":true}}]}}`)}, false, ""},
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
			if !strings.HasPrefix(res.Message, "High privileges "+tc.event.Kind+" ") || !strings.Contains(res.Message, tc.wantInMsg) {
				t.Fatalf("message %q does not contain %q", res.Message, tc.wantInMsg)
			}
			wantUID := tc.event.Kind + "/" + tc.event.Name
			if tc.event.Namespace != "" {
				wantUID = tc.event.Kind + "/" + tc.event.Namespace + "/" + tc.event.Name
			}
			if res.UniqueID != wantUID {
				t.Fatalf("uniqueId %q want %q", res.UniqueID, wantUID)
			}
		})
	}
}
