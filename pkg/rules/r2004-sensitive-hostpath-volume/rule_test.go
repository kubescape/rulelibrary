package r2004sensitivehostpathvolume

import (
	"strings"
	"testing"

	"github.com/kubescape/rulelibrary/pkg/common"
)

func podWithHostPaths(paths ...string) map[string]any {
	vols := make([]string, 0, len(paths))
	for i, p := range paths {
		vols = append(vols, `{"name":"h`+string(rune('0'+i))+`","hostPath":{"path":"`+p+`"}}`)
	}
	return common.JSONObject(`{"metadata":{"name":"p1","namespace":"default","ownerReferences":[{"kind":"ReplicaSet","name":"web-abc"}]},` +
		`"spec":{"containers":[{"name":"c"}],"volumes":[` + strings.Join(vols, ",") + `]}}`)
}

func podCreate(ns string, obj map[string]any) common.AdmissionEvent {
	return common.AdmissionEvent{Kind: "Pod", Name: "p1", Namespace: ns, Operation: "CREATE", Resource: "pods", Username: "alice", Object: obj}
}

func TestR2004SensitiveHostPathVolume(t *testing.T) {
	spec, err := common.LoadRuleFromYAML("sensitive-hostpath-volume.yaml")
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
		{"root", podCreate("default", podWithHostPaths("/")), true},
		{"etc", podCreate("default", podWithHostPaths("/etc")), true},
		{"etc trailing slash", podCreate("default", podWithHostPaths("/etc/")), true},
		{"etc kubernetes pki", podCreate("default", podWithHostPaths("/etc/kubernetes/pki")), true},
		{"kubelet subdir", podCreate("default", podWithHostPaths("/var/lib/kubelet/pki")), true},
		{"docker overlay2", podCreate("default", podWithHostPaths("/var/lib/docker/overlay2")), true},
		{"docker.sock", podCreate("default", podWithHostPaths("/var/run/docker.sock")), true},
		{"containerd.sock", podCreate("default", podWithHostPaths("/run/containerd/containerd.sock")), true},
		// Review finding: equivalent spellings Kubernetes accepts.
		{"dot component /./etc", podCreate("default", podWithHostPaths("/./etc")), true},
		{"double slash /var//lib/kubelet", podCreate("default", podWithHostPaths("/var//lib/kubelet")), true},
		{"triple slash", podCreate("default", podWithHostPaths("///etc")), true},
		{"dot then slashes", podCreate("default", podWithHostPaths("/.//./etc/kubernetes")), true},
		{"trailing dot /etc/.", podCreate("default", podWithHostPaths("/etc/.")), true},
		{"root as //", podCreate("default", podWithHostPaths("//")), true},
		{"root as /.", podCreate("default", podWithHostPaths("/.")), true},
		{"seventeen slashes", podCreate("default", podWithHostPaths("/////////////////etc")), true},
		{"eight dot components", podCreate("default", podWithHostPaths("/././././././././etc")), true},
		{"long mixed run", podCreate("default", podWithHostPaths("//././//./././//var///lib//./kubelet/./pki")), true},
		{"long run to root", podCreate("default", podWithHostPaths("/./././././////./")), true},
		{"long run benign stays benign", podCreate("default", podWithHostPaths("/////./././var///log")), false},
		// Review finding: runtime socket parent directories.
		{"/run/containerd", podCreate("default", podWithHostPaths("/run/containerd")), true},
		{"/var/run/containerd", podCreate("default", podWithHostPaths("/var/run/containerd")), true},
		{"/var/run/crio", podCreate("default", podWithHostPaths("/var/run/crio")), true},
		{"/run", podCreate("default", podWithHostPaths("/run")), true},
		{"benign plus sensitive", podCreate("default", podWithHostPaths("/var/log", "/root/.ssh")), true},
		// Benign controls.
		{"/var/log", podCreate("default", podWithHostPaths("/var/log")), false},
		{"/var/log/pods", podCreate("default", podWithHostPaths("/var/log/pods")), false},
		{"/etcd is not /etc", podCreate("default", podWithHostPaths("/etcd")), false},
		{"/homer is not /home", podCreate("default", podWithHostPaths("/homer")), false},
		{"/runtime is not /run", podCreate("default", podWithHostPaths("/runtime")), false},
		{"/data", podCreate("default", podWithHostPaths("/data")), false},
		{"/mnt/disks", podCreate("default", podWithHostPaths("/mnt/disks")), false},
		{"no volumes", podCreate("default", common.JSONObject(`{"metadata":{"name":"p1"},"spec":{"containers":[{"name":"c"}]}}`)), false},
		{"emptyDir only", podCreate("default", common.JSONObject(`{"metadata":{"name":"p1"},"spec":{"containers":[{"name":"c"}],"volumes":[{"name":"e","emptyDir":{}}]}}`)), false},
		{"kube-system excluded", podCreate("kube-system", podWithHostPaths("/etc")), false},
		{"UPDATE ignored", func() common.AdmissionEvent {
			e := podCreate("default", podWithHostPaths("/etc"))
			e.Operation = "UPDATE"
			return e
		}(), false},
		{"other kind", common.AdmissionEvent{Kind: "ConfigMap", Name: "x", Namespace: "default", Operation: "CREATE", Username: "alice",
			Object: common.JSONObject(`{"metadata":{"name":"x"},"data":{"path":"/etc"}}`)}, false},
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
				if !strings.Contains(res.Message, "sensitive hostPath volume") || !strings.Contains(res.Message, "alice") {
					t.Fatalf("unexpected message %q", res.Message)
				}
				if res.UniqueID != "default/ReplicaSet/web-abc" {
					t.Fatalf("unexpected uniqueId %q", res.UniqueID)
				}
			}
		})
	}
}
