# Testing `k8s-admission` rules

Admission rules (`R2xxx`) are evaluated by the Kubescape operator's admission webhook, not by
the node-agent. The node-agent CEL engine used by the other rule tests has none of the
admission variables, so these rules get their own small harness in `pkg/common/admission.go`.

## What the harness provides

`common.EvaluateAdmissionRule(rule, event)` compiles the rule's `k8s-admission` expressions
with cel-go and evaluates them against an `AdmissionEvent`. On a match it also evaluates the
`message` and `uniqueId` templates, so a template that only fails at runtime fails the test.

The environment mirrors `kubescape/operator` `admission/cel`:

| Variable | Shape | Filled from |
|---|---|---|
| `event` | map with `Kind`, `Name`, `Namespace`, `Operation`, `Resource`, `Subresource`, `DryRun`, `UserInfo.Username`, `UserInfo.Groups`, `UserInfo.UID` | `AdmissionEvent` fields |
| `object` | `map[string]dyn` | `AdmissionEvent.Object` |
| `oldObject` | `map[string]dyn` | `AdmissionEvent.OldObject` |
| `options`, `params` | `map[string]dyn` | `AdmissionEvent.Options`, empty map |
| `eventType` | string | always `k8s-admission` |

The operator declares `event` as a native Go struct. The harness uses a map with the same
field names, which evaluates identically for field access and string operations. Optional
types (`.?`) are not enabled in either, so an expression that needs them fails here as it
would in the operator.

`common.CheckAdmissionPrefilterConstraints(rule)` fails when an expression contains `||` or has
no literal `event.Kind == "..."`. The operator's Kind pre-filter is regex based: a single `||`
in any loaded expression disables it for every rule, and without a literal Kind the rule runs on
every admission event. Combine alternatives with `[a, b].exists(x, x)` instead.

`common.JSONObject(doc)` turns a JSON string into the unstructured map the operator passes as
`object`. Build fixtures the way the API server sends them, including `apiGroups` on RBAC
rules and `metadata.ownerReferences` on pods.

## Writing a test

Put a `rule_test.go` next to the rule YAML, in a package named after the rule directory
without dashes. Load the YAML with `common.LoadRuleFromYAML`, check the pre-filter constraints,
then table-drive fire and no-fire cases:

```go
spec, _ := common.LoadRuleFromYAML("high-privileges-role.yaml")
rule := spec.Rules[0]
if err := common.CheckAdmissionPrefilterConstraints(rule); err != nil {
    t.Fatal(err)
}
res, err := common.EvaluateAdmissionRule(rule, common.AdmissionEvent{
    Kind: "ClusterRole", Name: "god", Operation: "CREATE", Username: "alice",
    Object: common.JSONObject(`{"metadata":{"name":"god"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`),
})
```

Every rule should cover at least:

- one positive per branch of the expression;
- the equivalent spellings Kubernetes accepts for the same object (`/./etc` for a hostPath,
  `*/exec` for a subresource grant);
- benign look-alikes (`/etcd` next to `/etc/`, `get secrets` next to `list secrets`);
- excluded namespaces, the wrong `Operation`, and an event of another Kind;
- an UPDATE whose relevant field did not change, for rules that take UPDATE.

Run them with `go test ./pkg/rules/r2...`. The harness is expression-level: it does not start
the operator, call the admission API or exercise alert enrichment. Those are covered by the
operator's own tests and by loading the rule into a cluster.
