# R2006 — High privileges role created

| Field | Value |
|-------|-------|
| Severity | High (8) |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | Account Manipulation: Additional Container Cluster Roles (T1098.006) |
| Platforms | Kubernetes |
| Event type | `k8s-admission` (operator admission webhook, not node-agent) |
| Requires Application Profile | No |

## Description

Fires at admission time when a `ClusterRole` or `Role` is created, or has its `rules` changed,
and the resulting rules grant at least one of:

- a wildcard verb, or the `escalate`, `bind` or `impersonate` verb on any resource;
- `create`, `update` or `patch` in the core or wildcard API group on `pods/exec`, `pods/attach`,
  `serviceaccounts/token`, `nodes/proxy`, `secrets`, their wildcard-subresource spellings
  `*/exec`, `*/attach`, `*/token`, `*/proxy`, or the wildcard resource;
- `create`, `update` or `patch` in the `rbac.authorization.k8s.io` or wildcard API group on
  `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings` or the wildcard resource;
- `list` or `watch` in the core or wildcard API group on `secrets` or the wildcard resource.

Each of these lets the holder reach cluster-admin or read every credential in scope, so a role
that grants one is as sensitive as the `cluster-admin` binding that R2005 watches for. R2005
catches the binding of an existing powerful role. R2006 catches the creation of a new one, which
is the step an attacker takes when `cluster-admin` itself is monitored or blocked.

The operator webhook must register `clusterroles` and `roles`. kubescape/helm-charts#957 adds
them to the webhook and is unreleased at the time of writing. Charts without it deliver only
bindings, and this rule never fires.

## Attack Technique

Mapped to **T1098.006 — Additional Container Cluster Roles** under **TA0004 — Privilege
Escalation**. An identity that can write roles but is not yet cluster-admin writes itself a role
with `*` verbs, or with `escalate` so it can later grant permissions it does not hold, or with
`bind` so it can bind `cluster-admin` without holding it. A role that allows `create` on
`pods/exec` or `serviceaccounts/token` is an indirect route to the same place: exec into a
control-plane pod or mint a token for a privileged ServiceAccount. `list secrets` gives every
token and kubeconfig stored in the cluster in one call.

## How It Works

```cel
[event.Kind == "ClusterRole", event.Kind == "Role"].exists(k, k) &&
event.Operation in ["CREATE", "UPDATE"] &&
event.UserInfo.Username != "system:serviceaccount:kube-system:clusterrole-aggregation-controller" &&
has(object.rules) &&
(event.Operation == "CREATE" ? true : object.rules != (has(oldObject.rules) ? oldObject.rules : [])) &&
object.rules.exists(r, has(r.verbs) && has(r.resources) && has(r.apiGroups) && [
  r.verbs.exists(v, v in ["*", "escalate", "bind", "impersonate"]),
  (r.apiGroups.exists(g, g in ["", "*"]) &&
    r.verbs.exists(v, v in ["create", "update", "patch"]) &&
    r.resources.exists(res, res in ["*", "pods/exec", "pods/attach", "serviceaccounts/token", "nodes/proxy", "secrets",
                                     "*/exec", "*/attach", "*/token", "*/proxy"])),
  (r.apiGroups.exists(g, g in ["rbac.authorization.k8s.io", "*"]) &&
    r.verbs.exists(v, v in ["create", "update", "patch"]) &&
    r.resources.exists(res, res in ["*", "clusterroles", "clusterrolebindings", "roles", "rolebindings"])),
  (r.apiGroups.exists(g, g in ["", "*"]) &&
    r.verbs.exists(v, v in ["list", "watch"]) &&
    r.resources.exists(res, res in ["*", "secrets"]))
].exists(b, b))
```

`object` and `oldObject` are the admitted role and its previous state as unstructured maps. Kinds
and the four grant classes are combined with list `exists` instead of `||`, so the operator's
Kind pre-filter still sees both literal `event.Kind == "..."` constraints. A `||` anywhere in a
loaded expression disables that pre-filter for every rule.

Only resource rules are inspected: a PolicyRule must carry `resources` and `apiGroups`, which
Kubernetes requires for resource rules and forbids for `nonResourceURLs` rules. A rule with
`verbs: ["*"]` and `nonResourceURLs: ["/healthz"]` grants no resource privilege and does not
fire. Sensitive resource names are matched together with their API group, so a `secrets` or
`roles` resource in a custom group such as `vault.example.com` does not fire. Kubernetes
matches `*/exec` against every resource's `exec` subresource, so those spellings are listed
next to `pods/exec`.

A `PATCH` reaches the webhook as an `UPDATE` carrying the merged object, so patches are covered.
On UPDATE the rule fires only when `rules` changed, so label, annotation and ownerReference
updates do not re-alert on a role that was already powerful. Aggregated ClusterRoles with no
`rules` of their own never fire.

The `clusterrole-aggregation-controller` is excluded because it rewrites the `rules` of
aggregated ClusterRoles such as `admin` and `edit` on every reconcile, copying grants that were
already reviewed when the source roles were created.

`get` on `secrets` is deliberately not in scope. Almost every controller holds it for its own
namespace, and a role that reads one named secret is not a privilege escalation. `create` on
`pods` is also excluded: it is a real escalation path through hostPath and ServiceAccount
mounting, but it is granted to most CI and deployment identities and the resulting pod is caught
by R2002, R2003 and R2004 at creation.

**Message** names the role, whether it was created or updated, the requesting user, the risky
verbs present and the sensitive resources present. **UniqueID** is `Kind/[namespace/]name`.

## Investigation Steps

1. **Read the grant in the message.** `*` verbs or `escalate`/`bind`/`impersonate` on a new role
   outside platform namespaces is the strongest signal. `list secrets` in an application
   namespace is the second.
2. **Identify the requester.** A ServiceAccount from an application namespace writing roles is
   unusual unless it is a GitOps or operator controller. A human user doing it outside a change
   window deserves a conversation.
3. **Check whether the role is declared.** Compare with the GitOps repository, Helm release or
   Terraform state. Operators often ship ClusterRoles with wide grants; those are expected once
   per install, not on an ordinary Tuesday.
4. **Look for the binding.** The role is useless until bound. A RoleBinding or
   ClusterRoleBinding to the same role shortly after, or an R2005 alert from the same requester,
   confirms the escalation chain.
5. **Check the audit log for first use** of the role's subjects. If exec, token or secret
   requests already happened, assume compromise and scope accordingly.

## Remediation

- Delete or narrow the role unless it is declared and justified. Replace `*` with the explicit
  verbs and resources the workload needs.
- Rotate the requester's credentials and those of any subject bound to the role if the change
  was not authorised.
- Restrict `create` and `update` on roles and clusterroles to a small set of platform identities,
  and add a ValidatingAdmissionPolicy that rejects `escalate`, `bind` and `*` verbs outside
  approved names.
- Review who holds `escalate` and `bind` today. Those two verbs make every other RBAC control
  advisory.

## False Positives

- **Operator and Helm installs.** Many charts ship ClusterRoles with wildcard or RBAC write
  grants. Each install or upgrade that changes the rules fires once.
- **GitOps controllers** (ArgoCD, Flux) applying declared RBAC. They fire once per real change,
  not per sync, because unchanged rules do not fire.
- **Managed control planes** reconciling vendor roles in `kube-system`.
- **Secret stores and certificate managers** that legitimately `list` or `watch` secrets
  cluster-wide.

Each legitimate role fires once at creation and again only when its rules change, so the alert
stays reviewable. The rule is shipped disabled by default in ARMO rulesets until the expected
baseline per cluster is understood.
