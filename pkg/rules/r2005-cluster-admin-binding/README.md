# R2005 — cluster-admin role bound

| Field | Value |
|-------|-------|
| Severity | High (8) |
| MITRE Tactic | Persistence (TA0003) |
| MITRE Technique | Account Manipulation: Additional Container Cluster Roles (T1098.006) |
| Platforms | Kubernetes |
| Event type | `k8s-admission` (operator admission webhook, not node-agent) |
| Requires Application Profile | No |

## Description

Fires at admission time when a `ClusterRoleBinding` or `RoleBinding` whose `roleRef` is the
built-in `cluster-admin` ClusterRole is created, or when an existing one is updated with a
different subject list. `cluster-admin` grants every verb on every resource. Bound through a
ClusterRoleBinding it is full cluster control; bound through a RoleBinding it is full control of
that namespace, including the ability to read every secret and create privileged pods there.

Both resources are already in the operator's webhook registration, so no chart change is needed.

## Attack Technique

Mapped to **T1098.006 — Additional Container Cluster Roles** under **TA0003 — Persistence**. An
attacker who has briefly obtained a powerful identity, through a stolen kubeconfig, a leaked CI
token or an over-privileged service account, binds `cluster-admin` to an identity they control
so access survives the original credential being rotated. Binding a ServiceAccount is the usual
choice because its token can be minted at will from inside the cluster.

## How It Works

```cel
[event.Kind == "ClusterRoleBinding", event.Kind == "RoleBinding"].exists(k, k) &&
event.Operation in ["CREATE", "UPDATE"] &&
object.roleRef.kind == "ClusterRole" && object.roleRef.name == "cluster-admin" &&
(event.Operation == "CREATE"
  ? true
  : (has(object.subjects) ? object.subjects : []) != (has(oldObject.subjects) ? oldObject.subjects : []))
```

`object` and `oldObject` are the admitted binding and its previous state as unstructured maps.
The two Kinds are combined with a list `exists` instead of `||` so the operator's Kind pre-filter
can still read both literal `event.Kind == "..."` constraints and narrow evaluation to these two
Kinds. A `||` anywhere in a loaded expression disables that pre-filter for every rule.

On UPDATE the rule fires only when the subject list changed. `roleRef` is immutable, so the
only way to widen an existing cluster-admin binding is to add subjects. Label or annotation
changes, which controllers and GitOps tools make routinely, do not fire.

**Message** names the binding, every subject as `Kind:namespace/name`, and the requesting user.
**UniqueID** is `Kind/[namespace/]name`.

## Investigation Steps

1. **Identify the requester and the subject.** Both are in the message. A requester binding
   cluster-admin to a ServiceAccount in an application namespace, or to a User that does not
   exist in the identity provider, is the classic persistence pattern.
2. **Check whether the binding is declared.** Compare against the GitOps repository, Helm
   release manifests or the Terraform state. Helm charts that bind cluster-admin to their own
   ServiceAccount are common and should be documented, not ignored.
3. **Look at the requester's recent activity.** The same identity creating pods, reading secrets
   or creating tokens shortly before the binding suggests the binding is the second step, not the
   first.
4. **Check the audit log for the first use of the new subject.** If the subject has already made
   requests, assume persistence is established and scope the incident accordingly.

## Remediation

- Delete the binding unless it is declared and justified.
- Rotate the credentials of both the requester and the newly bound subject if the binding was
  not authorised. For a ServiceAccount subject, delete and recreate the ServiceAccount to
  invalidate its tokens.
- Replace cluster-admin grants with purpose-built ClusterRoles. Very few workloads need it.
- Restrict `create` and `update` on bindings to a small set of identities and gate them with an
  admission policy that forbids `cluster-admin` as a roleRef outside approved names.

## False Positives

- **Cluster bootstrap and operator installs.** Many Helm charts and operators bind cluster-admin
  to their ServiceAccount during installation. Every install or upgrade that recreates the
  binding fires once.
- **Platform team break-glass bindings** for on-call users.
- **Managed cloud components** that reconcile bindings in `kube-system`.

The alert is high fidelity because each legitimate binding fires once at creation. Review each
occurrence rather than suppressing the rule. The rule is shipped disabled by default in ARMO
rulesets until the expected baseline per cluster is understood.
