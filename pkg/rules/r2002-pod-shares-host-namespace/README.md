# R2002 — Pod shares host namespace

| Field | Value |
|-------|-------|
| Severity | Medium (6) |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | Escape to Host (T1611) |
| Platforms | Kubernetes |
| Event type | `k8s-admission` (operator admission webhook, not node-agent) |
| Requires Application Profile | No |

## Description

Fires at admission time when a Pod is created with `spec.hostPID`, `spec.hostIPC` or
`spec.hostNetwork` set to `true`. Each flag removes one of the kernel namespace boundaries
between the container and the node: `hostPID` exposes every process on the host and, combined
with `ptrace`, lets a container manipulate host processes; `hostIPC` exposes host and sibling
shared memory, semaphores and message queues; `hostNetwork` attaches the pod to the node's
network stack, exposing loopback-bound services and bypassing NetworkPolicy.

Pods created in `kube-system`, `kube-public`, `kube-node-lease` and `kubescape` are excluded,
because CNI, CSI, node monitoring and the Kubescape node-agent legitimately need these flags.

## Attack Technique

Mapped to **T1611 — Escape to Host** under **TA0004 — Privilege Escalation**. An attacker with
pod-create rights, or a compromised CI pipeline or controller, schedules a pod that shares a host
namespace as a staging step for host access: `hostPID` plus `nsenter -t 1` gives a host shell,
`hostNetwork` reaches the kubelet API and cloud metadata on the node's loopback. This rule sees
the request at the API server, before the pod runs, so it fires even when the pod never
schedules or dies before the node-agent observes it.

## How It Works

The operator's admission controller receives every `pods` CREATE request. The rule checks:

```cel
event.Kind == "Pod" && event.Operation == "CREATE" &&
!(event.Namespace in ["kube-system", "kube-public", "kube-node-lease", "kubescape"]) &&
["hostPID", "hostIPC", "hostNetwork"].exists(f, f in object.spec && object.spec[f] == true)
```

`object` is the admitted Pod as an unstructured map, so the pod spec is read with map
semantics (`f in object.spec`, `object.spec[f]`). The expression keys on a literal
`event.Kind == "Pod"` and avoids `||` so the operator's Kind pre-filter can statically narrow
evaluation to Pod events.

Only CREATE is inspected. These fields are immutable after creation, and pods receive a high
volume of UPDATE requests for status changes that carry the full object.

**Message** lists which flags were set, the pod and the requesting user.
**UniqueID** is `namespace/<ownerKind>/<ownerName>` when the pod has an owner reference,
otherwise `namespace/podName`. A Deployment with many replicas therefore produces one
deduplicated alert, not one per replica. When the API server has not assigned a name yet, the
`generateName` prefix is used.

## Investigation Steps

1. **Identify the requester.** `event.UserInfo.Username` is in the message. A human user or a
   CI service account creating host-namespace pods outside system namespaces is unusual.
2. **Check the owner.** The UniqueID names the owning ReplicaSet, DaemonSet or Job. A brand-new
   workload with no git history is more suspicious than a known agent moved to a new namespace.
3. **Look at the image and command.** Pair with the admission alert object: `nsenter`,
   `chroot /host`, `kubectl`, or a shell image together with `hostPID` is a strong escape
   indicator.
4. **Correlate with runtime alerts.** If the pod ran, look for node-agent alerts on the same
   workload (R1084 nsenter namespace join, R1083 chroot, unexpected process or file access).
5. **Check for repeat attempts.** The same user creating several variants (hostPID, then
   privileged, then hostPath) is a privilege-escalation search pattern.

## Remediation

- Delete the pod and the owning workload if it is not an approved agent.
- Revoke or scope down the pod-create permission of the requesting identity.
- Enforce Pod Security Admission `restricted` or `baseline` on application namespaces; both
  forbid host namespaces.
- Move legitimate host-namespace agents into a dedicated, labelled namespace and document them.

## False Positives

- **Node agents outside system namespaces.** Monitoring (node-exporter, Datadog, Dynatrace),
  CNI and CSI components, and security agents deployed to their own namespace rather than
  `kube-system` will fire on install and on every rollout. `hostNetwork` in particular is common
  for ingress controllers and service meshes in host-network mode.
- **Cluster add-ons installed by cloud providers** into namespaces such as `gmp-system` or
  `gke-managed-*`.

Handle these with a backend prefilter on the image or namespace rather than by disabling the
rule. The rule is shipped disabled by default in ARMO rulesets for this reason.
