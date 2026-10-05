# R2003 — Privileged pod created

| Field | Value |
|-------|-------|
| Severity | High (8) |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | Escape to Host (T1611) |
| Platforms | Kubernetes |
| Event type | `k8s-admission` (operator admission webhook, not node-agent) |
| Requires Application Profile | No |

## Description

Fires at admission time when a Pod is created and any of its containers, init containers or
ephemeral containers either runs with `securityContext.privileged: true` or adds a Linux
capability that is equivalent to host root. A privileged container has every capability, all
host devices, and no seccomp or AppArmor confinement, which makes host escape a matter of
mounting the node's root disk. The capability list is the near-root subset, not every
capability:

`ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_RAWIO`, `SYS_BOOT`, `NET_ADMIN`,
`DAC_READ_SEARCH`, `BPF`, `PERFMON`, `SYS_TIME`.

Pods created in `kube-system`, `kube-public`, `kube-node-lease` and `kubescape` are excluded,
because kube-proxy, CNI, CSI and the Kubescape node-agent are privileged by design.

`allowPrivilegeEscalation` is deliberately not a trigger. It defaults to true whenever it is
unset and would make the rule fire on most ordinary pods.

## Attack Technique

Mapped to **T1611 — Escape to Host** under **TA0004 — Privilege Escalation**. The textbook
sequence is: obtain pod-create rights (stolen kubeconfig, over-privileged service account,
compromised CI), create a privileged pod, then `mount /dev/sda1 /mnt` or write to
`/sys/fs/cgroup/release_agent` to execute on the node. `SYS_ADMIN` alone enables the cgroup
release-agent escape; `SYS_MODULE` loads a kernel module; `SYS_PTRACE` with `hostPID` injects
into host processes. Catching the pod spec at admission time is the earliest possible point.

## How It Works

```cel
event.Kind == "Pod" && event.Operation == "CREATE" &&
!(event.Namespace in ["kube-system", "kube-public", "kube-node-lease", "kubescape"]) &&
(object.spec.containers
  + (has(object.spec.initContainers) ? object.spec.initContainers : [])
  + (has(object.spec.ephemeralContainers) ? object.spec.ephemeralContainers : [])
).exists(c,
  has(c.securityContext) &&
  [
    has(c.securityContext.privileged) && c.securityContext.privileged == true,
    has(c.securityContext.capabilities) && has(c.securityContext.capabilities.add) &&
      c.securityContext.capabilities.add.exists(cap, cap in [ ... ])
  ].exists(b, b)
)
```

`object` is the admitted Pod as an unstructured map. The three container lists are
concatenated and scanned once. The two conditions are combined with a list `exists` rather than
`||`, because the operator's Kind pre-filter falls back to evaluating every admission event if
any loaded expression contains `||`. The expression keys on a literal `event.Kind == "Pod"` for
the same reason.

Only CREATE is inspected. Container security contexts are immutable after creation, and pods
receive many UPDATE requests for status changes.

**Message** names the pod and the requesting user. **UniqueID** is
`namespace/<ownerKind>/<ownerName>` when the pod has an owner reference, otherwise
`namespace/podName`, so a Deployment with many replicas produces one deduplicated alert.

## Investigation Steps

1. **Identify the requester.** `event.UserInfo.Username` is in the message. Privileged pods
   created by a human user or a CI identity outside system namespaces warrant a direct question.
2. **Inspect the full spec.** The admission alert carries the Pod object. Look at the image,
   command, `hostPID`, `hostPath` volumes and the service account. A privileged pod that also
   mounts `/` and runs `sleep infinity` is an attacker's beachhead.
3. **Check sibling alerts.** R2002 (host namespace) and R2004 (sensitive hostPath) on the same
   pod or user turn a single alert into a pattern.
4. **Correlate with runtime.** If the pod ran, look for node-agent alerts on the workload:
   R1037 cgroups release agent, R1002 kernel module load, R1054 mount operations, R0004
   unexpected capability used.
5. **Review RBAC.** Determine which Role grants the identity pod-create rights in that namespace
   and whether that grant is still needed.

## Remediation

- Delete the pod and the owning workload if it is not an approved component.
- Rotate credentials of the requesting identity if the creation was not authorised.
- Enforce Pod Security Admission `baseline` on application namespaces; it forbids privileged
  containers and the capabilities above.
- Replace privileged agents with capability-scoped equivalents where possible, and run the ones
  that genuinely need privilege from a dedicated namespace.

## False Positives

- **Privileged infrastructure outside `kube-system`.** Storage drivers, GPU device plugins,
  eBPF-based observability and security agents, and some service mesh init containers run
  privileged or add `NET_ADMIN` and `SYS_ADMIN`. Istio's init container adds `NET_ADMIN` and
  `NET_RAW`, so sidecar-injected namespaces will fire on every pod creation.
- **Build systems** such as Docker-in-Docker, Kaniko with privileged mode, or BuildKit.

Handle these with a backend prefilter on the image rather than by disabling the rule. The rule
is shipped disabled by default in ARMO rulesets for this reason.
