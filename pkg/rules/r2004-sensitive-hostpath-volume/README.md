# R2004 — Pod created with sensitive hostPath volume

| Field | Value |
|-------|-------|
| Severity | High (8) |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | Escape to Host (T1611) |
| Platforms | Kubernetes |
| Event type | `k8s-admission` (operator admission webhook, not node-agent) |
| Requires Application Profile | No |

## Description

Fires at admission time when a Pod is created with a `hostPath` volume whose path is, or sits
under, a location that gives the container control of the node:

| Exact match | Prefix match |
|---|---|
| `/`, `/etc`, `/proc`, `/root`, `/home`, `/var/run`, `/run` | `/etc/`, `/proc/`, `/root/`, `/home/` |
| `/var/lib/kubelet`, `/etc/kubernetes`, `/var/lib/docker/overlay2` | `/var/lib/kubelet/`, `/etc/kubernetes/` |
| `/var/run/docker.sock`, `/run/docker.sock` | |
| `/var/run/containerd/containerd.sock`, `/run/containerd/containerd.sock` | |
| `/var/run/crio/crio.sock`, `/run/crio/crio.sock` | |

Mounting `/` or `/etc` lets the container rewrite host configuration and add SSH keys or cron
jobs. `/var/lib/kubelet` holds the kubelet's client certificate and every pod's projected
service account tokens. The runtime sockets allow launching arbitrary privileged containers on
the node. `/var/lib/docker/overlay2` exposes every other container's filesystem.

Pods created in `kube-system`, `kube-public`, `kube-node-lease` and `kubescape` are excluded,
because CNI, CSI, log shippers and the Kubescape node-agent mount host paths by design.

## Attack Technique

Mapped to **T1611 — Escape to Host** under **TA0004 — Privilege Escalation**. A hostPath mount
is the simplest container escape in Kubernetes: it needs no capability, no privileged flag and
no kernel exploit, only pod-create rights in a namespace without Pod Security Admission. The
kubelet kubeconfig and the runtime socket are the two most common targets because each gives
node-level control that is hard to distinguish from normal kubelet activity.

## How It Works

```cel
event.Kind == "Pod" && event.Operation == "CREATE" &&
!(event.Namespace in ["kube-system", "kube-public", "kube-node-lease", "kubescape"]) &&
has(object.spec.volumes) &&
object.spec.volumes.exists(v,
  has(v.hostPath) && has(v.hostPath.path) &&
  [
    string(v.hostPath.path) in [ ...exact list... ],
    [ ...prefix list... ].exists(p, string(v.hostPath.path).startsWith(p))
  ].exists(b, b)
)
```

`object` is the admitted Pod as an unstructured map. Prefix entries carry a trailing slash so
`/etc/` matches `/etc/kubernetes` but not `/etcd`. The exact and prefix checks are combined
with a list `exists` rather than `||`, because the operator's Kind pre-filter falls back to
evaluating every admission event if any loaded expression contains `||`.

`/var/log`, `/var/lib/docker/containers` and `/sys` are intentionally absent. Log shippers and
node exporters mount them routinely and they are far less useful for escape.

Only CREATE is inspected; volumes are immutable after creation. Whether the mount is writable
is a property of `volumeMounts.readOnly`, not of the volume, and is not evaluated. A read-only
mount of `/var/lib/kubelet` still exposes credentials.

**Message** lists every hostPath in the pod, not only the matching one, plus the pod and
requesting user. **UniqueID** is `namespace/<ownerKind>/<ownerName>` when the pod has an owner
reference, otherwise `namespace/podName`.

## Investigation Steps

1. **Identify the requester.** `event.UserInfo.Username` is in the message.
2. **Read the matching path and its mount.** The admission alert carries the Pod object. Check
   `volumeMounts` for the mount point and `readOnly`. A writable `/` or `/etc` mount is the most
   severe case; a runtime socket mount is equivalent to root on the node.
3. **Check the image and command.** `nsenter`, `chroot /host`, `docker`, `crictl` or a plain
   shell paired with the mount is a strong indicator.
4. **Correlate with runtime alerts** on the same workload: R1033 docker socket access, R1082
   kubelet API access, R0010 sensitive file access, R1083 chroot execution.
5. **Check for credential use.** If `/var/lib/kubelet` was mounted, review API server audit
   logs for requests authenticated as that node after the pod started.

## Remediation

- Delete the pod and the owning workload if it is not an approved component.
- Rotate the kubelet certificate and any service account tokens of pods on that node if the
  kubelet directory was mounted by an unapproved pod.
- Enforce Pod Security Admission `baseline` on application namespaces; it forbids hostPath
  volumes entirely.
- Where an agent genuinely needs a host path, mount the narrowest subdirectory read-only.

## False Positives

- **Log and metrics shippers** that mount `/var/run/docker.sock` or `/run/containerd/*.sock`
  for container metadata, deployed outside `kube-system`.
- **Storage and backup tooling** that mounts `/var/lib/kubelet` to reach pod volumes.
- **Node configuration agents** and security scanners that mount `/` or `/etc` read-only.

Handle these with a backend prefilter on the image rather than by disabling the rule. The rule
is shipped disabled by default in ARMO rulesets for this reason.
