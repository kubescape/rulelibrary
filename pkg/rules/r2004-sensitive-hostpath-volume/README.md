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

| Sensitive location | Why |
|---|---|
| `/` | The whole node |
| `/etc` | Host configuration, SSH keys, cron, `/etc/kubernetes` with the control plane PKI |
| `/proc` | Process memory and kernel tunables of every host process |
| `/root`, `/home` | Credentials and shell history of host users |
| `/var/lib/kubelet` | Kubelet client certificate and every pod's projected ServiceAccount tokens |
| `/var/lib/docker/overlay2` | Every other container's filesystem |
| `/run`, `/var/run` | Container runtime sockets (`docker.sock`, `containerd/containerd.sock`, `crio/crio.sock`), which allow launching arbitrary privileged containers on the node |

The path and everything beneath it count, so `/var/lib/kubelet/pki`, `/run/containerd` and
`/var/run/docker.sock` all fire. The path is normalised before comparison: Kubernetes rejects
`..` in a hostPath but accepts single-dot components and repeated separators, so `/./etc`,
`/var//lib/kubelet` and `/etc/.` are the same mounts as `/etc` and `/var/lib/kubelet` and
are treated as such.

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
object.spec.volumes
  .filter(v, has(v.hostPath) && has(v.hostPath.path))
  .map(v, "/" + string(v.hostPath.path).split("/")
    .filter(c, c != "" && c != ".")
    .map(c, c + "/").join(""))
  .exists(p, [
    p == "/",
    ["/etc/", "/proc/", "/root/", "/home/", "/var/lib/kubelet/",
     "/var/lib/docker/overlay2/", "/var/run/", "/run/"].exists(d, p.startsWith(d))
  ].exists(b, b))
```

`object` is the admitted Pod as an unstructured map. Each hostPath is normalised by path
component: the path is split on `/`, empty and single-dot components are discarded, and the
rest are joined back with a leading and trailing slash. Any number of repeated separators or
`.` components collapses, so there is no bound an attacker can exceed. `..` needs no handling
because Kubernetes rejects it in a hostPath. After that every sensitive location is a single
prefix check: `/etc/` matches `/etc`, `/etc/`, `/./etc`, `/////etc`, `/etc/kubernetes/pki`
and `/etc/.`, but not `/etcd`.
The root check is a plain equality with `/`. The two checks are combined with a list `exists`
rather than `||`, because the operator's Kind pre-filter falls back to evaluating every
admission event if any loaded expression contains `||`.

`/var/log`, `/var/lib/docker/containers` and `/sys` are intentionally absent. Log shippers and
node exporters mount them routinely and they are far less useful for escape. `/run` and
`/var/run` are matched as whole trees because any directory containing a runtime socket exposes
the socket, so `/run/containerd` is as dangerous as `/run/containerd/containerd.sock`.

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
