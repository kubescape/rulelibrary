# R1004 — Process Executed from Mount

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects `exec` calls in a host or container where the executable resides under a Kubernetes-mounted volume path (configMap, secret, emptyDir, hostPath, persistent volume), and the binary was not part of the application profile. Mounted volumes are common attack surfaces because their contents can be modified externally — a compromised configMap, a misconfigured hostPath, or a writable PVC can become a vector for delivering binaries into an otherwise-locked-down container.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under **TA0002 — Execution**. Adversaries who cannot directly write into the container's filesystem sometimes pivot through mounted volumes: an attacker who can edit a configMap can drop a script that the workload then executes; an attacker who controls a hostPath gains a write surface that survives container restart. Detecting `exec` from mount paths catches both the "delivery via mounted config" and "delivery via shared storage" variants.

## How It Works

The rule combines an application-profile check with a Kubernetes mount-path lookup. For each `exec` event:

```
binary not in application profile (same exepath-authoritative check as R0001)
  AND the binary's resolved path (exepath, or argv[0]/comm when exepath is empty)
      starts with any of the container's mount paths
```

`k8s.get_container_mount_paths(namespace, podName, containerName)` returns the list of paths mounted into the container from Kubernetes-managed volumes. The rule fires only when the executed binary's path is under one of those mounts and was not seen during learning.

## Investigation Steps

1. **Identify the binary and the mount.** `event.exepath` (or `argv[0]`) together with the matched mount path show which volume delivered the binary. A configMap-mounted binary is a different incident from a hostPath-mounted binary.
2. **Find the source of the binary.** ConfigMap contents come from Kubernetes; a recent change to the configMap (audit logs) often reveals who or what placed the binary. PVC contents come from the underlying storage; trace whoever can write to it. HostPath contents come from the node filesystem and indicate host-level compromise.
3. **Inspect the binary itself.** Hash and analyze it; in many cases it is a benign script that happens to be in a volume, but in attack scenarios it is a downloader, reverse shell, or post-exploitation tool.
4. **Look at the executing process and parent.** A previously-baselined process exec'ing the new binary is interesting (the workload picked up a new code path); a freshly-spawned shell exec'ing it is essentially diagnostic.
5. **Decide: legitimate change or attack.** If legitimate, allowlist. If suspicious, treat as a possible supply-chain or shared-storage compromise.

## Remediation

**If malicious:** isolate the container (network policy or seccomp profile), preserve memory and the relevant mount contents, audit the source of the mount (configMap revision history, PVC access logs, hostPath ownership) to understand how the binary arrived, and rotate any credentials the workload had access to (see "blast radius"). If the source is a configMap or PVC shared by multiple workloads, treat all of them as potentially compromised.

**Hardening:** mark Kubernetes volumes `readOnly: true` where the workload only needs to read them, narrow access to configMaps and PVCs via RBAC, and audit hostPath mounts — most workloads do not need them, and removing them eliminates a major attack surface.

**If legitimate:** allowlist the specific binary path via a per-rule policy.

## False Positives

- **ConfigMap-delivered scripts** that the workload legitimately runs (init scripts, helper utilities). If they were exercised during learning they are already baselined; if added later, allowlist explicitly.
- **Helm chart upgrades** that ship new binaries via configMap rather than image. Common in legacy deploy patterns; consider refactoring to image-based delivery.
- **Operator-controlled mounts** (Operator Framework operators that drop binaries into workloads). Allowlist by operator.
