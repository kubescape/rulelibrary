# R1001 — Drifted Process Executed

| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Masquerading (T1036) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects execution of a binary that was not present in the container's base image — that is, a binary written to the container's writable upper layer after start. The rule fires on `exec` events where either the executable or its parent comes from the upperlayer (the overlayfs writable layer that holds runtime additions on top of the read-only image), and the binary was not part of the application profile. A workload that runs only the binaries from its base image is the expected and ideal posture; a binary appearing in the writable layer and being executed means something added it at runtime, which is the textbook indicator of a dropped attacker payload.

## Attack Technique

Mapped to **MITRE T1036 — Masquerading** under **TA0005 — Defense Evasion**. Attackers who compromise a container almost always need to put their tooling somewhere and execute it. The writable upper layer is the path of least resistance: it persists for the container's lifetime, requires no special privileges to write, and is invisible to image scanners that only audit the read-only base image. Dropping a binary into the upperlayer and `execve`'ing it is a near-universal step in container intrusion chains.

## How It Works

```
(event.upperlayer == true || event.pupperlayer == true)
  AND !ap.was_executed(containerId, event.exepath != "" ? event.exepath : parse.get_exec_path(args, comm))
```

The first clause checks whether the executable (or its parent) lives in the writable upper layer of the container's overlay. The second clause matches against the application profile using the exepath-authoritative resolution shared with R0001 — the CEL ternary prefers the kernel-resolved `exepath` and falls back to `argv[0]`/`comm` (via the 2-arg `parse.get_exec_path`) only when exepath is empty, so the rule queries the same identity the recorder stored.

## Investigation Steps

1. **Capture the binary before it disappears.** Upperlayer files vanish on container restart. If safe, hash and exfiltrate `event.exepath` immediately for static analysis.
2. **Identify the dropping process.** The binary did not arrive in the image, so something wrote it. Look for `write` events targeting the same path shortly before this exec. The writer's process ancestry typically reveals the ingress vector.
3. **Inspect the parent and user.** A binary in the upperlayer being run by a `nobody`-uid process spawned from a web server is essentially diagnostic of an intrusion in flight.
4. **Look for adjacent activity.** Outbound connections to fresh destinations (R0011), DNS anomalies (R0005), or credential reads (R0010, R0008) frequently follow a dropped-binary exec.
5. **Treat as confirmed intrusion until proven otherwise.** Given the severity and the rarity of legitimate hits, default to incident response posture.

## Remediation

**Active intrusion:** isolate the container immediately (network policy or seccomp profile), preserve `/dev/shm`, the upperlayer, and process memory if your tooling supports it. Identify and revoke any credentials reachable from the workload (see "blast radius"), and rebuild the workload from a known-good image rather than patching in place.

**Hardening:** apply read-only root filesystems where the workload tolerates them (this removes the writable layer entirely as a staging surface). Audit the base image for unnecessary tooling that would let an attacker live-off-the-land instead of dropping binaries. Tighten the container's capability set so the attacker cannot escalate further from a dropped tool.

## False Positives

- **Application updates that ship binaries at runtime.** Some legacy deploy patterns push binaries into a running container via a sidecar rather than via image rebuild. These should be considered antipatterns; if they cannot be changed, allowlist the specific binaries.
- **Self-updating runtimes.** A language runtime that downloads helper binaries to the upperlayer on first use. Rare in modern containers; allowlist explicitly.
- **In-container debug tooling** copied in by an operator. Distinguishable by parent process (kubectl-exec entry points).
