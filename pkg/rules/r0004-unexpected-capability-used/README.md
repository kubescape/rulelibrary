# R0004 — Linux Capabilities Anomalies in container

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects Linux capabilities exercised inside a host or container that were not observed during the learning window. Capabilities are the kernel's way of breaking root privileges into smaller, individually-grantable pieces (`CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, and ~40 others). A workload's real capability set is usually narrow; an attacker exercising a capability the workload never needed indicates either successful exploitation or a misconfigured container with too many capabilities available to abuse.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under **TA0002 — Execution**. Adversaries who land code in a container often reach for capabilities the workload itself doesn't need: `CAP_NET_RAW` for crafted-packet operations, `CAP_SYS_PTRACE` for process injection, `CAP_SYS_MODULE` for kernel modules, `CAP_DAC_READ_SEARCH` for bypassing filesystem permissions. Detecting on the deviation from baseline catches the attacker even when the rule library has no specific signature for the technique.

## How It Works

The node agent records every distinct capability exercised during the learning window. After the profile is finalized, every capability check is matched against the recorded set:

```
!ap.was_capability_used(containerId, capName)
```

The rule fires the first time a capability is exercised that the profile did not see during learning.

## Investigation Steps

1. **Identify the capability and the process.** `event.capName`, `event.syscallName`, `event.comm`, and `event.pid` together describe what was attempted. Some capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`) are essentially diagnostic of post-exploitation activity in most workloads.
2. **Check whether the container was even granted the capability.** If the pod spec or container runtime denied the capability, the syscall would have failed and the event indicates an attempted, not successful, use. Either way, the *attempt* is a strong signal.
3. **Map capability to attack pattern.** `CAP_NET_BIND_SERVICE` on a non-privileged port is benign; `CAP_NET_RAW` from a workload that never raw-sockets points at scanning or packet crafting.
4. **Pull surrounding events.** Capability use rarely happens in isolation: an exec event right before, a syscall anomaly right after, or a network anomaly nearby usually points at the broader attack.
5. **Decide: legitimate change or attack.** If legitimate, suppress the specific capability for the workload. If suspicious, isolate and begin incident response.

## Remediation

**If the capability use is malicious:** isolate the container (network policy or seccomp profile), preserve disk and memory for forensics, rotate credentials reachable from the workload (see "blast radius"), and begin incident response. As a hardening follow-up, drop the capability from the container spec so a future intruder cannot exercise it at all.

**If the capability use is legitimate:** allowlist it via a per-rule policy. The better long-term fix is usually to reduce the container's granted capabilities to the actual minimum, not to allow the workload to use anything it pleases.

Some workloads (orchestrators, CI/CD runners, debugging tools) by design exercise a broad capability set and are unsuited for this anomaly detection.

## False Positives

- **Periodic privileged operations.** A monthly admin task that needs `CAP_SYS_TIME` or `CAP_SETPCAP` may not have run during the learning window.
- **Container runtime helpers.** A few sidecar and init-container patterns briefly exercise capabilities not seen in steady state. These are best allowlisted by process name.
- **Newly-deployed features.** A code path added after profile finalization that requires a capability the workload previously did not use.
