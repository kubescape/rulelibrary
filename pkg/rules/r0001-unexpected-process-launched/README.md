# R0001 — Unexpected Process Launched

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host/Kubernetes/ECS |
| Requires Application Profile | Yes |

## Description

Detects any process executed inside a host or container that was not observed in that host/container's learned application profile. The rule fires on every `exec` event whose executable is not part of the container's baseline. It produces a strong signal in steady-state workloads where the set of legitimate processes is small and predictable, and is one of the broadest catch-alls for execution-based attacks such as command injection, web-shell drops, post-exploitation tooling, and lateral-movement payloads.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under tactic **TA0002 — Execution**. Adversaries who land code in a container almost always need to execute *some* unexpected binary or interpreter to make progress: a downloaded shell script, a reverse-shell binary, a privilege-escalation tool, a network utility for reconnaissance, or a cryptominer. Because the baseline is built from real execution traces of the running workload, anything outside that set surfaces here — including techniques the rule library has no signature for.

## How It Works

The node agent builds a per-container **application profile** during a learning window, recording every `exec` event observed. After the profile is finalized, every subsequent `exec` event is evaluated against the profile.

Simplified CEL:

```
!ap.was_executed(containerId, event.exepath != "" ? event.exepath : parse.get_exec_path(args, comm))
```

The exec path is resolved exepath-first to stay symmetric with the recording side, which stores the kernel-resolved path. The resolution is a plain CEL ternary (no special engine support required, so it runs on every agent version):

1. **exepath** — kernel-authoritative and spoof-resistant. `argv[0]` is user-controllable even when absolute (e.g. `exec -a /bin/sh sleep` reports `/bin/sh` while `/proc/<pid>/exe` is `/usr/bin/sleep`), so it cannot be trusted for an identity check.
2. **argv[0]** (via the 2-arg `parse.get_exec_path`) only when exepath is empty (`fexecve()` / `AT_EMPTY_PATH`, common from `sshd → unix_chkpwd`).
3. **comm** as the final fallback (also via the 2-arg form).

Because the rule queries the same identity the recorder stored, it needs only this single lookup. The rule fires when the resolved path was not seen during learning.

## Investigation Steps

1. **Identify the process and its parent.** Look at the alert's `event.comm`, `event.exepath`, `event.pid`, and the parent process (`pcomm`/`ppid`). A new shell spawned by a web server (e.g. `bash` from `nginx`) is much more concerning than a known internal tool fired by a known parent.
2. **Confirm the binary was not legitimately added.** Cross-reference the workload's recent deployments — a new image version may legitimately introduce a process the profile never saw. Check container image digests and recent CI/CD activity.
3. **Inspect the executable on disk.** If accessible, hash the binary and look it up against threat-intel sources. Check its path (`/tmp`, `/dev/shm`, container working dir) — non-standard locations strengthen the signal.
4. **Pull surrounding events.** Look for other alerts on the same container in the same time window — file writes, network connections, capability changes, or other R0001 hits. Adversary tooling rarely fires only one rule.
5. **Decide: legitimate change or attack.** If legitimate, retrain the profile (see Remediation). If suspicious, isolate the container and begin incident response.

## Remediation

**If the process is malicious:** isolate the container (network policy or seccomp profile), preserve disk/memory for forensics, rotate any credentials accessible from the container (see "blast radius"), and begin standard incident response. The parent process and ingress vector (which previous event allowed this `exec`?) usually reveal the entry point.

**If the process is legitimate but the profile is stale:**

- Suppress this specific binary for the workload via a per-rule allowlist policy.

**Do not blanket-disable R0001 on a workload** — it provides the deepest catch-all coverage in the rule library, and disabling it removes detection for a wide class of execution-based attacks. That said, some workloads are by definition not fit for anomaly detection: software orchestrators, CI/CD tools, runners — anything where the process-invocation cycle is detached from the container or host run cycle.

## False Positives

- **Periodic jobs that did not run during learning.** Weekly cron tasks, monthly batch jobs, ad-hoc maintenance scripts, and infrequent administrative tools can be missed by a short learning window. Lengthen the learning window or pre-warm the profile with the expected workload.
- **Runners or execution orchestrators.** Some software, by definition, has a different run cycle than the monitored host or container and may trigger false positives. One example is Apache Spark, where each job can ship its own binaries.

