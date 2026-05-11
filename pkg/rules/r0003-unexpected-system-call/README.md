# R0003 — Syscalls Anomalies in container

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects any system call invoked inside a host or container that was not observed during the learning window. The rule fires the first time a given syscall appears that is not part of the application profile's recorded syscall set. It is a very broad anomaly signal: the syscall surface a real workload uses is typically narrow and predictable, so deviations strongly indicate code outside the workload's normal behavior.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under **TA0002 — Execution**. Adversaries who land code in a container almost always reach for syscalls the workload itself does not need: namespace manipulation for escape, raw socket operations for tunneling, ptrace for injection, mount syscalls for filesystem games, or kernel-instrumentation primitives. Because the baseline is built from actual workload behavior, anything the workload never demonstrated surfaces here.

## How It Works

The node agent records every distinct syscall observed during the learning window. After the profile is finalized, every syscall event is checked against the recorded set:

```
!ap.was_syscall_used(containerId, syscallName)
```

The rule fires on any miss. Because most workloads use only a small subset of the ~350 available syscalls, the suppression catches steady-state activity while novel syscalls light up.

## Investigation Steps

1. **Identify the syscall and the process.** `event.syscallName`, `event.comm`, and `event.pid` are the starting point. Some syscalls (`ptrace`, `mount`, `unshare`, `keyctl`, `bpf`) are diagnostic on their own; others (`fchmod`, `fchown`) need context.
2. **Map the syscall to a technique.** Many security-relevant syscalls have a specific abuse pattern: `ptrace` for process injection, `unshare`/`setns` for container escape, `bpf` for kernel rootkits, `mount` for filesystem masquerade. The technique narrows the investigation immediately.
3. **Look at the process ancestry.** The parent process and its parent often reveal whether the syscall is benign (a new dependency the workload now uses) or hostile (a planted binary).
4. **Pull surrounding events.** Other R0003 hits, exec events, or file/network anomalies on the same container in the same window indicate active tradecraft rather than a quiet workload change.
5. **Decide: legitimate change or attack.** If legitimate, suppress the specific syscall via a per-rule allowlist. If suspicious, isolate and begin incident response.

## Remediation

**If the syscall is malicious:** isolate the container (network policy or seccomp profile), preserve disk and memory for forensics, rotate credentials reachable from the workload (see "blast radius"), and begin incident response. The use of an unusual syscall usually indicates the attacker has already executed payload code, so investigate that ingress.

**If the syscall is legitimate:** allowlist it via a per-rule policy for the affected workload. Prefer a tight allowlist (one syscall, one workload) over broad exceptions. Do not retrain the profile as a remediation step.

Some workloads are by definition not fit for syscall anomaly detection: software orchestrators, CI/CD tools, runners — anything where the workload runs arbitrary user-supplied code and the syscall surface is unbounded by design.

## False Positives

- **Periodic operations that did not run during learning.** A nightly backup that calls `fdatasync` or a weekly maintenance task that calls `setrlimit` may not appear in the baseline if those syscalls were not exercised during the learning window.
- **New library or runtime versions.** A dependency upgrade can introduce syscalls (e.g. `io_uring_*` after a libc bump) that the baseline does not know about.
- **Runners and execution orchestrators.** Workloads like Apache Spark, build runners, or function-as-a-service containers execute user code whose syscall set cannot be predicted from learning.
