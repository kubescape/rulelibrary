# R0009 — eBPF Program Load

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | System Binary Proxy Execution (T1218) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects loading of an eBPF program from a host or container. The `BPF_PROG_LOAD` command attaches code to a kernel hook point — kprobes, tracepoints, networking, security hooks — and the kernel runs that code with privileged access to kernel data structures. Legitimate uses (observability agents, runtime security tools, networking systems like Cilium) are well-known and few; an unexpected program load from a workload that never demonstrated this capability is a strong signal of either a rootkit or kernel-instrumentation-based attacker tooling.

## Attack Technique

Mapped to **MITRE T1218 — System Binary Proxy Execution** under **TA0005 — Defense Evasion**. eBPF gives an adversary unparalleled hiding capability: an eBPF program can intercept syscalls, hide processes from `ps`, drop network packets that would alert defenders, and rewrite the data returned to other security tools. Modern Linux rootkits increasingly rely on eBPF rather than kernel modules because the loading surface is wider (a process with `CAP_BPF` or `CAP_SYS_ADMIN` does not need to ship a `.ko` file).

## How It Works

The rule fires on any `bpf` syscall with `cmd == BPF_PROG_LOAD` (numeric value 5) that was not part of the baseline:

```
event.cmd == 5  // BPF_PROG_LOAD
  AND !ap.was_syscall_used(containerId, 'bpf')
```

If the application profile is available, prior baselined use of the `bpf` syscall suppresses the rule for that workload. The rule fires when no baseline exists or when the workload never demonstrated `bpf` use during learning.

## Investigation Steps

1. **Identify the loading process.** `event.comm` and the parent process are the starting point. A known observability or networking agent (Falco, Cilium, datadog-agent, parca, etc.) is benign in context; an unknown binary or a shell-spawned helper is not.
2. **Check whether the container even has `CAP_BPF` or `CAP_SYS_ADMIN`.** If not, the load attempt would have failed and the event indicates an attempted, not successful, attack. Either way, the attempt warrants investigation.
3. **Look at the program type and attach point.** Programs that attach to networking hooks (`SOCK_FILTER`, `XDP`) are common; programs that attach to security hooks (`LSM`, `BPF_PROG_TYPE_KPROBE`) and probe kernel internals are heavily skewed toward hostile use.
4. **Pull surrounding events.** A new binary executed shortly before, a capability anomaly (R0004), or a process that should not have privileged access are usually nearby.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the process. If suspicious, isolate the host (this is a host-level concern given eBPF's kernel scope).

## Remediation

**If the load is malicious:** isolate the host the load happened on — eBPF runs in kernel context, not container context, so the blast radius is the host, not just the container. Reboot to clear any loaded program (eBPF programs do not always survive reboot but may be re-pinned by the attacker). Capture loaded program info (`bpftool prog list`) before reboot if forensics tooling allows. Treat any host-level secrets and any data the eBPF program could observe as compromised (see "blast radius"). As a hardening follow-up, drop `CAP_BPF` and `CAP_SYS_ADMIN` from containers that do not need them, and use seccomp to block the `bpf` syscall entirely on workloads that never use it.

**If the load is legitimate:** allowlist the specific loading process via a per-rule policy. A new observability or networking agent rollout typically only needs to be allowlisted on initial deploy.

## False Positives

- **Observability and networking agents** added after the baseline was captured (Falco, Cilium, Tetragon, Pyroscope, datadog-agent, parca). Allowlist by process name on first deploy.
- **Distroless or minimal containers** that legitimately load an eBPF program for filtering. Rare but real, and best allowlisted on a per-workload basis.
- **eBPF-based CNI plugins** that load programs on pod startup; usually run in privileged sidecars and are baseline-able if learning happens after CNI install.
