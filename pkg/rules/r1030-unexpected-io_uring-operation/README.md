# R1030 — Unexpected io_uring Operation

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | System Binary Proxy Execution (T1218) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects io_uring operations from a host or container that were not observed during the learning window. `io_uring` is a modern Linux asynchronous-I/O interface that performs system-call-like operations (file reads, network sends, opens, splices) through a shared ring buffer between user space and the kernel — without going through the conventional syscall entry path. This means that defenders watching the syscall table miss io_uring activity entirely. Adversaries have noticed: io_uring is increasingly used as a "syscall bypass" channel for filesystem manipulation, network I/O, and process operations that would otherwise be visible to security tooling.

## Attack Technique

Mapped to **MITRE T1218 — System Binary Proxy Execution** under **TA0002 — Execution**. Modern Linux post-exploitation frameworks have added io_uring backends to perform reads, writes, opens, and even some exec-like operations without entering the syscall instruction. EDRs and audit pipelines that hook only the syscall path do not see this activity. Detecting on io_uring opcode use (rather than only on syscalls) closes the gap.

## How It Works

```
event type == 'iouring'
  // implicit: not in application profile syscall set
```

The node agent emits an `iouring` event for io_uring operations and surfaces the opcode and flags. Because the application profile's `syscalls: all` covers io_uring's pseudo-syscall opcodes for baselining purposes, the workload's recorded io_uring usage suppresses the rule for repeat operations; only novel opcodes trigger.

## Investigation Steps

1. **Identify the opcode and the process.** `event.opcode`, `event.flagsRaw`, and `event.comm` describe what was attempted via io_uring. Opcodes for `READ`, `WRITE`, `OPENAT`, `CONNECT`, `SENDMSG` are the typical attacker uses; the opcode list is in the kernel headers.
2. **Map the opcode to its effect.** An `OPENAT` opcode opening `/etc/shadow` is identical in effect to a regular `open` syscall, just invisible to a syscall-only audit. The investigation against the target follows the same path as the corresponding syscall would.
3. **Identify the process and look for io_uring usage history.** Many legitimate workloads use io_uring for performance; new use of io_uring by a workload that previously did not is the signal.
4. **Pull surrounding events.** Adversary chains that use io_uring usually still emit some events the standard path catches (network connections, file events) — the io_uring miss is on the syscalls themselves, not on the events.
5. **Treat as bypass attempt.** The pattern indicates an attacker aware enough of monitoring to choose io_uring as a channel.

## Remediation

**If malicious:** isolate the container (network policy or seccomp profile), preserve memory, audit which files were opened and which network destinations contacted via io_uring (the agent surfaces these), rotate any credentials reachable from the workload (see "blast radius"), and rebuild from a known-good image.

**Hardening:** apply seccomp policies that deny the `io_uring_setup`, `io_uring_register`, and `io_uring_enter` syscalls on workloads that do not need them. Some hardened distributions disable io_uring entirely at the kernel level (`CONFIG_IO_URING=n`); consider this for workloads that never legitimately use it. Where io_uring is needed, restrict it via the IORING_REGISTER_RESTRICTIONS feature to a specific opcode set.

**If legitimate:** allowlist the specific opcode via a per-rule policy. High-performance database and storage workloads are the most common legitimate users.

## False Positives

- **Modern high-performance workloads** that have recently adopted io_uring (recent versions of nginx, ScyllaDB, some databases). If they were exercised during learning, their opcode set is in the baseline; new opcodes after learning will trigger.
- **Workload version upgrades** that introduce io_uring usage where the previous version used regular syscalls.
- **Runners and orchestrators** where workload code paths vary and io_uring use is impossible to predict from learning.
