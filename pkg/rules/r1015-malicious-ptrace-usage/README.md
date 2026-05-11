# R1015 — Malicious Ptrace Usage

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Debugger Evasion (T1622) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects any use of the `ptrace` syscall by a process inside a host or container. `ptrace` is the kernel primitive that allows one process to inspect and modify another: read memory, write memory, intercept system calls, control execution. Legitimate use in production is rare (mostly debuggers and a handful of language-runtime helpers); use by attacker tooling is common — process injection, credential extraction from running processes, anti-debugging checks against the EDR itself. Because the legitimate base rate is so low, any `ptrace` event is worth investigating.

## Attack Technique

Mapped to **MITRE T1622 — Debugger Evasion** under **TA0005 — Defense Evasion**. Adversary uses of `ptrace` include: (1) attaching to a running process to extract secrets from its memory (e.g. SSH keys from `ssh-agent`, decrypted credentials from a long-running daemon); (2) injecting code into another process so the malicious code runs under the target process's identity; (3) detecting whether the attacker's own payload is being traced by a defender's debugger, and refusing to run if so. All three patterns trip this rule.

## How It Works

Pure signature on the syscall presence:

```
event type == 'ptrace'
```

The agent emits a `ptrace` event whenever the syscall is invoked. No baseline check is needed — the legitimate base rate is low enough that allowlisting (per process or per workload) is preferred to baselining.

## Investigation Steps

1. **Identify the tracer and the target.** `event.comm` is the process making the `ptrace` call; the syscall arguments name the target PID. A `ptrace` of an unrelated workload process is essentially diagnostic.
2. **Determine the ptrace operation.** `PTRACE_ATTACH` / `PTRACE_SEIZE` start a debugging session; `PTRACE_PEEKDATA` / `PTRACE_POKEDATA` read or write memory; `PTRACE_TRACEME` is benign anti-debugging. The operation narrows the intent immediately.
3. **Check the container's capabilities.** `ptrace` of another process requires the kernel's YAMA LSM allowance (`/proc/sys/kernel/yama/ptrace_scope`), `CAP_SYS_PTRACE`, or being the parent of the target. A container with `CAP_SYS_PTRACE` granted is itself a finding even if the call is benign.
4. **Inspect the target process.** If the target was a credential-holding daemon (`ssh-agent`, `gpg-agent`, the workload's own auth code), treat the secrets in its memory as exposed.
5. **Treat as serious incident.** The combination of low legitimate base rate and high attacker utility makes `ptrace` events high-signal.

## Remediation

**If malicious:** isolate the container (network policy or seccomp profile), preserve memory of both tracer and target, treat any in-memory secrets in the target process as exposed and rotate them (see "blast radius"), and rebuild from a known-good image.

**Hardening:** drop `CAP_SYS_PTRACE` from every container that does not legitimately debug (which is almost all of them). Apply seccomp policies that deny the `ptrace` syscall entirely on workloads that never use it. Set the host's `kernel.yama.ptrace_scope` sysctl to `2` (admin-only ptrace) or `3` (no ptrace at all) where the workload tolerates it.

**Legitimate uses:** debuggers (gdb, lldb, delve) attached to a running process during a kubectl-exec session; some language runtimes that briefly trace child processes; security tools that use ptrace for sandboxing. Allowlist these explicitly by process name.

## False Positives

- **Debug sessions** opened by operators via kubectl-exec or SSH. Expected and identifiable by the entry-point process.
- **Language runtimes that ptrace child processes** for sandboxing (some Python sandboxes, some Ruby debuggers). Allowlist by runtime image.
- **Container init systems** that briefly trace children during setup. Rare and identifiable by `event.pcomm`.
