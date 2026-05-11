# R1011 — ld_preload Hook Technique

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects two related techniques that use the Linux dynamic linker to inject code into processes: (1) running a process with the `LD_PRELOAD` environment variable set (so the linker loads attacker-supplied shared objects before the program's own dependencies), and (2) writes to `/etc/ld.so.preload` (a system-wide file that the linker reads at every exec, achieving the same code injection without needing to set environment variables). The rule is disabled by default because some legitimate runtimes (Java's `LD_PRELOAD`, MATLAB containers) use these mechanisms.

## Attack Technique

Mapped to **MITRE T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking** under **TA0005 — Defense Evasion**. `LD_PRELOAD` is a foundational primitive for Linux userland rootkits: a malicious `.so` loaded into every process can intercept libc calls, hide files from `ls`, hide processes from `ps`, intercept network connections, and redirect logging. The system-wide `/etc/ld.so.preload` variant achieves the same effect with one write to one file, surviving subsequent process launches.

## How It Works

Two event types, evaluated independently:

```
exec:
  event.comm != 'java'
    AND event.containerName != 'matlab'
    AND process.get_ld_hook_var(event.pid) != ''

open:
  event.path == '/etc/ld.so.preload'
    AND event.flagsRaw is set and non-zero
```

The exec arm reads the running process's `LD_PRELOAD` variable from procfs; if non-empty (and the process is not one of the well-known legitimate users), it fires. The open arm fires whenever `/etc/ld.so.preload` is opened with any flags set — usually because something is writing it. The two-process allowlist (`java`, `matlab`) covers the most common legitimate users; other legitimate uses should be allowlisted via a per-rule policy rather than expanding the rule's hardcoded list.

## Investigation Steps

1. **Identify which arm fired.** The exec arm tells you a process started with `LD_PRELOAD` set; the open arm tells you `/etc/ld.so.preload` was opened (almost certainly written). They sometimes fire together when an attacker is establishing persistence.
2. **For the exec arm: capture the preloaded library.** `process.get_ld_hook_var(event.pid)` returns the path(s) of the preloaded shared object(s). Read or hash these binaries before the attacker cleans up; static analysis of a userland rootkit's `.so` is usually fast and revealing.
3. **For the open arm: read the file content.** `/etc/ld.so.preload` listing one or more paths means every subsequent exec on the host (or container if locally scoped) will load those libraries. The listed paths are the rootkit components.
4. **Identify the persisting process.** Whoever set `LD_PRELOAD` or wrote `/etc/ld.so.preload` is the active loader. Walk the parent chain to find the entry point.
5. **Treat as persistence in flight.** Even if the immediately-affected process is benign, the same vector affects every subsequent exec.

## Remediation

**Active intrusion:** remove the offending entry — unset `LD_PRELOAD` from the affected process's environment (often requires killing and respawning), and delete or restore `/etc/ld.so.preload` to empty. Capture the malicious `.so` for analysis. Isolate the workload (network policy or seccomp profile), preserve memory, rotate credentials reachable from the workload (see "blast radius"), and rebuild from a known-good image since rootkit techniques often plant multiple persistence mechanisms.

**Hardening:** mount `/etc/ld.so.preload` read-only or via an immutable filesystem mount. Apply seccomp policies that deny writes to `/etc/ld.so.preload`. Drop `CAP_DAC_OVERRIDE` from containers so an attacker cannot write to root-owned files. For workloads that need a legitimate `LD_PRELOAD`, allowlist the specific library path rather than disabling the rule.

## False Positives

- **Java workloads** using `LD_PRELOAD` for native-library shimming. The rule excludes `java` by name, but Java wrappers or JVM forks with different process names may still trigger. Allowlist by image or by the specific wrapper.
- **APM and profiler agents** that inject via `LD_PRELOAD` (some attach mechanisms work this way). Allowlist by agent name and SHA.
- **Custom build wrappers** in CI that preload sanitizers or instrumentation libraries.
