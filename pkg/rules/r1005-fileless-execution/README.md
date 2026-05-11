# R1005 — Fileless Execution

| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Process Injection (T1055) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects `exec` calls where the executable backing the process is not a file on disk: a `memfd` (anonymous in-memory file), a `/proc/self/fd/<n>` reference, or a `/proc/<pid>/fd/<n>` reference to a file descriptor that holds the executable image directly. These execution paths leave no on-disk artifact, defeating file-integrity monitoring, antivirus scanners, and audit pipelines that hash binaries before allowing them to run. They are heavily used by modern Linux malware and post-exploitation frameworks.

## Attack Technique

Mapped to **MITRE T1055 — Process Injection** under **TA0005 — Defense Evasion**. The "fileless execution" tradecraft has three common shapes: (1) `memfd_create()` followed by writing the payload and `fexecve()` — the payload exists only in kernel memory tied to a file descriptor; (2) downloading a binary, then `execve('/proc/self/fd/N')` against a still-open file descriptor — the file is unlinked or never written to a stable path; (3) similar techniques against another process's open file descriptors. All three avoid the conventional "write binary to disk, run binary" pattern that most defenders watch.

## How It Works

Pure signature on the executable path:

```
event.exepath.contains('memfd')
  OR event.exepath.startsWith('/proc/self/fd')
  OR event.exepath.matches('/proc/[0-9]+/fd/[0-9]+')
```

No baseline is needed because legitimate use of these execution paths in a normal workload is essentially nil — these are deliberate evasion primitives.

## Investigation Steps

1. **Capture as much of the running process as possible.** The binary is in memory, not on disk. If your tooling supports memory dumping (gcore, criu, or platform equivalent), capture the process image before it exits.
2. **Identify the parent and how the payload arrived.** Look for the syscalls that created the in-memory image: a `memfd_create` immediately before, a downloader process feeding bytes via pipe, or a network connection delivering the payload directly into a file descriptor.
3. **Inspect the process tree.** Fileless execution is rarely a single event — the parent and grandparent processes usually reveal the loader chain (initial exploit, downloader, fileless payload).
4. **Pull surrounding events.** Outbound network connections (R0011), DNS anomalies (R0005), or credential reads frequently surround a fileless execution.
5. **Treat as confirmed intrusion until proven otherwise.** The legitimate base rate for these patterns is near zero.

## Remediation

**Active intrusion:** isolate the container immediately (network policy or seccomp profile), preserve process memory if your tooling supports it, identify and revoke any credentials reachable from the workload (see "blast radius"), and rebuild from a known-good image. The fileless payload typically disappears on container restart; capture it before then or accept that you will only have process metadata.

**Hardening:** apply seccomp policies that deny `memfd_create` and reject `execve` against `/proc/*/fd/*` paths for workloads that never legitimately use them. Drop `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` so an attacker cannot pivot to another process's file descriptors. Mount the container's root filesystem read-only where the workload tolerates it.

## False Positives

- **Just-in-time compilers and dynamic loaders** that legitimately use `memfd_create` to stage generated code. Some language runtimes do this; if so, allowlist by process name and consider whether the workload needs JIT at all.
- **Container init systems** that briefly use `memfd` patterns during setup. Rare and identifiable by process name.

The base rate of legitimate hits is low enough that false positives should be handled by per-workload exceptions, not by disabling the rule globally.
