# R1000 — Process Executed from Malicious Source

| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects any process whose executable, current working directory, or invocation path resolves to `/dev/shm`. `/dev/shm` is a `tmpfs` mount that is world-writable, in memory, and persists for the lifetime of the container — exactly the properties an adversary wants for staging payloads while evading on-disk forensics. Legitimate workloads almost never execute binaries from `/dev/shm`, so a hit on this rule is a strong indicator of an in-progress intrusion.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under **TA0002 — Execution**. The concrete tradecraft this rule catches is the "fileless" / "in-memory" staging pattern: an attacker who lands code via an exploit, a curl-piped script, or a download writes the payload to `/dev/shm`, then `execve()`s it. This avoids leaving artifacts on the persistent filesystem, evades file-integrity monitors that watch `/usr` and `/bin`, and skips path-based allowlists that focus on canonical locations. Cryptominers, reverse shells, and post-exploitation toolkits routinely use this pattern.

## How It Works

The rule is a pure signature — it does not depend on any baseline or learning. On every `exec` event it checks three signals:

```
exepath == '/dev/shm' || exepath.startsWith('/dev/shm/')
  OR
cwd == '/dev/shm' || cwd.startsWith('/dev/shm/')
  OR
parse.get_exec_path(args, comm).startsWith('/dev/shm/')
```

The `startsWith('/dev/shm/')` form (with trailing slash) is intentional: it matches `/dev/shm/foo` but **not** `/dev/shm_fake/foo`, avoiding false matches on similarly-named directories. The current-working-directory check catches the variant where a relative path (`./run.sh`) is executed from inside `/dev/shm` even though `exepath` itself resolves elsewhere.

## Investigation Steps

1. **Capture the payload before it disappears.** `/dev/shm` is volatile — files can vanish on container restart. If safe, hash and exfiltrate `event.exepath` immediately for static analysis.
2. **Trace the ingress.** Look back from the alert timestamp for the activity that put the file there: a `write()` event into `/dev/shm/*`, a recent `curl` / `wget`, a shell launched from a network-facing process, or an `exec` of a downloader script.
3. **Check the parent process and user.** A `nobody`-uid process spawned by `nginx`/`apache`/`node` executing from `/dev/shm` is essentially never legitimate. The parent chain often points directly at the exploited entry point.
4. **Search for lateral activity.** While `/dev/shm` execution suggests an attacker is mid-flight, also pull DNS lookups, outbound connections, credential file reads, and capability/privilege-escalation alerts on the same container.
5. **Treat as confirmed intrusion until proven otherwise.** Given the severity and the rarity of legitimate hits, default to incident response posture, not triage-and-dismiss.

## Remediation

**Active intrusion:** isolate the container immediately (network policy or seccomp profile), preserve `/dev/shm` and process memory if your tooling supports it, identify and revoke any credentials reachable from the workload, and rebuild from a known-good image. Treat all in-cluster lateral targets reachable from this container as potentially compromised until proven otherwise.

**Hardening to prevent recurrence:**

- Mount `/dev/shm` with `noexec` where the workload tolerates it. This stops the technique at the kernel level.
- Limit the size of `/dev/shm` so it cannot hold large payloads.
- Drop unnecessary Linux capabilities (`CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`) so the attacker cannot remount `/dev/shm` exec.
- Apply read-only root filesystems where possible to remove other staging locations.

## False Positives

- **Workloads that legitimately use `/dev/shm` for shared memory IPC.** A small set of applications (some databases, video pipelines, scientific compute) place named files in `/dev/shm` for cross-process communication. They typically `mmap` those files, not `execve` them — execution of `/dev/shm` content is rare even for these workloads.
- **Specialized debug or profiling tooling.** A few APM/profiler agents drop helper binaries in `/dev/shm` at startup. These should be allowlisted explicitly rather than disabling the rule.
- **Test fixtures and CI runners.** Some CI systems stage temporary executables in tmpfs paths. Audit the build pipeline before allowlisting.

The base rate of legitimate `/dev/shm` execution is low enough that the rule is high-fidelity by default. False positives are best handled by per-workload exceptions, not by disabling the rule globally.
