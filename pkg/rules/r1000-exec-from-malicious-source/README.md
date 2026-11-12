# R1000 — Process Executed from Malicious Source

| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects any process whose executed file, executable, or current working directory resolves to `/dev/shm`. `/dev/shm` is a `tmpfs` mount that is world-writable, in memory, and persists for the lifetime of the container — exactly the properties an adversary wants for staging payloads while evading on-disk forensics. Legitimate workloads almost never execute binaries from `/dev/shm`, so a hit on this rule is a strong indicator of an in-progress intrusion.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under **TA0002 — Execution**. The concrete tradecraft this rule catches is the "fileless" / "in-memory" staging pattern: an attacker who lands code via an exploit, a curl-piped script, or a download writes the payload to `/dev/shm`, then `execve()`s it. This avoids leaving artifacts on the persistent filesystem, evades file-integrity monitors that watch `/usr` and `/bin`, and skips path-based allowlists that focus on canonical locations. Cryptominers, reverse shells, and post-exploitation toolkits routinely use this pattern.

## How It Works

The rule is a pure signature — it does not depend on any baseline or learning. On every `exec` event it checks three signals:

```
exepath == '/dev/shm' || exepath.startsWith('/dev/shm/')
  OR
cwd == '/dev/shm' || cwd.startsWith('/dev/shm/')
  OR
file == '/dev/shm' || file.startsWith('/dev/shm/')
```

The `startsWith('/dev/shm/')` form (with trailing slash) is intentional: it matches `/dev/shm/foo` but **not** `/dev/shm_fake/foo`, avoiding false matches on similarly-named directories. The current-working-directory check catches the variant where a relative path (`./run.sh`) is executed from inside `/dev/shm` even though `exepath` itself resolves elsewhere. The third clause checks `event.file`, the file the kernel executed (`d_path(bprm->file)`). It differs from `exepath` for a shebang script or a binfmt_misc binary: `exec /dev/shm/run.sh` with `#!/bin/sh` has `file` `/dev/shm/run.sh` but `exepath` `/bin/sh` (resolved), so only this clause sees the script. `event.file` is empty when an agent can't resolve it, and then the clause is simply false.

Earlier versions checked `argv[0]` here. Since Inspektor Gadget v0.57, `event.args` is the real argv, and `argv[0]` is chosen by the caller: for a shebang script it's the interpreter, and `exec -a /dev/shm/x sleep 100` sets it to anything. That missed shebang scripts in `/dev/shm` and let a spoofed `argv[0]` fire the rule.

The alert message and `uniqueId` report `event.file`, falling back to `exepath` when it's empty, so a shebang hit names the script rather than `/bin/sh`.

## Agent version gate

`agentVersionRequirement: ">=0.3.307"`. `event.file` is registered in CEL from kubescape/node-agent v0.3.307 (kubescape/node-agent#1065). Older agents don't register the field, so the rule would fail to compile there; the rules watcher skips a gated rule before compiling it, and those agents don't run R1000. Prerelease agent builds (for example `v0.3.310-rc.1`) don't satisfy the constraint either, which is how Masterminds/semver treats prereleases. The gate fails open: an agent whose `AGENT_VERSION` is unset or not a semantic version (for example the image tag `latest`) loads R1000 anyway, and an older one then logs a compile warning and never matches it.

Agents that use a different version line must replace this requirement with their own floor when they consume the rule.

## Investigation Steps

1. **Capture the payload before it disappears.** `/dev/shm` is volatile — files can vanish on container restart. If safe, hash and exfiltrate the executed file (`event.file`, or `event.exepath` when it's empty) immediately for static analysis.
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
