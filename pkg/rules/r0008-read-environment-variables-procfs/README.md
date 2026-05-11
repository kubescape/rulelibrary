# R0008 — Read Environment Variables from procfs

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | Unsecured Credentials: Credentials In Files (T1552.001) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects reads of `/proc/<pid>/environ` by a process that was not observed reading the procfs environ files during learning. The `environ` file exposes the environment variables of a running process, which on most workloads contain API keys, database passwords, cloud credentials, OAuth secrets, and other high-value material that adversaries explicitly target. A read of any process's `environ` from inside a container is rare in normal operation and almost always indicates credential harvesting.

## Attack Technique

Mapped to **MITRE T1552.001 — Unsecured Credentials: Credentials In Files** under **TA0006 — Credential Access**. Environment variables are a common but insecure place to put secrets (twelve-factor apps still recommend it, container orchestrators still inject secrets this way), and adversaries know it. Reading `/proc/*/environ` walks every process on the host or container in one shot and harvests whatever was in their environment at exec time — including secrets that were deleted from the filesystem.

## How It Works

The rule fires on any `open` event matching the procfs environ path that was not observed during learning:

```
event.path.startsWith('/proc/')
  AND event.path.endsWith('/environ')
  AND !ap.was_path_opened_with_suffix(containerId, '/environ')
```

The suffix-based suppression covers both `/proc/self/environ` and `/proc/<pid>/environ` paths, so legitimate self-reads (an app reading its own environment) are correctly allowlisted by the workload's baseline if they happened during learning.

## Investigation Steps

1. **Identify the reading process.** `event.comm`, `event.pid`, and `event.path` together describe the access. Reading another process's environ is much more concerning than reading `/proc/self/environ`.
2. **List which environs were read.** A single self-read may be a debugging library; a sweep across `/proc/[0-9]+/environ` is essentially diagnostic of credential harvesting.
3. **Determine the blast radius.** Whatever was in the read process's environment is now in the attacker's hands. Inventory the secrets injected as environment variables across the affected workload(s) and rotate them.
4. **Look for upstream activity.** A new shell, a fresh binary, or an unexpected `exec` typically precedes a credential-harvest sweep.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the reading process. If suspicious, rotate exposed credentials and isolate.

## Remediation

**If the read is malicious:** rotate every credential that was in the environment of any read process, immediately (see "blast radius"). Isolate the source container (network policy or seccomp profile), preserve memory and disk, and audit whether the rotated credentials were used elsewhere between the read and the rotation. Long-term hardening: move secrets out of environment variables and into a secrets manager (Kubernetes Secrets mounted as files, Vault, AWS Secrets Manager) with rotation enabled.

**If the read is legitimate:** allowlist the specific reading process via a per-rule policy. Self-environ reads from a known library are common; cross-process reads are not, and should be allowlisted with skepticism.

## False Positives

- **Self-introspection libraries** that read `/proc/self/environ` for diagnostic purposes. If they ran during learning they are already baselined; if added later, allowlist by process.
- **APM and profiler agents** that enumerate processes for metrics may touch `environ` on each. Allowlist by agent name.
- **In-container debuggers and orchestrators** that walk procfs are inherently broad readers and may be better off having R0008 disabled on the workload.
