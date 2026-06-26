# R0040 — Unexpected Process Arguments

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Execution (TA0002) |
| MITRE Technique | Command and Scripting Interpreter (T1059) |
| Platforms | Host/Kubernetes/ECS |
| Requires Application Profile | Yes |

## Description

Detects a process whose executable **is** part of the container's learned application profile but which is invoked with an **argv vector that was never observed during learning**. Where R0001 fires when an unknown *binary* runs, R0040 narrows in on the next layer: a known, allowed binary being driven with unexpected arguments — `curl` reaching a new URL, `sh -c <payload>`, a package manager asked to install something, or an interpreter handed a script it never ran in the baseline.

The rule deliberately stays silent when the path itself is unknown (that is R0001's job) and when the argv vector matches any recorded pattern for that path, so it only adds signal on top of an already-allowed executable.

## Attack Technique

Mapped to **MITRE T1059 — Command and Scripting Interpreter** under tactic **TA0002 — Execution**. Living-off-the-land attacks frequently reuse binaries that are already present and already allowed in the workload — shells, interpreters, and network tools — and the malicious intent lives entirely in the *arguments*. A baseline that records only "binary X ran" misses this; R0040 closes that gap by also pinning the argument shape each allowed binary was seen with.

## How It Works

During the learning window the node agent records, per container, each `exec` event's executable path **and** its argv vector. The projection layer exposes those vectors as the `ExecsByPath` composite-key surface (path → list of recorded argv vectors). After the profile is finalized, every `exec` whose path is in the profile is re-checked against the recorded vectors.

Simplified CEL:

```
ap.was_executed(containerId, parse.get_exec_path(args, comm, exepath))
  && !ap.was_executed_with_args(containerId, parse.get_exec_path(args, comm, exepath), args)
```

- The first clause gates on the path being **known** — an unknown path is R0001's domain, not R0040's.
- `ap.was_executed_with_args` looks the resolved path up in `ExecsByPath` and asks storage's `dynamicpathdetector.MatchExecArgs` whether the runtime argv matches **any** recorded vector for that path. The rule fires only when none match.

Argument matching uses dedicated sentinels, not shell globbing:

- `⋯⋯` (`ExecArgsWildcard`) — matches zero or more trailing args.
- `⋯` (`DynamicIdentifier`) — matches exactly one arg / one embedded segment (e.g. a versioned binary name).
- `*` is a **literal** character, never a wildcard.

Back-compat: profiles compiled by older storage versions that never populated `ExecsByPath` are treated as having no argv constraint, so R0040 stays silent on them rather than alerting on every exec.

## Investigation Steps

1. **Read the argv off the alert.** `event.args` (and the `argv=` suffix in the message) shows exactly how the allowed binary was invoked. Compare it against what the workload legitimately does — a new URL on `curl`, a `-c` one-liner on `sh`/`bash`, or an install/download subcommand are high-signal.
2. **Identify the parent.** `pcomm`/`ppid` reveal who launched it. A known tool driven by an unexpected parent (e.g. `sh` spawned by a web server) is far more concerning than the same tool under its normal supervisor.
3. **Confirm it is not a legitimate change.** A new image version, config, or feature flag can legitimately introduce a new argument shape the profile never saw. Check recent deployments and CI/CD activity.
4. **Pull surrounding events.** Look for correlated alerts on the same container in the same window — network egress, file writes, capability changes. Argument-level abuse rarely fires alone.
5. **Decide: legitimate drift or attack.** If legitimate, retrain or allowlist (see Remediation). If suspicious, isolate the container and begin incident response.

## Remediation

**If the invocation is malicious:** isolate the container, preserve disk/memory for forensics, rotate any credentials reachable from the container, and trace the parent/ingress vector that allowed the exec.

**If the invocation is legitimate but the profile is stale:**

- Retrain the profile so the new argv vector is recorded, or
- Add a per-rule allowlist entry for the specific binary/argument shape on that workload.

**Do not blanket-disable R0040 on workloads with a small, stable command surface** — it is the only rule that detects abuse of *already-allowed* binaries via their arguments. As with R0001, workloads whose invocation cycle is detached from the container/host run cycle (CI runners, job orchestrators) are poor fits for argument-level anomaly detection and are better excluded than left noisy.

## False Positives

- **Argument shapes not exercised during learning.** Periodic jobs, ad-hoc maintenance commands, or rarely-used subcommands of an allowed binary can be missed by a short learning window. Lengthen the window or pre-warm the profile.
- **Dynamic arguments** — timestamps, request IDs, generated file names, or per-run URLs — produce argv vectors that differ every run. Use the recorded wildcard sentinels (`⋯` / `⋯⋯`) in the profile to express the variable positions, or allowlist the binary.
- **Runners and execution orchestrators** whose argument set is, by design, unbounded (e.g. Apache Spark shipping per-job binaries and flags).
