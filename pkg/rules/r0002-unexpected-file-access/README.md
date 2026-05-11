# R0002 — Files Access Anomalies in container

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Collection (TA0009) |
| MITRE Technique | Data from Local System (T1005) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects reads of sensitive system locations inside a host or container that were not observed during the learning window. The rule watches a curated set of high-value directories (`/etc/`, `/var/log/`, `/var/run/`, `/run/`, `/var/spool/cron/`, `/var/www/`, `/var/lib/`, `/opt/`, `/usr/local/`, `/app/`, plus the marker files `/.dockerenv` and `/proc/self/environ`) and fires whenever a process opens a path under one of them that the application profile did not record. The rule is disabled by default because steady-state false-positive rate depends heavily on the workload's file-access patterns.

## Attack Technique

Mapped to **MITRE T1005 — Data from Local System** under **TA0009 — Collection**. Once an adversary has code execution they typically read configuration, application code, secrets, and logs to understand the environment and to harvest material. This rule surfaces that reconnaissance against the workload's own observed file-access shape, catching reads of files the workload itself never needs.

## How It Works

The node agent records every `open` event in the watched prefixes during the learning window. After the profile is finalized, every subsequent `open` in those prefixes is checked against the profile, with three explicit suppressions baked into the rule body:

```
event.path is under one of the watched prefixes
  AND event.path is NOT under /run/secrets/kubernetes.io/serviceaccount
  AND event.path is NOT under /var/run/secrets/kubernetes.io/serviceaccount
  AND event.path is NOT under /tmp
  AND !ap.was_path_opened(containerId, event.path)
```

The `/tmp` and Kubernetes service-account paths are excluded because they have their own dedicated rules; including them here would produce duplicate alerts on the same activity.

## Investigation Steps

1. **Identify the process and the file.** Look at `event.comm`, `event.pid`, and `event.path`. A new shell or a network-facing process reading `/etc/passwd`, `/etc/nginx/`, or `/var/lib/postgresql` is much more concerning than a known internal tool opening a known path.
2. **Confirm the path is sensitive in context.** `/etc/` reads can be benign (libc reading `/etc/nsswitch.conf`) or critical (`/etc/shadow`, `/etc/cron.d/*`). Use the path semantics, not just the prefix, to triage.
3. **Look at the parent process and user.** A `nobody`-uid process spawned by a web server reading `/var/www/` configuration is essentially never legitimate.
4. **Pull surrounding events** for the same container in the same window: exec events, network connections, or other R0002 hits in adjacent directories indicate active enumeration.
5. **Decide: legitimate change or attack.** If legitimate, suppress the specific file or workload via a per-rule allowlist. If suspicious, isolate and begin incident response.

## Remediation

**If the access is malicious:** isolate the container (network policy or seccomp profile), preserve disk and memory for forensics, rotate any credentials reachable from the file content (see "blast radius"), and begin standard incident response. The opening process's ancestry usually identifies the ingress vector.

**If the access is legitimate:** suppress the specific path or process for the workload via a per-rule allowlist policy. Do not retrain the profile as a remediation step.

Some workloads are by definition not fit for application-profile anomaly detection: software orchestrators, CI/CD tools, runners — anything where the process and file-access cycle is detached from the container or host run cycle. R0002 is best disabled on such workloads rather than allowlisted item-by-item.

## False Positives

- **Periodic jobs that did not run during learning.** Weekly cron tasks, monthly batch jobs, ad-hoc admin scripts, and infrequent maintenance tools may open files under the watched prefixes for the first time after the profile is finalized. Lengthen the learning window or pre-warm the profile.
- **Self-updating runtimes and package managers.** Some interpreters and language toolchains touch `/etc/` or `/usr/local/` files on first invocation; these may not appear in the recorded baseline.
- **Build orchestrators and runners.** Workloads like Apache Spark or CI runners that ship per-job binaries and config will read configuration files the profile never saw.
