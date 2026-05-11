# R0010 — Unexpected Sensitive File Access

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | Data from Local System (T1005) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects reads of `/etc/shadow` from a host or container by a process that was not observed reading it during learning. `/etc/shadow` holds hashed passwords for local accounts and is one of the highest-value files on a Linux system. With rare exceptions (PAM-using authentication processes during legitimate user login), no workload code path needs to read this file in steady state, so a hit is a strong indicator of credential theft in progress.

## Attack Technique

Mapped to **MITRE T1005 — Data from Local System** under **TA0006 — Credential Access**. Once an adversary has root or `CAP_DAC_READ_SEARCH` they typically reach for `/etc/shadow` immediately: hashed passwords can be cracked offline, used for password-spraying against other systems, or used directly if weak hashing or known passwords are in play. Containers that share the host's `/etc/shadow` via bind mount (a misconfiguration) are particularly dangerous because a container compromise yields host credentials.

## How It Works

The rule fires on any `open` of a path starting with `/etc/shadow` that was not part of the baseline:

```
event.path.startsWith('/etc/shadow')
  AND !ap.was_path_opened(containerId, event.path)
```

The prefix match covers `/etc/shadow` proper, `/etc/shadow-` (the backup), and `/etc/shadow.bak`-style variants that some attackers target.

## Investigation Steps

1. **Identify the reading process and user.** `event.comm`, `event.pid`, and the open flags reveal who and how. A read by an unfamiliar binary, a shell, or a network-facing service is essentially diagnostic. A read by `sshd`, `login`, `su`, `sudo`, or a known PAM-using process is usually benign.
2. **Check effective UID and capabilities.** Reading `/etc/shadow` requires either root (UID 0) or `CAP_DAC_READ_SEARCH`. The presence of this capability on a process that should not have it is a separate red flag.
3. **Determine the blast radius.** Every account with a hash now in the shadow file should be treated as potentially exfiltrated. Inventory the accounts, prioritize ones with weak or known-leaked passwords, and rotate (see "blast radius").
4. **Look for upstream activity.** A fresh exec, a privilege escalation event, or an unexpected capability use (R0004) typically precedes this read.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the process. If suspicious, rotate all local account passwords and isolate.

## Remediation

**If the read is malicious:** rotate every local-account password whose hash was in the file (see "blast radius"). Isolate the container or host (network policy or seccomp profile), preserve memory and disk, and audit whether any of the local accounts have been used for authentication elsewhere between the read and the rotation. Long-term hardening: do not bind-mount the host's `/etc/shadow` into containers, use SSO/IAM instead of local accounts where possible, and apply seccomp policies that deny `open` of `/etc/shadow` from workloads that never need it.

**If the read is legitimate:** allowlist the specific reading process. PAM-using processes are the most common legitimate readers; others should be allowlisted with skepticism.

## False Positives

- **PAM-using processes that were not exercised during learning.** A workload that supports SSH login but had no logins during the learning window may not have baselined the `sshd → unix_chkpwd` read of `/etc/shadow`.
- **Backup and integrity-monitoring tools** that hash sensitive files. Allowlist by process; ensure the tool itself is not a vector.
- **Configuration management agents** (Ansible, Puppet, Chef) that read `/etc/shadow` for state checks. Rare in containers; common on hosts.
