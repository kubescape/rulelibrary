# R1010 — Symlink Created Over Sensitive File

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | Data from Local System (T1005) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects the creation of a symbolic link whose target is `/etc/shadow` or `/etc/sudoers` (or any path beginning with those prefixes), by a process whose application profile does not include access to that target. Symlink creation against sensitive files is a classic privilege-escalation and credential-access trick: an attacker who can write a symlink into a directory readable by a more privileged process can cause that process to read the sensitive target through the symlinked path, bypassing access controls or audit rules that watch only direct opens.

## Attack Technique

Mapped to **MITRE T1005 — Data from Local System** under **TA0006 — Credential Access**. The "symlink games" tradecraft has two main shapes: (1) a less-privileged attacker creates a symlink at a path that a more-privileged process will read, redirecting the privileged read to a sensitive file; (2) an attacker creates the symlink themselves and reads through it to bypass audit rules that match on the target path string rather than the resolved inode. Either way, the symlink creation event is the earliest catch-point before the actual sensitive data is exposed.

## How It Works

```
(event.oldPath.startsWith('/etc/shadow') OR event.oldPath.startsWith('/etc/sudoers'))
  AND !ap.was_path_opened(containerId, event.oldPath)
```

`event.oldPath` is the symlink's target (what it points at). The rule fires when the target is one of the sensitive prefixes and the workload was not observed legitimately opening that target during learning. The profile check exists so workloads that genuinely read these files during normal operation (like PAM-using authentication code) suppress the rule.

## Investigation Steps

1. **Identify the new symlink and its target.** `event.newPath` is where the symlink was placed, `event.oldPath` is what it points at. The location of the symlink often reveals the intent: a symlink at `/tmp/x` pointing to `/etc/shadow` is for the attacker's own use; a symlink at a path the workload's privileged process is about to read is a trap for that process.
2. **Identify the creating process.** `event.comm` and parent process point at who set the trap. An unfamiliar binary creating symlinks into sensitive paths is essentially diagnostic.
3. **Look for the consumer.** A privileged process opening the symlink path shortly after creation completes the attack. Cross-correlate symlink creation with subsequent opens on the symlink path.
4. **Inventory other symlinks.** Attackers rarely set just one. Walk the workload's filesystem for symlinks targeting sensitive paths.
5. **Treat as confirmed credential-access attempt.** The legitimate base rate of symlinks to `/etc/shadow` or `/etc/sudoers` is essentially zero.

## Remediation

**Active intrusion:** remove the symlink, identify and audit any reads that may have followed it (was the privileged process tricked into reading the sensitive file?), rotate any credentials whose hashes could have been exposed (see "blast radius"), isolate the workload, and rebuild from a known-good image.

**Hardening:** apply seccomp policies that deny `symlink`/`symlinkat` syscalls on workloads that never legitimately create symlinks. Use Linux's `fs.protected_symlinks` sysctl (set to 1) on the host to prevent the most common symlink-following attacks. Mount sensitive directories read-only inside containers; do not bind-mount the host's `/etc/shadow` or `/etc/sudoers` into containers.

## False Positives

- **Backup and snapshot tools** that legitimately symlink sensitive files for archival. These should be explicitly allowlisted by process.
- **Configuration management tools** (Ansible, Puppet) that create symlinks for `/etc/shadow` rotation patterns. Rare; identifiable by process name.
- **Distribution-specific PAM helpers** that legitimately symlink shadow during early boot of some minimal containers.
