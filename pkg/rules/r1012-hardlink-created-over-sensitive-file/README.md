# R1012 — Hard Link Created Over Sensitive File

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | Data from Local System (T1005) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects the creation of a hard link whose target is `/etc/shadow` or `/etc/sudoers` (or any path beginning with those prefixes), by a process whose application profile does not include legitimate access to that target. Hard links create a second name for the same inode, sharing data and permissions but living in a directory the attacker controls. Unlike symlinks, hardlinks survive deletion of the original name and do not have a separate file mode, which makes them harder to audit and harder to remove cleanly.

## Attack Technique

Mapped to **MITRE T1005 — Data from Local System** under **TA0006 — Credential Access**. The hardlink trick complements symlink games: an attacker who can hardlink `/etc/shadow` into a path they own can read the hash content through their own filename, defeating audit rules that watch only `/etc/shadow` by path string. Some defenses that monitor file access by path will miss the hardlinked read entirely; the inode is the same, but the path differs.

## How It Works

```
(event.oldPath.startsWith('/etc/shadow') OR event.oldPath.startsWith('/etc/sudoers'))
  AND !ap.was_path_opened(containerId, event.oldPath)
```

`event.oldPath` is the hardlink's target (the existing file the new name will share an inode with). The rule fires when the target is sensitive and the workload was not observed legitimately opening that target during learning.

## Investigation Steps

1. **Identify the new hardlink and its target.** `event.newPath` is where the new name was placed, `event.oldPath` is the existing file. The new name's location often reveals intent (a hardlink in `/tmp/` pointing at `/etc/shadow` is for the attacker; a hardlink in a path a privileged process reads is a trap).
2. **Identify the creating process.** `event.comm` and the parent process show who. An unfamiliar binary creating hardlinks into sensitive paths is essentially diagnostic.
3. **Look for the read of the hardlinked path.** A read of `event.newPath` shortly after the link is created completes the attack — the attacker (or a tricked privileged process) reads sensitive content through their controlled name.
4. **Inventory other hardlinks.** `find / -inum <inode>` against the sensitive file's inode reveals every name currently pointing at it; an attacker may have planted more than one.
5. **Treat as confirmed credential-access attempt.** Legitimate hardlinks to `/etc/shadow` or `/etc/sudoers` are essentially nonexistent in normal workloads.

## Remediation

**Active intrusion:** remove the hardlink (unlink the new name, which leaves the original intact; verify by checking the link count on the original file). Audit reads that may have followed via the attacker-controlled path. Rotate credentials whose hashes could have been exposed (see "blast radius"), isolate the workload, and rebuild from a known-good image.

**Hardening:** Linux's `fs.protected_hardlinks` sysctl (set to 1) on the host prevents users from hardlinking files they do not own — apply at the host level. Apply seccomp policies that deny the `link` and `linkat` syscalls on workloads that never legitimately create hardlinks. Do not bind-mount sensitive host files into containers.

## False Positives

- **Backup and snapshot tools** that use hardlink-based deduplication (rsnapshot, restic in some configurations). These should be allowlisted by process.
- **Configuration management tools** that hardlink during atomic file replacement patterns. Rare for sensitive files.
- **Container-image extraction tools** that use hardlinks to represent shared image layers. Identifiable by process and namespace.
