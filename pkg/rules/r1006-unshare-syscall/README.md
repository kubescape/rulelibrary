# R1006 — Process tries to escape container

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Privilege Escalation (TA0004) |
| MITRE Technique | Escape to Host (T1611) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects calls to the `unshare` syscall from any process other than `runc` inside a host or container, when the syscall was not part of the application profile's recorded syscall set. `unshare` is the kernel primitive that creates new namespaces, and legitimate use inside an already-namespaced container is exceedingly rare — the container runtime (`runc`) itself uses it once at container setup, after which the workload's processes do not need it. Adversaries use `unshare` as a building block for container-escape techniques that combine namespace manipulation with other primitives (mount syscalls, capability handoffs) to reach the host.

## Attack Technique

Mapped to **MITRE T1611 — Escape to Host** under **TA0004 — Privilege Escalation**. Container escape from a less-privileged container typically requires manipulating Linux namespaces: leaving the user namespace to gain real root, leaving the mount namespace to access the host filesystem, leaving the PID namespace to interact with host processes. `unshare` (alongside `setns` and `clone` with namespace flags) is the syscall that performs these manipulations. Detecting on it catches the escape attempt early, before the attacker can complete the chain.

## How It Works

```
event.pcomm != 'runc'
  AND !ap.was_syscall_used(containerId, 'unshare')
```

The first clause filters out the one legitimate caller (the container runtime during setup). The second suppresses any workload that was observed using `unshare` during learning, which is uncommon but not impossible for some niche workloads.

## Investigation Steps

1. **Identify the calling process and its parent.** `event.comm` and `event.pcomm` tell you who and from where. An `unshare` call from a shell, a freshly-dropped binary, or a network-facing process is essentially diagnostic of an escape attempt.
2. **Check the container's capabilities.** `unshare` for most namespace types requires `CAP_SYS_ADMIN`. If the container has it, the call may succeed; if it does not, the call failed but the attempt is still highly suspicious.
3. **Inspect surrounding syscalls.** Escape chains typically combine `unshare` with `setns`, `mount`, `pivot_root`, or `chroot` calls. Looking at the syscall sequence shows whether this is a probe or a complete escape attempt.
4. **Determine whether the escape succeeded.** If the process is no longer in the container's PID namespace (visible from host-level tooling), assume host compromise.
5. **Treat as serious incident.** Even an attempted escape indicates the attacker has root-equivalent privileges inside the container.

## Remediation

**Active escape attempt:** isolate the container (network policy or seccomp profile), preserve memory, capture syscall traces if possible, and if the escape may have succeeded, treat the host as compromised and isolate it as well (see "blast radius"). Trace the upstream activity that allowed the attacker to call `unshare` in the first place — usually a freshly-dropped binary and an over-permissive capability set.

**Hardening:** drop `CAP_SYS_ADMIN` from every container that does not strictly require it (which is almost all of them). Apply seccomp policies that deny the `unshare` syscall entirely on workloads that never use it. Use a less-privileged container runtime where possible (gVisor, kata-containers) to add another isolation layer.

**Legitimate use:** rare. Some specialized workloads (container-in-container CI runners, sandbox tools) legitimately call `unshare`. Allowlist these explicitly rather than disabling the rule.

## False Positives

- **Container-in-container patterns** where the workload itself runs other containers (CI runners, k3d, etc.). These genuinely need `unshare` and are best allowlisted by process.
- **Sandboxing tools** like Firejail, Bubblewrap, or unshare-based test harnesses inside a container.
- **Custom init systems** that re-namespace processes during workload bootstrap. Rare; identifiable by process name and parent.
