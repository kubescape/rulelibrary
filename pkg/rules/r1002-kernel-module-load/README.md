# R1002 — Process tries to load a kernel module

| Field | Value |
|-------|-------|
| Severity | Critical |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Boot or Logon Autostart Execution: Kernel Modules and Extensions (T1547.006) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects the loading of a Linux kernel module via the `init_module` or `finit_module` syscalls from a host or container. Loaded kernel modules run with full kernel privilege and can do anything the kernel can: hide processes, intercept syscalls, modify network traffic, install persistent rootkits, and disable other security controls. Almost nothing in a properly-engineered container workload needs to load kernel modules in steady state, so any hit is a strong indicator of either successful host compromise or attempted privilege escalation.

## Attack Technique

Mapped to **MITRE T1547.006 — Kernel Modules and Extensions** under **TA0005 — Defense Evasion**. Loading a kernel module is one of the highest-impact actions a process can take: it gives the attacker code execution in ring 0 with no MMU isolation from anything else on the host. Adversary tradecraft includes loading rootkit modules to hide processes and files, loading modules that disable other LKM-based security tools, and loading modules that survive container restart by attaching at the host kernel level.

## How It Works

Pure signature on syscall name:

```
event.syscallName == 'init_module' || event.syscallName == 'finit_module'
```

No baseline check is needed because the legitimate use of these syscalls inside a container is essentially zero — kernel modules are loaded from the host, not from container userland.

## Investigation Steps

1. **Identify the loading process and module.** `event.comm`, `event.pid`, and `event.module` describe what was attempted. A known node-level driver bootstrap (e.g. NVIDIA driver install, custom networking driver) is a different situation from an unknown binary loading an unknown module.
2. **Confirm the container had the capability.** Loading requires `CAP_SYS_MODULE`. Containers should almost never have this capability; if they do, that misconfiguration itself is a critical finding even if the load failed.
3. **Capture the module file.** If the load attempt referenced a `.ko` file on disk, exfiltrate it for static analysis before the attacker cleans up.
4. **Check kernel logs.** `dmesg` and the kernel ring buffer show whether the load succeeded. A failed load attempt is still a critical signal — the attacker is now aware they need a different escalation path.
5. **Treat as host-level incident.** Kernel modules run in host kernel context, so the scope of the incident is the host, not just the container.

## Remediation

**Active intrusion (loaded module):** isolate the host immediately (not just the container — the module lives in host kernel space). Reboot the host to clear the loaded module; reboots may not be sufficient if the attacker has established persistence in `/etc/modules-load.d/` or `/lib/modules/`, so audit those paths before bringing the host back. Treat all host-level secrets and data as potentially compromised (see "blast radius").

**Active intrusion (failed attempt):** isolate the container, drop `CAP_SYS_MODULE` from the container's capability set, and audit the workload for whatever allowed the attacker to even attempt this.

**Hardening:** drop `CAP_SYS_MODULE` from all containers that do not legitimately load modules (which is nearly all of them). Set the host kernel's `kernel.modules_disabled` sysctl to `1` after all needed modules are loaded at boot, which forbids further module loading until the next reboot.

## False Positives

- **Privileged init containers** that legitimately load drivers for hardware passthrough (GPU, FPGA, specialized NICs). Identifiable by process and module name; should be the only legitimate caller in normal operation.
- **CNI plugin initialization** that loads networking modules at host startup. Usually runs in a privileged DaemonSet pod and is identifiable by the loading process.
