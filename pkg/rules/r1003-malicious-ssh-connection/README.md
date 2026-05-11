# R1003 — Disallowed SSH Connection

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Lateral Movement (TA0008) |
| MITRE Technique | Remote Services: SSH (T1021.001) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Optional |

## Description

Detects SSH connections from a host or container whose source port is in the Linux ephemeral range (32768–60999) and whose destination port is not the standard SSH port (22) or the common alternate (2022). When the destination IP is also not in the container's Network Neighborhood, the connection fires this rule. The pattern matches an SSH client launched from inside the workload to reach an SSH server on an unusual port — a textbook lateral-movement pattern where attackers tunnel SSH through non-standard ports to evade port-based egress filters. The rule is disabled by default; enable it on workloads that should never originate SSH.

## Attack Technique

Mapped to **MITRE T1021.001 — Remote Services** under **TA0008 — Lateral Movement**. Once an adversary has code execution in a container, SSH is the natural pivot tool to reach other systems where they have credentials or keys. Using a non-standard destination port (4022, 2222, 31337, etc.) is common because operators often allow outbound 22 only to known bastion hosts, while a wider TCP egress posture might allow arbitrary high ports — making the non-standard port a usable channel.

## How It Works

```
event source port in [32768, 60999]
  AND event destination port NOT in [22, 2022]
  AND !nn.was_address_in_egress(containerId, event.dstIp)
```

The source-port range identifies a connecting (client) socket; servers do not allocate ephemeral source ports. The destination-port exclusion suppresses the legitimate-SSH-to-standard-port case (which a different rule could cover). The Network Neighborhood check suppresses any destination the workload was previously observed talking to, removing internal SSH-to-bastion patterns that were learned.

## Investigation Steps

1. **Confirm it is actually SSH.** The event type is `ssh`, derived from packet inspection of the connection. Cross-check the destination port and protocol if your tooling permits.
2. **Identify the originating process.** `event.comm` reveals the SSH client — most often `ssh`, `scp`, `sftp`, or a wrapper. An SSH client running in a workload that should not initiate SSH is essentially diagnostic.
3. **Look up the destination.** Reverse-DNS, ASN, and threat-intel on `event.dstIp:event.dstPort` typically clarify whether the destination is a known internal bastion, a known external resource, or an attacker-controlled host.
4. **Pull surrounding events.** An SSH out is often preceded by a credential read (R0006, R0008, R0010) and a freshly-executed binary (R1001). The credential the attacker stole and the binary they used to mount the pivot are both diagnostic.
5. **Decide the response.** Treat as active lateral movement until disproven; one outbound SSH from an unexpected workload is enough to escalate.

## Remediation

**If the connection is malicious:** apply an egress NetworkPolicy that denies the destination, isolate the source container, preserve memory and disk, audit the destination host for activity originating from the source workload, and rotate any credentials or SSH keys reachable from the source workload (see "blast radius").

**Hardening:** apply default-deny egress NetworkPolicies and explicitly permit only the destinations the workload needs. For workloads that legitimately use SSH for ops, restrict by destination port and destination address. Audit whether the container even needs SSH client tooling installed — most do not, and removing it reduces the attacker's options post-compromise.

**If the connection is legitimate:** allowlist the specific destination via a per-rule policy.

## False Positives

- **Operator-initiated debug SSH** from within a container during troubleshooting. Distinguishable by entry point (kubectl-exec) and by the operator's username on the destination.
- **Workloads with internal SSH-based deploys** that point at a fleet of hosts on non-standard ports. Typically captured by the Network Neighborhood baseline once it matures.
- **CI runners and orchestrators** that SSH to many destinations as part of their normal job execution.
