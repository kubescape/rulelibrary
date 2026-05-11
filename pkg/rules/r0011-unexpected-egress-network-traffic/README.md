# R0011 — Unexpected Egress Network Traffic

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Exfiltration (TA0010) |
| MITRE Technique | Exfiltration Over C2 Channel (T1041) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes (uses Network Neighborhood) |

## Description

Detects outbound network connections from a host or container to public (non-private-IP) destinations that were not observed in the container's Network Neighborhood during the learning window. Private-range destinations (RFC1918, cluster-internal, link-local) are excluded because intra-cluster service-to-service traffic is too varied to baseline reliably at the IP level. A workload's external egress is usually narrow and stable; new public destinations indicate either a feature rollout or an outbound channel the attacker wants to use. The rule is disabled by default because false-positive rate is workload-dependent.

## Attack Technique

Mapped to **MITRE T1041 — Exfiltration Over C2 Channel** under **TA0010 — Exfiltration**. Once an adversary has code execution they typically need an outbound channel — to beacon to their C2, to exfiltrate stolen data, to pull additional payloads. Detecting on destinations the workload has not been observed talking to surfaces these channels without requiring signatures of specific C2 frameworks.

## How It Works

The rule fires on outbound TCP/UDP connections where the destination is not private and not in the Network Neighborhood:

```
event.pktType == 'OUTGOING'
  AND !net.is_private_ip(event.dstAddr)
  AND !nn.was_address_in_egress(containerId, event.dstAddr)
```

`net.is_private_ip` covers RFC1918, RFC4193, and loopback/link-local ranges, so cluster-internal and host-internal traffic is silently filtered. Only the public-Internet destinations the workload never demonstrated talking to surface.

## Investigation Steps

1. **Identify the destination.** Reverse-DNS, ASN, and threat-intel lookups on `event.dstAddr` and `event.dstPort` often determine the situation in seconds. A known cloud provider IP block hosting your real dependency is benign; an unknown VPS provider on a non-standard port is not.
2. **Identify the originating process.** `event.comm`, `event.pid`, and the container name point at the caller. A network-facing service connecting outbound to a fresh public IP is much more concerning than a known scheduled job hitting a software-update endpoint.
3. **Inspect the protocol and port.** Standard ports (443, 80) on common destinations are usually less interesting than non-standard ports (4444, 8080, 31337) or known C2 default ports.
4. **Pull surrounding events.** An unexpected egress connection often follows a DNS anomaly (R0005), a freshly-executed binary, or a credential read. Cross-correlation usually confirms or refutes within minutes.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the destination or update the egress policy. If suspicious, block egress to the destination and isolate.

## Remediation

**If the connection is malicious:** apply an egress NetworkPolicy that denies the destination IP (and ideally pivots the workload to a default-deny egress posture). Isolate the container's network, preserve memory and disk, rotate any credentials the workload had access to (see "blast radius"), and begin incident response. Trace back to the upstream event that created the new behavior — a freshly-dropped binary or a config change is the usual ingress.

**If the connection is legitimate:** allowlist the specific destination via a per-rule policy. The Network Neighborhood will pick the destination up at the next baseline pass.

Some workloads (web scrapers, build runners, orchestrators) have an open-ended set of public destinations by design and are unsuited for egress-IP anomaly detection.

## False Positives

- **Long-tail external dependencies the workload uses only occasionally.** A monthly billing API call, a vendor health check, or a license-verification ping that was not exercised during learning.
- **CDN and cloud-provider IP rotation.** Some services rotate the public IPs behind a hostname; a workload connecting to the new IPs of a known hostname will trigger until the baseline picks them up.
- **Multi-region cloud APIs** where the workload occasionally falls back to a region not visited during learning.
