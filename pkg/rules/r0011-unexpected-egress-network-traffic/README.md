# R0011 — Unexpected Egress Network Traffic

| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Exfiltration (TA0010) |
| MITRE Technique | Exfiltration Over C2 Channel (T1041) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes (uses Container Profile egress) |

## Description

Detects outbound network connections from a container to destinations that were not observed in the container's profile during the learning window. Internal and external destinations are treated alike: there is no private-IP exemption, so lateral movement to an unlisted peer inside the cluster alerts just like a connection to an unknown Internet host. Matching is port- and protocol-aware: a known destination on a port it was never contacted on during learning alerts, while an entry recorded without ports allows any port. Internal peers are allowlisted narrowly by `podSelector`/`namespaceSelector` or by a resolved `serviceRef`/`serviceSelector`, not by a service CIDR that would blind the rule to everything in that range. A workload's egress set is usually narrow and stable; new destinations indicate either a feature rollout or an outbound channel the attacker wants. The rule is disabled by default because the false-positive rate is workload-dependent. Its ingress twin is R0012.

## Attack Technique

Mapped to **MITRE T1041 — Exfiltration Over C2 Channel** under **TA0010 — Exfiltration**. Once an adversary has code execution they typically need an outbound channel — to beacon to their C2, to exfiltrate stolen data, to pull additional payloads, or to pivot to the next workload. Detecting on destinations and ports the workload has not been observed using surfaces these channels without signatures for specific C2 frameworks, and covers the in-cluster pivot that a public-IP-only rule misses.

## How It Works

The rule fires on outbound TCP/UDP connections where the destination is neither an allowlisted address nor an allowlisted selector for the destination port and protocol:

```
event.pktType == 'OUTGOING'
  AND !cp.was_address_port_protocol_in_egress(containerId, event.dstAddr, event.dstPort, event.proto)
  AND !cp.was_selector_in_egress(containerId, event.dstNamespace, event.dstPodLabels, event.dstPort, event.proto)
```

`was_address_port_protocol_in_egress` checks the profile's egress entries by address: an entry with a port list must contain the destination port and protocol; an entry without ports allows any port. `was_selector_in_egress` checks entries expressed as a `podSelector` (optionally with a `namespaceSelector`) against the destination pod's labels and namespace, the way a NetworkPolicy peer is written; a `podSelector` without a `namespaceSelector` only matches peers in the profile's own namespace. An entry with an empty `podSelector` matches nothing, so an allowlist entry must name what it permits. Entries recorded as a `serviceRef` are resolved to the backing pods' selector at profile load. Destinations without pod identity (external IPs, nodes, host-network processes) carry an empty namespace and empty labels and can only match by address.

## Investigation Steps

1. **Identify the destination.** For an in-cluster peer the event carries `dstNamespace`, `dstPodLabels` and the pod name. For an external address, reverse-DNS, ASN and threat-intel lookups on `event.dstAddr` and `event.dstPort` usually decide it in seconds: a cloud provider block hosting a real dependency is benign, an unknown VPS provider on a non-standard port is not.
2. **Identify the originating process.** `event.comm`, `event.pid` and the container name point at the caller. A network-facing service connecting out to a fresh destination is more concerning than a scheduled job hitting an update endpoint.
3. **Inspect the port and protocol.** A known destination on a new port is usually a feature change; an unknown destination on a non-standard port (4444, 8080, 31337) or a data port on an internal peer (database, cache, broker) is the lateral-movement or C2 shape.
4. **Pull surrounding events.** An unexpected egress often follows a DNS anomaly (R0005), a freshly executed binary, or a credential read; on an internal destination check for the matching R0012 alert on the peer.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the destination narrowly. If suspicious, block egress to it and isolate the workload.

## Remediation

**If the connection is malicious:** apply an egress NetworkPolicy that denies the destination (and ideally pivot the workload to default-deny egress). Isolate the container's network, preserve memory and disk, rotate any credentials the workload had access to, and begin incident response. Trace back to the event that created the new behavior — a dropped binary or a config change is the usual entry.

**If the connection is legitimate:** allowlist the specific destination. For an in-cluster peer prefer a `podSelector`/`namespaceSelector` or `serviceRef` entry over an address or CIDR, so the allowlist keeps detecting movement to everything else in that range. The profile will pick the destination up at the next learning pass.

Some workloads (web scrapers, build runners, orchestrators, service meshes' control planes) have an open-ended destination set by design and are unsuited for egress anomaly detection.

## False Positives

- **Long-tail dependencies used only occasionally.** A monthly billing API call, a vendor health check, a failover replica or a license ping not exercised during learning.
- **CDN and cloud-provider IP rotation.** Services that rotate the public IPs behind a hostname trigger until the baseline picks the new addresses up.
- **Multi-region cloud APIs** where the workload occasionally falls back to a region not visited during learning.
- **Internal peers whose pods churn** (scaled deployments, rolling updates) when they were recorded by address rather than by selector; re-record them as selector entries.
- **Wrong-port retries** from misconfigured clients: a known peer contacted on a port it never listens on is reported, which is correct but not malicious.
