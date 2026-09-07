# R0012 — Unexpected Ingress Network Traffic

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Lateral Movement (TA0008) |
| MITRE Technique | Exploitation of Remote Services (T1210) |
| Platforms | Kubernetes |
| Requires Application Profile | Yes (uses Container Profile ingress) |

## Description

Detects inbound connections to a container from peers that were not observed in the container's profile during the learning window. It is the symmetric twin of R0011 (egress): where R0011 watches what a workload reaches out to, R0012 watches who reaches in. There is no private-IP exemption — an unlisted peer inside the cluster alerts exactly like an unlisted peer on the Internet — so lateral movement towards this workload is visible from the target's side even when the source has no profile, no agent coverage, or has already been compromised. Matching is port- and protocol-aware on the local listening port: a known peer connecting to a port it never used during learning alerts. The rule is disabled by default because meshes with incomplete ingress allowlists (shared ingress controllers, monitoring scrapers, health probes from rotating IPs) produce a sustained false-positive stream until the allowlist is complete.

## Attack Technique

Mapped to **MITRE T1210 — Exploitation of Remote Services** under **TA0008 — Lateral Movement**. After an initial foothold an adversary moves by connecting to other workloads' listening services: databases, caches, admin endpoints, debug ports. The compromised source may be unmonitored or already trusted, but the target's profile still knows the narrow set of peers and ports it legitimately serves. Alerting on the target side surfaces the connection regardless of how the source was obtained.

## How It Works

The rule fires on inbound (`HOST`) packets whose remote peer is neither an allowlisted address nor an allowlisted selector for the local port and protocol:

```
event.pktType == 'HOST'
  AND !cp.was_address_port_protocol_in_ingress(containerId, event.dstAddr, event.dstPort, event.proto)
  AND !cp.was_selector_in_ingress(containerId, event.dstNamespace, event.dstPodLabels, event.dstPort, event.proto)
```

`was_address_port_protocol_in_ingress` checks the profile's ingress entries by peer address: an entry with a port list must contain the local port and protocol; an entry without ports allows any port. `was_selector_in_ingress` checks entries expressed as a `podSelector` (optionally with a `namespaceSelector`) against the peer pod's labels and namespace, the same way a NetworkPolicy peer is written. An entry with an empty `podSelector` matches nothing, so an allowlist entry has to name what it permits. Entries recorded as a `serviceRef` are resolved to the backing pods' selector at profile load. Peers without pod identity (an external IP, a node, a host-network process) carry an empty namespace and empty labels and can only match by address.

## Investigation Steps

1. **Identify the peer.** `event.dstAddr` is the remote side. For an in-cluster peer the event carries `dstNamespace`, `dstPodLabels` and the pod name, which name the source workload directly. For an external address use reverse-DNS and threat-intel lookups.
2. **Identify what was reached.** `event.dstPort` and `event.proto` are the local port and protocol on the alerting container. A connection to a data port (database, cache, message broker) or a management port from an unexpected peer is the classic lateral-movement shape.
3. **Check the source workload's own alerts.** If the peer is an in-cluster pod, look for R0011 on that pod for the same connection, plus recent exec, dropped-binary, or credential-access alerts on it. A source that is itself anomalous confirms the picture; a source that is a known component simply missing from the allowlist refutes it.
4. **Check the port against the profile.** A known peer on a new port is a different situation from an unknown peer: the former is usually a feature change or a newly enabled endpoint, the latter is either a new client or an attacker.
5. **Decide: legitimate change or attack.** If legitimate, extend the allowlist with a narrow selector or service entry. If suspicious, apply an ingress NetworkPolicy that denies the peer and isolate the source.

## Remediation

**If the connection is malicious:** apply an ingress NetworkPolicy on the target that denies the source (or pivot the namespace to default-deny ingress with explicit allow rules), isolate the source workload, preserve its memory and disk, and rotate any credentials the target service could have handed out (database users, tokens, session keys). Trace the source's own timeline to find how it was compromised.

**If the connection is legitimate:** add the peer to the profile's ingress entries as a `podSelector`/`namespaceSelector` or `serviceRef` rather than a broad CIDR, so the allowlist keeps detecting lateral movement from everything else in that range. The profile will pick the peer up at the next learning pass.

Workloads that serve an open-ended set of internal clients by design (shared ingress controllers, API gateways, DNS, metrics endpoints scraped by many collectors) are poor candidates for ingress anomaly detection.

## False Positives

- **Incomplete ingress allowlists on meshes.** Peers that connect only occasionally (cron-driven clients, failover replicas, canary rollouts) that were not exercised during learning.
- **Probes and scrapers from rotating addresses.** Node-level health checks, monitoring collectors and service-mesh sidecars whose source address changes with node or pod churn. Allowlist them by selector, not by address.
- **Ingress controllers and load balancers** whose pod set scales and whose source pods therefore change; a selector entry on the controller's labels is the durable allowlist.
- **Retried or refused connections on wrong ports** from misconfigured clients show up as ingress on the unexpected port; these are real, just not malicious.
