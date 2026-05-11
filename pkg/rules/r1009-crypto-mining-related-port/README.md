# R1009 — Crypto Mining Related Port Communication

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Command and Control (TA0011) |
| MITRE Technique | Application Layer Protocol (T1071) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No (uses Network Neighborhood) |

## Description

Detects outbound TCP connections from a host or container to well-known cryptomining pool ports (`3333`, `45700`). Cryptomining is a common post-exploitation monetization path: once an adversary gains code execution in a container they often deploy a miner that connects to a Stratum pool. The default Stratum ports are a strong network-layer fingerprint.

This rule does not raise alerts on its own - it is a building block consumed by higher-level detections that correlate it with other signals (e.g. a previously-unseen process making the connection, high CPU, or other mining-adjacent activity).

## Attack Technique

Mapped to **MITRE T1071 — Application Layer Protocol** under **TA0011 — Command and Control**. Cryptominers in compromised containers typically connect outbound to a mining pool using the Stratum protocol over TCP. While the protocol itself is benign-looking application-layer traffic, the ports are well-known and rarely match anything legitimate. Detecting on these ports gives a cheap, low-false-positive way to surface mining-adjacent C2 traffic without inspecting payload contents.

## How It Works

Pure network-event signature with a network-baseline suppression:

```
event.proto == 'TCP'
  AND event.pktType == 'OUTGOING'
  AND event.dstPort in [3333, 45700]
  AND !nn.was_address_in_egress(event.containerId, event.dstAddr)
```

Four gates:

1. **TCP only.** UDP traffic on the same ports does not trigger — Stratum is TCP.
2. **Outgoing only.** Inbound connections to these ports (an unlikely accident) are ignored.
3. **Destination port matches the watchlist** — `3333` and `45700` are the canonical Stratum and known mining-pool ports the rule tracks. The list is in the rule's `state.ports` field for traceability.
4. **Destination IP is not already in the container's Network Neighborhood.** If the workload has been observed talking to this address during the learning window, the connection is treated as part of its baseline and suppressed, this is what filters out, for example, an internal service that happens to listen on `:3333`.

The baseline reference is **Network Neighborhood**, not Application Profile — they are separate per-container baselines tracking different surfaces.

## Investigation Steps

1. **Identify the process making the connection.** `event.comm` and `event.pid` point at the connecting binary. If it is unknown to the workload, a freshly-deployed binary you have no record of, that alone is essentially diagnostic for mining when paired with the destination port.
2. **Look up the destination.** `event.dstAddr` resolved to a known mining pool (or an IP block historically used by one) is a strong confirmation. Threat-intel feeds and public mining-pool IP lists are useful here.
3. **Check resource usage.** Cryptominers are CPU-bound by design. Spike in container CPU around the connection timestamp is corroborating evidence.
4. **Pull the broader picture.** Mining payloads usually arrive via a previous compromise (exploited app, leaked credentials, malicious image). Look for earlier alerts on the same container, file writes to `/tmp` or `/dev/shm`, shells spawned from web servers, unexpected outbound HTTP downloads, to identify the ingress vector.
5. **Decide the response.** Even though this rule is Low severity in isolation, in combination with a positive process-identification step it should escalate to incident-response posture.

## Remediation

**Confirmed mining activity:** kill the connecting process, isolate the container's egress (cluster network policy that denies the destination, or a full container quarantine), preserve a binary sample for analysis, and rotate any secrets the container had access to. The container should be redeployed from a known-good image, not patched in place.

**Hardening:**

- Apply egress NetworkPolicies that allow only the destinations the workload needs. A default-deny egress posture stops mining payloads from ever phoning home.
- Set CPU limits on containers — even legitimate workloads benefit, and mining payloads become economically uninteresting when capped.
- Audit the image supply chain — many mining incidents trace back to compromised base images or unverified third-party images.

## False Positives

- **Workloads that legitimately use port 3333 or 45700.** Some internal services pick these ports without knowing they overlap mining pools. The Network Neighborhood suppression handles this automatically once the baseline observes the destination — so for steady-state workloads the rate should be near zero. For new workloads, allow the baseline to mature before treating R1009 hits as actionable.
- **Penetration tests or red-team exercises** that intentionally simulate mining traffic. Expected; coordinate with the responsible team to scope alerts.
- **Service discovery or health checks scanning a wide port range** that happen to hit `3333` or `45700` outbound TCP. Rare in practice — most discovery is destination-pinned, not arbitrary outbound.

Because the rule does not directly raise alerts, low-confidence solitary hits are absorbed by the correlation layer. Tune at that layer rather than disabling R1009.
