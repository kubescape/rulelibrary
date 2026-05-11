# R1008 — Crypto Mining Domain Communication

| Field | Value |
|-------|-------|
| Severity | Critical |
| MITRE Tactic | Command and Control (TA0011) |
| MITRE Technique | Application Layer Protocol: DNS (T1071.004) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects DNS lookups for any domain in a curated list of well-known cryptomining pool hostnames. The list covers ~90 of the most common Monero, Ethereum-classic, Zcash, and multi-coin mining-pool domains and their regional shards (e.g. `xmr.nanopool.org.`, `eu1.ethermine.org.`, `pool.minexmr.com.`, `supportxmr.com.`). A DNS lookup for any of these from a workload that is not itself a mining-pool client is essentially diagnostic of an in-progress mining incident.

## Attack Technique

Mapped to **MITRE T1071.004 — Application Layer Protocol: DNS** under **TA0011 — Command and Control**. Cryptominers in compromised workloads need to reach a mining pool to receive work and submit shares. Most miners are configured with a hostname rather than an IP address (so the pool operator can rebalance load), and DNS is the universally-allowed egress channel. Catching the lookup at the DNS layer is cheap, signature-driven, and independent of whether the connection itself reaches the pool successfully.

## How It Works

Pure signature match against a fixed allowlist of mining-pool domains:

```
event.name in [<curated list of ~90 mining-pool hostnames>]
```

The list lives in the rule definition's `ruleExpression.expression` and is maintained centrally. Domains are matched with the trailing dot (`xmr.nanopool.org.`) which is the canonical form delivered by the DNS subsystem.

## Investigation Steps

1. **Confirm the lookup and the requesting process.** `event.name` is the domain queried; `event.comm` is the process. A workload that has no business looking up `pool.minexmr.com.` doing so is the entire story.
2. **Check whether the connection succeeded.** A DNS lookup is necessary but not sufficient — surrounding events (an outbound TCP connection to the resolved address, ideally on port 3333 or 45700, R1009) confirm the miner actually reached the pool.
3. **Find the miner binary.** If the lookup happened, a process called the resolver. Identify that process (R0001 may have fired on it) and capture the binary for forensics.
4. **Map the spread.** Mining payloads rarely target a single workload. Check sibling pods, other workloads using the same compromised SA, and the entire cluster for the same domain in DNS logs.
5. **Treat as confirmed intrusion.** The false-positive rate of this rule is essentially nil.

## Remediation

**Active intrusion:** apply an egress policy that denies the domain (or denies all DNS to the resolver if the workload should have no external DNS), kill the miner process, isolate the container, preserve the binary, and rotate any credentials the compromised workload had access to (see "blast radius"). Search the cluster for the same domain in DNS or for the same binary across workloads — mining payloads spread.

**Hardening:** apply default-deny egress NetworkPolicies; the miner cannot mine if it cannot reach a pool. Apply CPU limits to all containers; if the miner does run, it is economically uninteresting. Audit the image supply chain for the original ingress vector.

## False Positives

- **Threat-intel and security-research workloads** that legitimately query mining-pool domains for monitoring or research. These should be explicitly allowlisted by namespace or workload.
- **Vulnerability scanners and red-team tooling** running inside the cluster as part of authorized exercises. Coordinate with the responsible team to scope.

The base rate of legitimate hits is near zero. A hit should escalate to incident response, not be silenced.
