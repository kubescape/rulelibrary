# R1007 — Crypto Miner Launched (XMR / RandomX)

| Field | Value |
|-------|-------|
| Severity | Critical |
| MITRE Tactic | Impact (TA0040) |
| MITRE Technique | Resource Hijacking (T1496) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | No |

## Description

Detects execution of a process whose CPU instruction profile matches the RandomX algorithm — the proof-of-work function used by Monero (XMR) and several other privacy-coin miners. The node agent observes the process's instruction stream and recognizes the distinctive memory and arithmetic pattern of RandomX hashing. The detection is algorithmic rather than signature-based: it does not rely on the miner binary's name or hash, so renaming `xmrig` to `nginx-worker` will not evade it.

## Attack Technique

Mapped to **MITRE T1496 — Resource Hijacking** under **TA0040 — Impact**. Cryptomining is one of the most common post-exploitation monetization paths in cloud environments: once an attacker has code execution they deploy a miner that uses the workload's CPU (or, more lucratively, the cluster's entire CPU pool if they can spread) to mine cryptocurrency. Monero with its RandomX proof-of-work is overwhelmingly the coin of choice because RandomX is CPU-friendly and resistant to GPU/ASIC acceleration, so a stolen CPU cycle is worth more than for most other coins.

## How It Works

```
event type == 'randomx'
```

The `randomx` event is emitted by the node agent when its on-CPU profiler detects the characteristic instruction and memory-access pattern of RandomX hashing in a running process. The rule fires unconditionally on any such event — legitimate hits are essentially zero because no real workload incidentally runs RandomX as a side effect.

## Investigation Steps

1. **Capture the running process.** `event.exepath` and `event.comm` point at the binary. Hash and exfiltrate it before the attacker cleans up.
2. **Identify how the miner arrived.** Walk back from the alert: a freshly-dropped binary in the upperlayer (R1001), a fileless execution (R1005), an exec from `/dev/shm` (R1000), or a binary delivered via mounted volume (R1004) are the usual entry points.
3. **Determine the scope.** Mining is typically not a single-pod event — attackers spread the miner to as many workloads as their access permits. Check sibling pods in the namespace, other workloads using the same compromised service account, and the broader cluster.
4. **Identify the C2 / pool endpoint.** The miner has to connect somewhere to receive work and submit shares. Outbound connections from the workload (R0011, R1009) usually show the destination pool.
5. **Treat as confirmed intrusion.** RandomX detection has near-zero false positive rate; the legitimate base rate is effectively zero.

## Remediation

**Active intrusion:** kill the miner process, isolate the container's egress (network policy denying the destination, or full quarantine), preserve the binary for forensics, and rotate any credentials the compromised workload had access to (see "blast radius"). Rebuild from a known-good image; do not patch in place. Search the rest of the cluster for the same binary or for other workloads connecting to the same pool — mining payloads spread.

**Hardening:** apply CPU limits to all containers; capping a workload at its real CPU need makes mining economically uninteresting, even if a payload lands. Apply default-deny egress NetworkPolicies — miners must connect outbound to a pool, so denying the connection breaks the operation. Audit the image supply chain; many mining incidents originate from a compromised base image or untrusted third-party image.

## False Positives

- **Cryptographic test suites** that exercise RandomX as part of an algorithm correctness check. Rare in production workloads.
- **Cryptocurrency-native applications** (block explorers, payment processors handling XMR) that legitimately compute RandomX as part of their function. These should be allowlisted explicitly by image identity.

The legitimate base rate is low enough that any hit warrants a real investigation, not a routine triage-and-dismiss.
