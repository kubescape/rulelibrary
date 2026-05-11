# R0005 — DNS Anomalies in container

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Command and Control (TA0011) |
| MITRE Technique | Application Layer Protocol: DNS (T1071.004) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes (uses Network Neighborhood) |

## Description

Detects DNS queries from a host or container to domains that were not observed in the container's Network Neighborhood during the learning window. Cluster-internal lookups (anything ending in `.svc.cluster.local.`) are excluded so the rule focuses on external destinations. A workload's external DNS pattern is usually narrow and predictable; any new domain is either a new dependency rollout or an outbound channel the attacker wants to use.

## Attack Technique

Mapped to **MITRE T1071.004 — Application Layer Protocol: DNS** under **TA0011 — Command and Control**. DNS is a near-universally-allowed egress channel, which makes it the first protocol attackers reach for: command-and-control beacons, DNS-tunneled exfiltration, payload-fetch from attacker-controlled domains, and lookups for cloud-metadata or third-party APIs all surface here. Catching them at the DNS layer is cheap and language-agnostic.

## How It Works

The node agent records every external (non-cluster-internal) domain queried during the learning window into the container's Network Neighborhood. After the baseline is finalized, every DNS event is matched:

```
!event.name.endsWith('.svc.cluster.local.')
  AND !nn.is_domain_in_egress(containerId, event.name)
```

The first clause filters Kubernetes service discovery noise; the second checks whether the destination domain was seen during learning.

## Investigation Steps

1. **Resolve the domain to its purpose.** The domain itself often gives away the intent: a typosquat of a CDN, an attacker-themed name, a dynamic-DNS provider, a Pastebin-like service, or a known C2 framework's default domain are all diagnostic.
2. **Identify the requesting process.** `event.comm` and the container name in `event.containerName` point at the process. A network-facing service suddenly resolving `paste.ee` or a cloud-metadata host is much more interesting than a known cron job hitting a software-update endpoint.
3. **Pull surrounding events.** A DNS anomaly is often followed by a network connection to the resolved address (R0011 may fire), a download (`curl`/`wget` exec), or a fileless execution. Cross-correlation often confirms or refutes the alert quickly.
4. **Check threat-intel feeds.** The domain may already be tagged as known-bad. A clean reputation does not exonerate (newly-registered domains are common attacker tradecraft) but a known-bad tag is a strong escalation signal.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the domain for the workload. If suspicious, isolate the container and begin incident response.

## Remediation

**If the lookup is malicious:** apply an egress policy that denies the domain (or denies all DNS to the resolver if the workload should have no external DNS at all), isolate the container's network egress, preserve memory and disk, rotate any credentials reachable from the workload (see "blast radius"), and begin incident response. Look for the upstream activity that brought the domain into the workload's behavior — a freshly-dropped binary or a config change is the usual ingress.

**If the lookup is legitimate:** allowlist the specific domain (and ideally only that domain) via a per-rule policy. The Network Neighborhood will pick the domain up at the next baseline pass.

Some workloads (CI runners, orchestrators, scrapers) make DNS queries to a long tail of unpredictable domains by design and are unsuited for DNS anomaly detection.

## False Positives

- **Long-tail external dependencies the workload uses only occasionally.** A monthly software-update check, a billing-API call once per cycle, or a vendor health check that was not exercised during learning.
- **CDN domain rotation.** Some services rotate hostnames (e.g. signed-URL hosts under `*.cloudfront.net` or `*.s3.amazonaws.com`) that the baseline did not see verbatim.
- **Workloads with broad external surface by design.** Web scrapers, build orchestrators, and CI runners visit domains that cannot be enumerated up front.
