# R0005 — DNS Anomalies in container

| Field | Value |
|-------|-------|
| Severity | Low |
| MITRE Tactic | Command and Control (TA0011) |
| MITRE Technique | Application Layer Protocol: DNS (T1071.004) |
| Platforms | Host, Kubernetes, ECS |
| Requires Container Profile | Yes — completed/full, DNS-aware and nontruncated |

## Description

Detects a successful answered DNS response for a name absent from the container's
learned DNS baseline. DNS-only, cluster-internal and reverse lookups are learned
directly, even without a connection. A new name after learning can indicate a
legitimate dependency change or unexpected outbound activity.

## Attack Technique

Mapped to **MITRE T1071.004 — Application Layer Protocol: DNS**, under
**TA0011 — Command and Control**. Attackers can resolve infrastructure for
command-and-control, payload retrieval or DNS-tunneled exfiltration. A new name
is an investigation signal; this rule alone does not establish malicious intent.

## How It Works

During the existing container learning window, successful DNS responses with
answers contribute canonical names to `spec.dnsLookups`. After learning:

```cel
event.qr == 'R' && event.numAnswers > 0 &&
has(event.rcode) && event.rcode == 'Success' &&
!cp.was_dns_resolved(event.containerId, event.name)
```

The helper checks DNS history, independently of connection destinations.
Queries, error responses and empty answers cannot establish anomalies. Missing,
legacy, partial, TooLarge and DNS-truncated profiles remain silent. IP rotation
does not affect name matching. Cluster and reverse names have no suffix exemption.

The baseline freezes after completion. Alerts never teach new names. The name
cap is 4096 per container and the supporting address cap is 16 per name; name
truncation makes the baseline unsuitable for DNS anomaly matching.

## Investigation Steps

1. Identify the domain's purpose and compare it with the workload's expected
   dependencies. Check reputation and registration context where available;
   a new or clean reputation alone does not establish whether it is benign.
2. Identify the requesting process using executable path, process name, PID,
   container and workload metadata. Examine its image/version and recent changes.
3. Inspect the completed profile's DNS entries and readiness. A recorded network
   destination is not evidence that this DNS name was learned.
4. Correlate the lookup with surrounding connections, downloaded files and
   process executions. For internal names, check the intended Service/workload;
   for reverse names, identify the address and expected discovery behavior.
5. Determine whether the name represents an authorized change or suspicious
   activity before accepting it or starting a new learning window.

## Remediation

**Malicious activity:** contain the affected workload, restrict the unwanted
communication, preserve relevant evidence, and investigate the process and
credentials involved according to the incident-response procedure.

**Legitimate activity:** apply a scoped Risk Acceptance or explicitly relearn
an updated workload in a trusted state. A repeated alert does not update the
baseline, and there is no scheduled baseline pass that automatically accepts it.
Stable host identities and mutable image tags require explicit relearning after
software changes that leave the profile identity unchanged.

## False Positives

- Infrequently used dependencies or maintenance endpoints not exercised during learning.
- Rotating CDN hostnames; changing IP addresses alone do not cause a DNS mismatch.
- Authorized new cluster services, reverse lookups or workload dependencies after completion.
- Scrapers, build orchestrators and CI runners with intentionally unpredictable name sets.

## Rollout

Deploy DNS-aware storage and agents first. After all agents are upgraded,
explicitly relearn old and mixed-version profiles, including those already
carrying a DNS version marker. Then enable this rule version with a compatible
released agent version. Older agents cannot compile `cp.was_dns_resolved`.
