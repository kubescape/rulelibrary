# R0007 — Workload uses Kubernetes API unexpectedly

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Lateral Movement (TA0008) |
| MITRE Technique | Exploitation of Remote Services (T1210) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects two related signals that indicate a host or container is communicating with the Kubernetes API server in a way the workload was not observed doing during learning: (1) execution of `kubectl` (or any binary named `kubectl` / ending in `/kubectl`) that was not part of the application profile, and (2) outbound network connections to the cluster's API server address that were not part of the Network Neighborhood baseline. Either signal alone is interesting; together they often indicate cluster reconnaissance from a compromised pod.

## Attack Technique

Mapped to **MITRE T1210 — Exploitation of Remote Services** under **TA0008 — Lateral Movement**. The Kubernetes API server is one of the highest-value lateral-movement targets in a cluster: it controls every workload, every secret, and every cluster role binding. An adversary with code execution in a pod that has API access often pivots through the API to escalate, enumerate, or persist. Detecting both the typical tool (`kubectl`) and the typical destination (the API server address) catches both the tooled and the scripted variants.

## How It Works

Two event types, evaluated independently:

```
exec:
  (event.comm == 'kubectl' || event.exepath.endsWith('/kubectl'))
    AND !ap.was_executed(containerId, ...)

network:
  event.pktType == 'OUTGOING'
    AND k8s.is_api_server_address(event.dstAddr)
    AND !nn.was_address_in_egress(containerId, event.dstAddr)
```

The exec arm catches the binary by name; the network arm catches any outbound to the cluster's API endpoint(s), so a Go or Python client using the in-cluster config also triggers when the workload was not previously observed talking to the API server.

## Investigation Steps

1. **Identify which signal fired.** The exec signal points at a binary; the network signal points at an HTTP/TLS connection. They usually fire together for tooling-based reconnaissance but only the network arm fires for in-process clients.
2. **Look at the originating process and parent.** A `kubectl exec` from a freshly-spawned shell inside a web-facing pod is essentially diagnostic of an intruder.
3. **Pull API server audit logs.** If the connection succeeded, the Kubernetes API server's audit log shows exactly what was requested, by which service account, and against which resources. This determines blast radius.
4. **Check the pod's service account permissions.** A pod whose SA has `cluster-admin` is a very different incident from a pod whose SA has only `get` on its own pod.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the binary and/or destination. If suspicious, rotate the SA token, isolate the pod, and audit API server logs from the alert time forward.

## Remediation

**If the activity is malicious:** rotate the service account token immediately, audit the API server logs for actions taken with the compromised SA, and isolate the pod (network policy or seccomp profile). Treat any cluster resources the SA could reach as potentially compromised (see "blast radius"). As hardening, set `automountServiceAccountToken: false` on workloads that do not need API access, and apply NetworkPolicies that deny egress to the API server from pods that should not reach it.

**If the activity is legitimate:** allowlist the specific binary or destination via a per-rule policy.

## False Positives

- **Kubernetes-aware sidecars** added after the baseline was captured. Service-mesh proxies, secret-rotation agents, and metrics scrapers that talk to the API server may not have been present during learning.
- **Application updates that introduce a Kubernetes client.** A code path that begins using the Kubernetes API after a deploy will trigger until either the baseline is replaced or the workload is allowlisted.
- **Operator/admin debug sessions.** A human shell that runs `kubectl` inside a pod for troubleshooting; expected from kubectl-exec entry points and distinguishable by parent process.
