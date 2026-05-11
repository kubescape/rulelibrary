# R0006 — Unexpected Service Account Token Access

| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Credential Access (TA0006) |
| MITRE Technique | Steal Application Access Token (T1528) |
| Platforms | Host, Kubernetes, ECS |
| Requires Application Profile | Yes |

## Description

Detects reads of a Kubernetes service-account token by a process that was not observed reading the token during the learning window. The rule watches the standard token paths under `/run/secrets/kubernetes.io/serviceaccount/token`, `/var/run/secrets/kubernetes.io/serviceaccount/token`, and the EKS equivalents under `/run/secrets/eks.amazonaws.com/serviceaccount/token`. The token grants whatever RBAC the pod's service account has, so anyone who reads it can act as that pod against the Kubernetes API.

## Attack Technique

Mapped to **MITRE T1528 — Steal Application Access Token** under **TA0006 — Credential Access**. Service-account tokens are the most valuable in-cluster credential a compromised pod can yield: they are pre-mounted, pre-authenticated, and tied to whatever roles the cluster operator granted the pod. Adversaries with code execution in a container will reach for the token early to enumerate the cluster, escalate via overly-permissive roles, or exfiltrate the token for use from outside the cluster.

## How It Works

The rule fires on any `open` event whose path matches one of the standard token locations and which is not part of the workload's recorded token-access history:

```
event.path under /run/secrets/.../serviceaccount/token (or /var/run/.../, or EKS equivalents)
  AND !ap.was_path_opened_with_suffix(containerId, '/token')
```

The `was_path_opened_with_suffix` check generalizes across the various mount paths so legitimate access from any of them is correctly suppressed.

## Investigation Steps

1. **Identify the reading process.** `event.comm`, `event.pid`, and the open flags reveal whether the token was read for normal use (a k8s client library called during request handling) or by a shell, debugger, or unknown binary.
2. **Check the parent process.** A token read from a freshly-launched `bash` or `curl` spawned by a network-facing service is essentially diagnostic of credential theft.
3. **Look for outbound use.** If the token has already been used, you may see network requests to the Kubernetes API server (audit logs are authoritative here) or outbound requests to a non-cluster destination containing the token.
4. **Determine the blast radius.** The compromised service account's RBAC bindings define what the attacker can now do — list secrets across namespaces, create privileged pods, exec into other pods. Cluster role bindings are the worst case.
5. **Decide: legitimate change or attack.** If legitimate, allowlist the reading process. If suspicious, rotate the token and isolate the pod.

## Remediation

**If the token read is malicious:** rotate the service account's token (deleting the secret will force recreation, but better: delete and recreate the service account). Audit Kubernetes API server logs for any actions taken with the token between the read and the rotation. Isolate the pod (network policy or seccomp profile), preserve memory and disk, and treat any resources the compromised SA had access to as potentially compromised (see "blast radius"). Tighten the SA's RBAC to least-privilege as a hardening follow-up.

**If the token read is legitimate:** allowlist the specific process via a per-rule policy. Better long-term, audit whether the workload actually needs Kubernetes API access — many do not, and disabling the token mount (`automountServiceAccountToken: false`) removes the attack surface entirely.

## False Positives

- **Workloads with multiple Kubernetes-client containers** where one client was not exercised during learning.
- **Sidecar agents that read the token on-demand** rather than at startup, where the on-demand path didn't run during the learning window.
- **k8s client library version bumps** that change which exact mount path is opened first.
