# R1016 — Signed Profile Tampered

| Field | Value |
|-------|-------|
| Severity | Critical |
| MITRE Tactic | Defense Evasion (TA0005) |
| MITRE Technique | Impair Defenses (T1562) |
| Platforms | Host, Kubernetes |
| Requires Application Profile | No |
| Trigger | Code-emitted (no eBPF event / CEL expression) |

## Description

Detects tampering with a cryptographically signed, user-managed profile —
an `ApplicationProfile` or `NetworkNeighborhood` referenced by a pod via the
`kubescape.io/user-defined-profile` label and signed under the
`signature.kubescape.io/*` annotations.

node-agent re-verifies the signature every time the profile is loaded into the
`ContainerProfileCache`. When the signature annotation is **present but no
longer valid** — i.e. the profile content was modified after it was signed —
node-agent emits this alert. A missing/unsigned profile does not trigger it
(signing is opt-in), and operational errors (e.g. malformed annotations) are
explicitly excluded so they cannot raise a false R1016.

Unlike the eBPF-driven rules in this library, R1016 has **no triggering event
type and no CEL expression**: it is emitted directly from node-agent's tamper
-detection code path. The entry here exists so the rule's metadata (name,
severity, MITRE mapping, tags) lives in the single source of truth and flows
into the bundled `default-rules.yaml` like every other rule.

## Attack Technique

An attacker who can edit a signed profile resource (for example via a
compromised service account with write access to the CRD) could try to widen
the allow-list — adding their own binary to the exec allow-list or their C2
endpoint to the network allow-list — to evade the profile-based detections.
Because the overlay is signed, any such edit invalidates the signature, and
R1016 surfaces the tampering.

## Remediation

Investigate who modified the profile and when. Re-sign the profile after
verifying its contents, and review RBAC so that only trusted principals can
write user-managed `ApplicationProfile` / `NetworkNeighborhood` resources.
