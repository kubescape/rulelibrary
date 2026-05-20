# R2001 — Port forward to pod

Detects port-forward operations on pods via the Kubernetes admission webhook.

## Trigger

Evaluated by the operator's admission controller (not the node-agent). Fires
when the API server processes a `pods/portforward` subresource CONNECT —
typically triggered by `kubectl port-forward <pod>` or any client that opens
a port-forward stream.

## CEL expression

```cel
event.Kind == "PodPortForwardOptions"
```

The expression keys on `event.Kind` so the operator's Kind pre-filter can
short-circuit unrelated admission events.

## Alert content

- **Message:** `Port forward to pod: <name> in namespace <ns> by <username>`
- **UniqueID:** `<namespace>/<name>` — suitable for downstream deduplication.

## MITRE

- Tactic: TA0011 (Command and Control)
- Technique: T1090 (Proxy)

## Notes

- Profile dependency is `NotRequired` (2): admission rules evaluate API
  objects, not runtime behavior.
- This rule replaces the operator's hardcoded `R2001 Port Forward` Go
  implementation.
