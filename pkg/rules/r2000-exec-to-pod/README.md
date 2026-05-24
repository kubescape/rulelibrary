# R2000 — Exec to pod

Detects exec operations on pods via the Kubernetes admission webhook.

## Trigger

This rule is evaluated by the operator's admission controller (not the
node-agent). It fires when the API server processes a `pods/exec` subresource
CONNECT — typically triggered by `kubectl exec <pod>` or any client that
opens an exec stream.

## CEL expression

```cel
event.Kind == "PodExecOptions"
```

The expression deliberately keys on `event.Kind` rather than
`event.Resource`/`event.Subresource` so the rule remains stable if the
Kubernetes API evolves. The pre-filter in the operator uses this same
constraint to skip CEL evaluation for unrelated admission events.

## Alert content

- **Message:** `Exec to pod: <name> in namespace <ns> by <username>`
- **UniqueID:** `<namespace>/<name>` — suitable for downstream deduplication.

## MITRE

- Tactic: TA0002 (Execution)
- Technique: T1609 (Container Administration Command)

## Notes

- Profile dependency is `NotRequired` (2): admission rules evaluate API
  objects, not runtime behavior, and do not consult application profiles.
- This rule replaces the operator's hardcoded `R2000 Exec to Pod` Go
  implementation.
