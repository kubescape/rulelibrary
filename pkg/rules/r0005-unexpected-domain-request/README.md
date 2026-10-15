# DNS anomalies (R0005)

Reports a successful answered DNS response whose name was not learned during the
container profile learning window. Matching uses `cp.was_dns_resolved`; connection
destinations do not teach DNS. Cluster-internal and reverse names follow the same
learning behavior as external names. Queries, error responses and empty answers
cannot establish anomalies.

Requires a completed full DNS-aware profile. Missing, legacy, partial, TooLarge
and truncated profiles stay silent. The baseline freezes after completion; alerts
do not teach new names. Deploy DNS-aware storage and agents, then explicitly
relearn existing and mixed-version profiles after all agents are upgraded before
enabling this rule version. Changes to stable workload identities require explicit
relearning. This change preserves connection-based rule behavior.
