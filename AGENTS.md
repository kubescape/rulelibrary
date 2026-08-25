# Agent Instructions for rulelibrary

When you add, modify, or delete a rule under `pkg/rules/`:

1. Each rule directory MUST contain a non-empty `README.md` that follows
   the template used by sibling rules (see any existing rule's README.md
   for the structure: metadata table + Description, Attack Technique, How
   It Works, Investigation Steps, Remediation, False Positives).
2. If you add a new rule, generate its `README.md` in the same commit.
3. If you modify a rule's YAML (CEL expression, severity, MITRE fields,
   profileDependency), update the affected sections of its `README.md`
   in the same commit.
4. Do not commit a rule change without its corresponding README update —
   the release build will fail.

The release build's `gen.sh` invokes `scripts/check_readmes.sh`, which
exits non-zero if any rule under `pkg/rules/` is missing or has an empty
`README.md`. The README content is consumed downstream by the
`armo-rulelibrary` build (which embeds this repo as a submodule) and
shipped as the `documentation` field on each rule.

## Writing CEL efficiently

Every enabled rule is evaluated on every matching event, on every node — per-event
cost is a multiplier. When authoring or modifying a rule's `ruleExpression`, follow
[`docs/writing-optimized-cel.md`](docs/writing-optimized-cel.md): collapse `==` OR-chains
to `x in [...]` / `x in {...}`, fold `endsWith`/`startsWith`/`contains` chains into
`[...].exists(s, ...)`, iterate collections once instead of re-scanning per needle, and
order cheap/selective predicates before expensive `ap.*`/`nn.*` profile gates. These
rewrites preserve the detection outcome while letting the engine's set-membership and
constant-folding optimizers do their job.
