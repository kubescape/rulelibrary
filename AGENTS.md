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

See: `shared-designs-and-docs/rule-improvement-epic/rule-documentation-field-design.md`
