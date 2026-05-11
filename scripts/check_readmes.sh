#!/usr/bin/env bash
# Verify every rule directory under the given path has a non-empty README.md.
# Used by the release build as a hard gate.

set -euo pipefail

RULES_DIR="${1:-pkg/rules}"

if [ ! -d "$RULES_DIR" ]; then
  echo "check_readmes: directory not found: $RULES_DIR" >&2
  exit 1
fi

failed=0
while IFS= read -r -d '' rule_dir; do
  readme="$rule_dir/README.md"
  if [ ! -f "$readme" ]; then
    echo "check_readmes: missing README.md in $(basename "$rule_dir")" >&2
    failed=1
    continue
  fi
  if [ ! -s "$readme" ]; then
    echo "check_readmes: empty README.md in $(basename "$rule_dir")" >&2
    failed=1
  fi
done < <(find "$RULES_DIR" -mindepth 1 -maxdepth 1 -type d -name 'r[0-9]*' -print0)

if [ "$failed" -ne 0 ]; then
  echo "check_readmes: one or more rules are missing or have empty README.md" >&2
  exit 1
fi

echo "check_readmes: OK"
