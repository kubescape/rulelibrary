#!/usr/bin/env bats

setup() {
  TEST_DIR=$(mktemp -d)
  export RULES_DIR="$TEST_DIR/pkg/rules"
  mkdir -p "$RULES_DIR/r0001-good" "$RULES_DIR/r0002-bad"
  echo "# Rule" > "$RULES_DIR/r0001-good/README.md"
  # r0002-bad has no README
}

teardown() {
  rm -rf "$TEST_DIR"
}

@test "check_readmes.sh fails when a rule directory is missing README.md" {
  run bash "$BATS_TEST_DIRNAME/check_readmes.sh" "$RULES_DIR"
  [ "$status" -ne 0 ]
  [[ "$output" == *"r0002-bad"* ]]
}

@test "check_readmes.sh passes when all rule directories have README.md" {
  echo "# Rule 2" > "$RULES_DIR/r0002-bad/README.md"
  run bash "$BATS_TEST_DIRNAME/check_readmes.sh" "$RULES_DIR"
  [ "$status" -eq 0 ]
}

@test "check_readmes.sh fails when README.md exists but is empty" {
  echo "# Rule 2" > "$RULES_DIR/r0002-bad/README.md"
  : > "$RULES_DIR/r0001-good/README.md"
  run bash "$BATS_TEST_DIRNAME/check_readmes.sh" "$RULES_DIR"
  [ "$status" -ne 0 ]
  [[ "$output" == *"r0001-good"* ]]
}
