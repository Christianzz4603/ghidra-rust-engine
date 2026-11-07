#!/usr/bin/env bash

set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

PROFILE="${1:?usage: build-and-test.sh <test|release>}"
failed=0

# Run every step even when an earlier one fails so a single CI run reports all failures.
step() {
    local label="$1"
    shift
    echo ">> ${label}"
    if ! "$@"; then
        echo "!! step failed: $*"
        failed=1
    fi
}

step "cargo test (default features, $PROFILE)" cargo test --profile "$PROFILE" --all-targets --no-fail-fast
step "cargo test (all processors, $PROFILE)" cargo test --profile "$PROFILE" --all-targets --features all-processors --no-fail-fast
step "cargo check (no default features, $PROFILE)" cargo check --profile "$PROFILE" --all-targets --no-default-features
step "cargo run (inspect example, $PROFILE)" cargo run --profile "$PROFILE" --example inspect -- tests/data/decomp/bin/x86_64-O2 > /dev/null

exit "$failed"
