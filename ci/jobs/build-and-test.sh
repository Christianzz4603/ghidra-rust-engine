#!/usr/bin/env bash

set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

PROFILE="${1:?usage: build-and-test.sh <test|release>}"

# Run every step even when an earlier one fails, so a single CI run reports all
# problems instead of stopping at the first failing test binary. The script
# still exits non-zero if any step failed.
failed=0
step() {
    echo ">> $*"
    "$@" || { echo "!! step failed: $*"; failed=1; }
}

echo ">> cargo test (default features, $PROFILE)"
step cargo test --profile "$PROFILE" --all-targets --no-fail-fast

echo ">> cargo test (all processors, $PROFILE)"
step cargo test --profile "$PROFILE" --all-targets --features all-processors --no-fail-fast

echo ">> cargo check (no default features, $PROFILE)"
step cargo check --profile "$PROFILE" --all-targets --no-default-features

echo ">> cargo run (inspect example, $PROFILE)"
step cargo run --profile "$PROFILE" --example inspect -- tests/data/decomp/bin/x86_64-O2 > /dev/null

exit "$failed"
