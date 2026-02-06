#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_SCRIPT="$SCRIPT_DIR/test-infra.sh"
cleanup() {
    echo ""
    echo "Cleaning up test infrastructure..."
    "$INFRA_SCRIPT" stop
}
trap cleanup EXIT
"$INFRA_SCRIPT" start
source "${TMPDIR:-/tmp}/tranquil_pds_test_infra.env"
echo ""
echo "Running database migrations..."
sqlx database create 2>/dev/null || true
sqlx migrate run --source "$PROJECT_DIR/migrations"
echo ""
ulimit -n 65536

echo "Building test binaries..."
cargo test --no-run 2>&1 | tail -1

echo "Running tests..."
echo ""
cargo nextest run "$@"

echo ""
echo "All tests passed."
