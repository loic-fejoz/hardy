#!/bin/bash
# Mutation testing runner for Hardy DTN Router using cargo-mutants
#
# Usage:
#   ./scripts/run_mutants.sh                    # Run on hardy-ltp (default)
#   ./scripts/run_mutants.sh --all              # Run on hardy-ltp and hardy-ltp-cla
#   ./scripts/run_mutants.sh --diff             # Run only on uncommitted/recent git changes
#   ./scripts/run_mutants.sh --file <path>      # Run on a specific file
#   ./scripts/run_mutants.sh --list             # List mutants without executing tests
#
# Requires cargo-mutants (cargo install cargo-mutants)

set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

if ! command -v cargo-mutants >/dev/null 2>&1; then
    echo "ERROR: 'cargo-mutants' is not installed." >&2
    echo "Install it with: cargo install cargo-mutants" >&2
    exit 1
fi

PACKAGES=("hardy-ltp")
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            PACKAGES=("hardy-ltp" "hardy-ltp-cla")
            shift
            ;;
        --diff)
            DIFF_FILE="$(mktemp)"
            git diff "${2:-HEAD~1}" > "$DIFF_FILE"
            EXTRA_ARGS+=("--in-diff" "$DIFF_FILE")
            shift
            ;;
        --file)
            EXTRA_ARGS+=("--file" "$2")
            shift 2
            ;;
        --list)
            EXTRA_ARGS+=("--list")
            shift
            ;;
        -p|--package)
            PACKAGES=("$2")
            shift 2
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

for pkg in "${PACKAGES[@]}"; do
    echo "=== Running mutation testing on package: ${pkg} ==="
    cargo mutants -p "${pkg}" "${EXTRA_ARGS[@]}"
done
