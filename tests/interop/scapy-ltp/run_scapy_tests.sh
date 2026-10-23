#!/usr/bin/env bash
#
# Run LTP and LTP/UDP Scapy testbed against Hardy BPA.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

VENV_PYTHON="$WORKSPACE_DIR/.venv/bin/python3"
if [ ! -x "$VENV_PYTHON" ]; then
    echo "Error: Python venv not found at $VENV_PYTHON"
    echo "Please create it and install scapy + cbor2."
    exit 1
fi

SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --skip-build)
            SKIP_BUILD=true
            ;;
        *)
            ;;
    esac
done

if [ "$SKIP_BUILD" = false ]; then
    echo "==> Building hardy-bpa-server..."
    cargo build -p hardy-bpa-server
fi

BPA_BIN="$WORKSPACE_DIR/target/debug/hardy-bpa-server"
if [ ! -x "$BPA_BIN" ]; then
    BPA_BIN="$WORKSPACE_DIR/target/release/hardy-bpa-server"
fi

if [ ! -x "$BPA_BIN" ]; then
    echo "Error: hardy-bpa-server binary not found!"
    exit 1
fi

HARDY_ENGINE_ID=1
SCAPY_ENGINE_ID=2
HARDY_LTP_PORT=21115
SCAPY_LTP_PORT=21116

TMP_DIR="$(mktemp -d /tmp/hardy-scapy-test.XXXXXX)"
HARDY_CONFIG="$TMP_DIR/hardy_config.toml"
HARDY_PID=""

cleanup() {
    if [ -n "$HARDY_PID" ]; then
        echo "==> Stopping hardy-bpa-server (PID $HARDY_PID)..."
        kill "$HARDY_PID" 2>/dev/null || true
        wait "$HARDY_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cat > "$HARDY_CONFIG" << EOF
log-level = "debug"
status-reports = true
node-ids = "ipn:$HARDY_ENGINE_ID.0"

[built-in-services]
echo = [7]

[storage.metadata]
type = "memory"

[storage.bundle]
type = "memory"

[rfc9171-validity]
primary-block-integrity = false

[[clas]]
name = "ltp-scapy"
type = "ltp"
engine-id = $HARDY_ENGINE_ID
max-segment-payload-len = 1400
rtt = "100ms"
ack-margin = "100ms"

[clas.transport]
type = "udp"
bind-addr = "127.0.0.1:$HARDY_LTP_PORT"

[[clas.peers]]
engine-id = $SCAPY_ENGINE_ID
address = "127.0.0.1:$SCAPY_LTP_PORT"
node-id = "ipn:$SCAPY_ENGINE_ID.0"
EOF

echo "==> Starting hardy-bpa-server on 127.0.0.1:$HARDY_LTP_PORT..."
"$BPA_BIN" -c "$HARDY_CONFIG" > "$TMP_DIR/hardy.log" 2>&1 &
HARDY_PID=$!
sleep 1.5

if ! kill -0 "$HARDY_PID" 2>/dev/null; then
    echo "Error: hardy-bpa-server failed to start!"
    cat "$TMP_DIR/hardy.log"
    exit 1
fi

echo "==> Running Scapy LTP test suite..."
export SCAPY_LTP_PORT="$SCAPY_LTP_PORT"
export HARDY_LTP_PORT="$HARDY_LTP_PORT"
export SCAPY_ENGINE_ID="$SCAPY_ENGINE_ID"
export HARDY_ENGINE_ID="$HARDY_ENGINE_ID"

cd "$SCRIPT_DIR"
unset PYTHONPATH
if ! "$VENV_PYTHON" -m unittest -v test_scapy_ltp.py; then
    echo "==> Test failed! Displaying hardy-bpa-server log:"
    cat "$TMP_DIR/hardy.log"
    exit 1
fi

echo "==> All Scapy LTP tests passed successfully!"
