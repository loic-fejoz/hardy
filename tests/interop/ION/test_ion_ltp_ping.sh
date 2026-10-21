#!/bin/bash
# Interoperability test: Hardy <-> NASA JPL ION-DTN ping/echo via LTP/UDP
#
# This script tests bidirectional ping/echo between Hardy and ION over LTP/UDP:
#   1. ION as server with bpecho, Hardy pings it via LTP/UDP
#   2. Hardy as server with echo service, ION bping pings it via LTP/UDP
#   3. Packet capture analysis with Wireshark/tshark (packet-ltp.c)
#
# Prerequisites:
#   - Docker installed (for ION container)
#   - Hardy tools and bpa-server built
#   - ION Docker image built (ion-interop)
#   - tshark installed (Wireshark CLI)
#
# Usage:
#   ./tests/interop/ION/test_ion_ltp_ping.sh [--skip-build] [--count N]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Configuration
HARDY_NODE_NUM=1
ION_NODE_NUM=2
HARDY_LTP_ENGINE=1
ION_LTP_ENGINE=2
HARDY_LTP_PORT=1113
ION_LTP_PORT=1114
ION_IMAGE="ion-interop"
PING_COUNT=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $*"; }

# Parse options
SKIP_BUILD=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --count|-c)
            PING_COUNT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Cleanup function
ION_CONTAINER=""
HARDY_PID=""
CAPTURE_CONTAINER=""
CLEANUP_IN_PROGRESS=""

kill_process() {
    local pid=$1
    local name=$2
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping $name (PID $pid)..."
        kill "$pid" 2>/dev/null || true
        local count=0
        while kill -0 "$pid" 2>/dev/null && [ $count -lt 50 ]; do
            sleep 0.1
            count=$((count + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Force killing $name (PID $pid)..."
            kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    if [ -n "$CLEANUP_IN_PROGRESS" ]; then
        return
    fi
    CLEANUP_IN_PROGRESS=1

    log_info "Cleaning up..."

    if [ -n "$CAPTURE_CONTAINER" ]; then
        docker stop -t 1 "$CAPTURE_CONTAINER" 2>/dev/null || true
        docker rm -f "$CAPTURE_CONTAINER" 2>/dev/null || true
    fi
    docker rm -f hardy-ltp-pcap-capture 2>/dev/null || true

    if [ -n "$ION_CONTAINER" ]; then
        docker stop -t 2 "$ION_CONTAINER" 2>/dev/null || true
        docker rm -f "$ION_CONTAINER" 2>/dev/null || true
    fi
    docker rm -f ion-interop-ltp-test 2>/dev/null || true

    kill_process "$HARDY_PID" "hardy-bpa-server"

    # Clean up stale ION shared memory and POSIX semaphores
    docker run --rm --ipc=host --entrypoint killm "$ION_IMAGE" 2>/dev/null || true

    log_info "Cleanup complete"
}
trap cleanup EXIT INT TERM

# Create temporary directory
TEST_DIR=$(mktemp -d)
chmod 777 "$TEST_DIR"
log_info "Using test directory: $TEST_DIR"
PCAP_FILE="$TEST_DIR/hardy_ion_ltp.pcap"

# Build Hardy tools and server if needed
if [ "$SKIP_BUILD" = false ]; then
    log_step "Building Hardy tools and bpa-server..."
    cd "$WORKSPACE_DIR"
    cargo build --release -p hardy-tools -p hardy-bpa-server
fi

BP_BIN="$WORKSPACE_DIR/target/release/bp"
BPA_BIN="$WORKSPACE_DIR/target/release/hardy-bpa-server"

if [ ! -x "$BP_BIN" ]; then
    log_error "bp binary not found at $BP_BIN"
    exit 1
fi

if [ ! -x "$BPA_BIN" ]; then
    log_error "hardy-bpa-server binary not found at $BPA_BIN"
    exit 1
fi

# Check for ion-interop Docker image
if ! docker image inspect "$ION_IMAGE" &>/dev/null; then
    log_info "Building ion-interop Docker image..."
    docker build --load -t "$ION_IMAGE" "$SCRIPT_DIR/docker"
else
    log_info "Using existing ion-interop image"
fi

# Check for tshark
if ! command -v tshark &>/dev/null; then
    log_error "tshark is required for packet capture dissection"
    exit 1
fi

# Clean any existing IPC state before starting tests
docker run --rm --ipc=host --entrypoint killm "$ION_IMAGE" 2>/dev/null || true

# Start packet capture via container tcpdump on loopback
log_step "Starting packet capture on loopback (UDP ports $HARDY_LTP_PORT and $ION_LTP_PORT)..."
CAPTURE_CONTAINER="hardy-ltp-pcap-capture"
docker rm -f "$CAPTURE_CONTAINER" 2>/dev/null || true
docker run -d --name "$CAPTURE_CONTAINER" --network host --user root \
    -v "$TEST_DIR:/capture" "$ION_IMAGE" \
    tcpdump -U -i lo -w /capture/hardy_ion_ltp.pcap "udp port $HARDY_LTP_PORT or udp port $ION_LTP_PORT"
sleep 2

# =============================================================================
# TEST 1: Hardy -> ION (Hardy bp ping via LTP/UDP, ION bpecho)
# =============================================================================
echo ""
echo "============================================================"
log_info "TEST 1: Hardy pings ION echo service via LTP/UDP"
echo "============================================================"

log_step "Starting ION daemon with LTP CL..."
docker rm -f ion-interop-ltp-test 2>/dev/null || true

ION_CONTAINER=$(docker run -d \
    --name ion-interop-ltp-test \
    --network host \
    --ipc=host \
    -e CLA_TYPE=ltp \
    -e ION_NODE_NUM="$ION_NODE_NUM" \
    -e LTP_ENGINE_NUM="$ION_LTP_ENGINE" \
    -e LTP_PORT="$ION_LTP_PORT" \
    -e REMOTE_HOST="127.0.0.1" \
    -e REMOTE_PORT="$HARDY_LTP_PORT" \
    -e REMOTE_NODE="$HARDY_NODE_NUM" \
    -e REMOTE_LTP_ENGINE="$HARDY_LTP_ENGINE" \
    "$ION_IMAGE")

log_info "Started ION container: ${ION_CONTAINER:0:12}"

# Wait for ION to start successfully
TEST1_RESULT="FAIL"
for _ in 1; do
    log_info "Waiting for ION to complete startup..."
    READY=false
    for i in {1..30}; do
        if docker logs "$ION_CONTAINER" 2>&1 | grep -q "ION started successfully"; then
            READY=true
            break
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$ION_CONTAINER" 2>/dev/null)" != "true" ]; then
            log_error "ION container stopped unexpectedly"
            docker logs "$ION_CONTAINER" 2>&1 | tail -30
            break
        fi
        sleep 0.5
    done

    if [ "$READY" != true ]; then
        log_error "ION did not start successfully; skipping TEST 1"
        docker logs "$ION_CONTAINER" 2>&1 | tail -30
        break
    fi
    log_info "ION is ready with LTP engine $ION_LTP_ENGINE on port $ION_LTP_PORT"

    # Give ION a moment to initialize internal tasks
    sleep 2

    # Start bpecho service in ION
    log_step "Starting bpecho service on ipn:$ION_NODE_NUM.7..."
    docker exec -d "$ION_CONTAINER" bpecho "ipn:$ION_NODE_NUM.7"
    sleep 2

    # Hardy pings ION echo service via built-in LTP CLA
    log_step "Hardy pinging ION echo service at ipn:$ION_NODE_NUM.7 via LTP/UDP..."
    echo ""

    PING_TIMEOUT=$((PING_COUNT * 3 + 15))
    PING_OUTPUT=$(timeout "${PING_TIMEOUT}s" "$BP_BIN" ping "ipn:$ION_NODE_NUM.7" "127.0.0.1:$ION_LTP_PORT" \
        --cla ltp \
        --cla-bind "0.0.0.0:$HARDY_LTP_PORT" \
        --source "ipn:$HARDY_NODE_NUM.12345" \
        --count "$PING_COUNT" \
        --interval 1s \
        --wait 5s \
        --timeout "${PING_TIMEOUT}s" \
        2>&1) && EXIT_CODE=0 || EXIT_CODE=$?

    echo "$PING_OUTPUT"
    echo ""

    STATS_LINE=$(echo "$PING_OUTPUT" | grep -E '[0-9]+ (bundles )?transmitted' | head -1)
    TRANSMITTED=$(echo "$STATS_LINE" | sed -E 's/^([0-9]+).*/\1/')
    RECEIVED=$(echo "$STATS_LINE" | sed -E 's/.*, ([0-9]+) received.*/\1/')

    if [ $EXIT_CODE -eq 0 ] && [ "$RECEIVED" = "$TRANSMITTED" ] && [ -n "$RECEIVED" ] && [ "$RECEIVED" -gt 0 ]; then
        log_info "TEST 1 PASSED: Hardy successfully pinged ION ($RECEIVED/$TRANSMITTED)"
        TEST1_RESULT="PASS"
    elif [ $EXIT_CODE -eq 0 ] && [ -n "$RECEIVED" ] && [ "$RECEIVED" -gt 0 ]; then
        log_error "TEST 1 FAILED: Partial loss - only $RECEIVED/$TRANSMITTED responses received"
    elif [ $EXIT_CODE -eq 1 ]; then
        log_error "TEST 1 FAILED: No echo responses received (100% loss)"
    else
        log_error "TEST 1 FAILED: Error during ping (exit code $EXIT_CODE)"
    fi
done

# Stop ION for test 2
log_info "Stopping ION after Test 1..."
docker stop "$ION_CONTAINER" 2>/dev/null || true
docker rm -f "$ION_CONTAINER" 2>/dev/null || true
ION_CONTAINER=""
docker run --rm --ipc=host --entrypoint killm "$ION_IMAGE" 2>/dev/null || true
sleep 1

# =============================================================================
# TEST 2: ION -> Hardy (Hardy bpa-server with echo, ION bping via LTP/UDP)
# =============================================================================
echo ""
echo "============================================================"
log_info "TEST 2: ION bping pings Hardy echo service via LTP/UDP"
echo "============================================================"

# Create Hardy bpa-server configuration
cat > "$TEST_DIR/hardy_config.toml" << EOF
log-level = "info"
status-reports = true
node-ids = "ipn:$HARDY_NODE_NUM.0"

[built-in-services]
echo = [7]

[storage.metadata]
type = "memory"

[storage.bundle]
type = "memory"

[rfc9171-validity]
primary-block-integrity = false

[[clas]]
name = "ltp-1"
type = "ltp"
engine-id = $HARDY_LTP_ENGINE
max-segment-payload-len = 1400
rtt = "200ms"
ack-margin = "200ms"

[clas.transport]
type = "udp"
bind-addr = "0.0.0.0:$HARDY_LTP_PORT"

[[clas.peers]]
engine-id = $ION_LTP_ENGINE
address = "127.0.0.1:$ION_LTP_PORT"
node-id = "ipn:$ION_NODE_NUM.0"
EOF

log_step "Starting Hardy BPA server with LTP CLA..."
"$BPA_BIN" -c "$TEST_DIR/hardy_config.toml" &
HARDY_PID=$!
sleep 2

if ! kill -0 "$HARDY_PID" 2>/dev/null; then
    log_error "Hardy BPA server failed to start"
    exit 1
fi
log_info "Hardy BPA server started with PID $HARDY_PID"

# Start ION to ping Hardy
log_step "Starting ION daemon with LTP CL..."
docker rm -f ion-interop-ltp-test 2>/dev/null || true

ION_CONTAINER=$(docker run -d \
    --name ion-interop-ltp-test \
    --network host \
    --ipc=host \
    -e CLA_TYPE=ltp \
    -e ION_NODE_NUM="$ION_NODE_NUM" \
    -e LTP_ENGINE_NUM="$ION_LTP_ENGINE" \
    -e LTP_PORT="$ION_LTP_PORT" \
    -e REMOTE_HOST="127.0.0.1" \
    -e REMOTE_PORT="$HARDY_LTP_PORT" \
    -e REMOTE_NODE="$HARDY_NODE_NUM" \
    -e REMOTE_LTP_ENGINE="$HARDY_LTP_ENGINE" \
    "$ION_IMAGE")

log_info "Started ION container: ${ION_CONTAINER:0:12}"

TEST2_RESULT="FAIL"
for _ in 1; do
    log_info "Waiting for ION to complete startup..."
    READY=false
    for i in {1..30}; do
        if docker logs "$ION_CONTAINER" 2>&1 | grep -q "ION started successfully"; then
            READY=true
            break
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$ION_CONTAINER" 2>/dev/null)" != "true" ]; then
            log_error "ION container stopped unexpectedly"
            docker logs "$ION_CONTAINER" 2>&1 | tail -30
            break
        fi
        sleep 0.5
    done

    if [ "$READY" != true ]; then
        log_error "ION did not start successfully; skipping TEST 2"
        docker logs "$ION_CONTAINER" 2>&1 | tail -30
        break
    fi
    log_info "ION is ready with LTP engine $ION_LTP_ENGINE on port $ION_LTP_PORT"

    # Give ION time to settle
    sleep 2

    # Run bping from ION container targeting Hardy echo service at ipn:1.7
    log_step "ION bping to Hardy echo service at ipn:$HARDY_NODE_NUM.7..."
    PING_TIMEOUT=$((PING_COUNT * 3 + 15))
    PING_OUTPUT=$(timeout "${PING_TIMEOUT}s" docker exec "$ION_CONTAINER" \
        bping -c "$PING_COUNT" -q 5 \
        "ipn:$ION_NODE_NUM.1" "ipn:$HARDY_NODE_NUM.7" \
        2>&1) || true

    echo "$PING_OUTPUT"
    echo ""

    STATS_LINE=$(echo "$PING_OUTPUT" | grep "bundle loss" | head -1)
    RECEIVED=$(echo "$STATS_LINE" | sed -E 's/.*, ([0-9]+) bundles received.*/\1/')

    if [ -n "$RECEIVED" ] && [ "$RECEIVED" -ge 1 ] 2>/dev/null; then
        if echo "$STATS_LINE" | grep -q "0.00% bundle loss"; then
            log_info "TEST 2 PASSED: ION received $RECEIVED responses from Hardy ($STATS_LINE)"
            TEST2_RESULT="PASS"
        else
            log_error "TEST 2 FAILED: Partial loss ($STATS_LINE)"
            TEST2_RESULT="FAIL"
        fi
    else
        log_error "TEST 2 FAILED: No echo responses received"
        TEST2_RESULT="FAIL"
    fi
done

# Stop Hardy BPA and ION
kill_process "$HARDY_PID" "hardy-bpa-server"
HARDY_PID=""

docker stop "$ION_CONTAINER" 2>/dev/null || true
docker rm -f "$ION_CONTAINER" 2>/dev/null || true
ION_CONTAINER=""
docker run --rm --ipc=host --entrypoint killm "$ION_IMAGE" 2>/dev/null || true

# =============================================================================
# PACKET CAPTURE VALIDATION (tshark / packet-ltp.c)
# =============================================================================
echo ""
echo "============================================================"
log_info "WIRESHARK / TSHARK PACKET CAPTURE VALIDATION"
echo "============================================================"

if [ -n "$CAPTURE_CONTAINER" ]; then
    log_info "Stopping packet capture..."
    docker stop -t 2 "$CAPTURE_CONTAINER" 2>/dev/null || true
    docker rm -f "$CAPTURE_CONTAINER" 2>/dev/null || true
    CAPTURE_CONTAINER=""
fi
sleep 1

PCAP_RESULT="FAIL"
if [ -f "$PCAP_FILE" ]; then
    log_info "Captured packets in $PCAP_FILE:"
    tshark -r "$PCAP_FILE" -c 10 2>/dev/null || true
    echo ""

    log_step "Dissecting LTP segments via tshark (packet-ltp.c)..."
    LTP_DISSECTION=$(tshark -r "$PCAP_FILE" -Y "ltp" 2>/dev/null || true)
    echo "$LTP_DISSECTION"
    echo ""

    LTP_COUNT=$(echo "$LTP_DISSECTION" | grep -c . || true)
    log_info "Total dissected LTP packets: $LTP_COUNT"

    if [ "$LTP_COUNT" -gt 0 ]; then
        log_info "Wireshark/tshark packet-ltp dissection confirmed valid LTP frames on the wire!"
        PCAP_RESULT="PASS"
    else
        log_error "No LTP packets detected in capture!"
    fi
else
    log_error "PCAP file not found at $PCAP_FILE"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "============================================================"
echo "TEST SUMMARY:"
echo "  TEST 1 (Hardy -> ION LTP Ping):      $TEST1_RESULT"
echo "  TEST 2 (ION -> Hardy LTP Ping):      $TEST2_RESULT"
echo "  PCAP (Wireshark LTP Dissection):     $PCAP_RESULT"
echo "============================================================"

if [ "$TEST1_RESULT" = "PASS" ] && [ "$TEST2_RESULT" = "PASS" ] && [ "$PCAP_RESULT" = "PASS" ]; then
    log_info "ALL LTP INTEROPERABILITY TESTS PASSED!"
    exit 0
else
    log_error "SOME LTP INTEROPERABILITY TESTS FAILED!"
    exit 1
fi
