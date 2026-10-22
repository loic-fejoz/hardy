# Fuzz Test Plan: Licklider Transmission Protocol (LTP)

| Document Info | Details |
| ----- | ----- |
| **Functional Area** | Transport Protocol Robustness & Codec Integrity |
| **Module** | `hardy-ltp` and `hardy-ltp-cla` |
| **Target Directories** | `ltp/fuzz/fuzz_targets/`, `ltp-cla/fuzz/fuzz_targets/` |
| **Tooling** | `cargo-fuzz` (libFuzzer) + AddressSanitizer + ClusterFuzzLite |
| **Test Suite ID** | FUZZ-LTP-01 |
| **Version** | 1.0 |

## 1. Introduction

This document details the fuzz testing strategy for the `hardy-ltp` and `hardy-ltp-cla` modules. As a space and long-delay DTN transport protocol operating over potentially lossy, impaired, or adversarial links, the LTP implementation must never panic, leak unbounded memory, or enter an unrecoverable state when processing malformed or corrupted network inputs.

**Primary Objective:** Ensure that no sequence of arbitrary byte inputs can trigger panics, unhandled out-of-memory (OOM) conditions, or corrupted state transitions in the parser, state machine, or network driver.

## 2. Requirements Mapping

The following specifications are verified by this plan:

| Reference | Description |
| ----- | ----- |
| **RFC 5326 §3** | Segment formats: parsing, boundary validation, and extension decoding. |
| **RFC 5326 §6** | Sans-I/O Engine operations: session state transitions, checkpoint/report processing, and cancellation handshakes. |
| **RFC 5326 §3.1** | SDNV (Self-Delimiting Numeric Value) parsing, 64-bit bounds, and canonical encoding. |
| **RFC 7122** | LTP over UDP convergence layer datagram ingestion and address handling. |
| **KISS Framing** | Escape sequence parsing, frame demarcation (`FEND`), and corruption recovery. |

## 3. Fuzz Target Definitions

### 3.1 Segment Parsing (`segment_decode`)

* **Source File:** `ltp/fuzz/fuzz_targets/segment_decode.rs`
* **Target:** `hardy_ltp::segment::Segment::parse`
* **Input:** Raw arbitrary byte sequence (`&[u8]`).
* **Invariants Checked:**
  * The decoder **MUST NOT** panic on any input.
  * If parsing succeeds, `used <= input.len()`.
  * **Roundtrip fixed-point invariant:** The parsed `Segment` re-encoded via `encode_to_vec()` must re-parse successfully into an identical `Segment` (`reparsed == seg`).
  * The canonical re-encoded length must never exceed the accepted byte count (`encoded.len() <= used`).

### 3.2 SDNV & KISS Framing (`sdnv_kiss`)

* **Source File:** `ltp/fuzz/fuzz_targets/sdnv_kiss.rs`
* **Target:** `hardy_ltp::sdnv` and `hardy_ltp::kiss`
* **Input:** Raw arbitrary byte sequence (`&[u8]`).
* **Invariants Checked:**
  * SDNV decoding (`sdnv::decode`) must reject integers exceeding 64 bits and never panic.
  * Successful SDNV decodings must re-encode to the exact predicted length and decode back to the identical numeric value.
  * KISS unescaping (`kiss::unescape`) and escaping (`kiss::escape`) must satisfy the roundtrip identity.
  * KISS frame decoding (`kiss::decode_frame`) must correctly identify frame boundaries and preserve frame payloads.

### 3.3 Sans-I/O Engine State Machine (`engine_ops`)

* **Source File:** `ltp/fuzz/fuzz_targets/engine_ops.rs`
* **Target:** `hardy_ltp::engine::Engine`
* **Input:** Structured sequence of arbitrary `EngineOp` commands generated via `arbitrary::Arbitrary`:
  * `IncomingSegment`: feed arbitrary segment octets into `handle_incoming_segment`.
  * `RequestTransmission`: initiate block transfers with varying red/green lengths.
  * `TimerTick`: advance simulated monotonic time and trigger timer table expirations.
  * `DrainOutputs` / `DrainNotices`: poll outgoing queues and notices.
* **Invariants Checked:**
  * State transitions, timer expirations, and cancellation handshakes must remain crash-free.
  * Memory allocation must remain strictly bounded under session floods (`max_recv_sessions` enforcement).

### 3.4 CLA UDP Ingestion (`cla_packet`)

* **Source File:** `ltp-cla/fuzz/fuzz_targets/cla_packet.rs`
* **Target:** `hardy_ltp_cla::LtpCla`
* **Input:** Raw arbitrary UDP datagram payloads sent to the CLA driver.
* **Invariants Checked:**
  * The async driver task must never crash or terminate when untrusted datagrams are received on the transport port.

## 4. Execution & CI Integration

### 4.1 Local Execution

Run individual fuzz targets with:

```bash
cargo +nightly fuzz run segment_decode --fuzz-dir ltp/fuzz
cargo +nightly fuzz run sdnv_kiss --fuzz-dir ltp/fuzz
cargo +nightly fuzz run engine_ops --fuzz-dir ltp/fuzz
cargo +nightly fuzz run cla_packet --fuzz-dir ltp-cla/fuzz
```

### 4.2 Automated Discovery

All targets in `ltp/fuzz` and `ltp-cla/fuzz` are automatically discovered by `.clusterfuzzlite/build.sh` and tracked in `scripts/run_lcov.sh`.
