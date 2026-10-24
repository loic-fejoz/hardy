# hardy-hqfbp-cla

Hamradio Quick File Broadcasting Protocol (HQFBP) Convergence Layer Adapter (CLA) for the Hardy Bundle Protocol Agent.

Part of the [Hardy](https://github.com/ricktaylor/hardy) DTN Bundle Protocol implementation.

## Overview

This crate provides a CLA implementing RFC 9171 §7 over amateur radio physical channels using the HQFBP transport specification (`hqfbp-rs`). It enables delay-tolerant bundle transmission across VHF/UHF/HF packet radio, KISS TNCs, soundmodem soundcards, AX.25 / Direwolf bridges, and GNU Radio SDR flowgraphs.

## Features

- **Amateur Radio Addressing:** Seamless translation between BPv7 `ClaAddress` and ham callsigns/SSIDs, with native `"CQ"` broadcast support.
- **Multiple Transports:** Configurable underlying physical layer:
  - **KISS over TCP:** Connects to Direwolf, Soundmodem, or networked TNCs with hardware parameter framing (`TxDelay`, `Persistence`, `SlotTime`).
  - **KISS over Serial / TTY:** Native RS-232 / USB TNC support via asynchronous serial streams (enabled via the `serial` feature).
  - **Direct UDP:** Low-overhead datagram encapsulation for GNU Radio flowgraphs and local loopback testing.
- **Dynamic Content Encoding Pipeline:**
  - Configurable hailing/announcement channel encoding pipeline (e.g. `[H, Crc32]`).
  - Default bundle PDU content encoding pipeline (e.g. `[Gzip, H, Crc32]`).
  - Non-blocking dynamic runtime selector engine (`DynamicEncodingSelector`) allowing per-bundle (routing metadata/lane) and per-peer encoding overrides.
  - Forward Error Correction (FEC) support including Reed-Solomon $(255, 223)$ and RaptorQ fountain codes.
- **Robust Multi-Transmitter State Machine:**
  - Concurrent deframing and reassembly across multiple transmitting callsigns.
  - Hard memory accounting on in-flight buffered bytes with backpressure enforcement.
  - Session TTL timeouts and LRU eviction of idle stations to prevent resource exhaustion from RF packet loss.
  - Fast 64-bit FNV payload hash deduplication to eliminate RF packet radio echoes and digipeater retransmissions.

## Configuration

In `bpa-server.yaml`, configure the HQFBP adapter under `clas`:

```yaml
clas:
  - name: hqfbp-tnc
    type: !Hqfbp
      my_callsign: "F4JXQ"
      transport:
        mode: !KissTcp
          host: "127.0.0.1"
          port: 8001
          tx_delay_ms: 300
          persistence: 63
          slot_time_ms: 100
      hailing_encodings: "h, crc32"
      bundle_encodings: "gzip, chunk(240), h, crc32"
      max_concurrent_senders: 16
      max_in_flight_bytes: 10485760  # 10 MB
      session_ttl_secs: 120
      peers:
        - callsign: "G4DPZ"
          encodings: "chunk(128), h, rs(255,223)"
```

## Licence

Apache 2.0 -- see [LICENSE](../LICENSE)
