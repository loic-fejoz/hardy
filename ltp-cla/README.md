# hardy-ltp-cla

An RFC 5326 / RFC 7122 Licklider Transmission Protocol (LTP) and KISS Convergence Layer Adapter (CLA) for the Hardy BPv7 Bundle Processing Agent.

## Features

- **UDP Transport (RFC 7122)**: Standard LTP over UDP datagrams (default port 1113).
- **KISS Transport**: Encapsulated LTP over KISS framing for AX.25 packet radio / Direwolf TNCs.
- **Full BPA Integration**: Implements [`hardy_bpa::cla::Cla`](https://docs.rs/hardy-bpa), reporting deferred transfer outcomes (`Accepted` -> `Completed`/`Failed`) and streaming ingress dispatch.
