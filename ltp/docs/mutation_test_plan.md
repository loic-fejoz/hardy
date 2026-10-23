# Mutation Test Plan: LTP and LTP-CLA

| Document Info | Details |
| ----- | ----- |
| **Functional Area** | Test Quality, Fault Detection & Code Hardening |
| **Module** | `hardy-ltp` and `hardy-ltp-cla` |
| **Tooling** | `cargo-mutants` |
| **Test Suite ID** | MUT-LTP-01 |
| **Version** | 1.0 |

## 1. Introduction

Mutation testing evaluates the efficacy of the test suite by systematically introducing syntactic faults ("mutations") into the production source code and verifying that existing tests fail ("kill the mutant"). If a mutant survives without any test failing, it reveals a blind spot where logic errors could go undetected.

For a mission-critical space transport protocol like LTP (RFC 5326), mutation testing provides assurance that boundary checks, state machine transitions, timeout backoffs, and cancellation triggers are rigorously asserted.

## 2. Configuration & Scope

Mutation testing configuration is located at `.cargo/mutants.toml`.

### 2.1 Scope & Filters

* **`hardy-ltp`**: ~600 mutants covering:
  * SDNV variable-length encoding, overflow rejection, and canonical checks (`sdnv.rs`).
  * RFC 5326 segment parsing, extension validation, and byte serialisation (`segment/`).
  * Sans-I/O Engine state transitions, timers, retransmission limits, and session limits (`engine/`).
  * KISS framing, byte escaping, and error detection (`kiss.rs`).
  * Contiguous range sets and gap coalescing (`range.rs`).
* **`hardy-ltp-cla`**: ~75 mutants covering:
  * CLA driver loop, UDP socket management, and KISS TCP reconnection with backoff (`driver.rs`).
  * BPA integration, registration, and peer mapping resolution (`cla.rs`).
  * Transport configuration defaults and humantime parsing (`config.rs`).

### 2.2 Excluded Patterns

To focus CPU cycles on behavioral logic, pure formatting boilerplate is excluded:
* `.*Display::fmt.*`
* `.*Debug::fmt.*`
* `.*Error::fmt.*`
* Non-functional capacity calls (`with_capacity`, `reserve`).

## 3. Execution & Workflow

### 3.1 Local Execution via Helper Script

The repository provides `scripts/run_mutants.sh`:

```bash
# Run mutation testing on hardy-ltp (default)
./scripts/run_mutants.sh

# Run on both hardy-ltp and hardy-ltp-cla
./scripts/run_mutants.sh --all

# Run incrementally on files modified in git
./scripts/run_mutants.sh --diff

# Target a specific file
./scripts/run_mutants.sh --file ltp/src/range.rs
```

### 3.2 Continuous Integration

Automated mutation testing is configured in `.github/workflows/mutants.yml`:
* **Pull Requests:** Runs in incremental mode (`--in-diff`) against the PR base branch whenever `ltp/**` or `ltp-cla/**` files change.
* **Scheduled:** Runs weekly (Sunday 03:00 UTC) across the full LTP codebase.
* **Manual (`workflow_dispatch`):** Allows on-demand execution on specific packages.

## 4. Assessment & Remediation

When a mutant survives:
1. Examine the diff in `mutants.out/mutants.json`.
2. Determine if the mutant represents meaningful behavioral logic or dead/equivalent code.
3. If behavioral, add a focused unit or property test in `ltp/tests/` or `ltp-cla/tests/` specifically asserting the expected behavior.
