<!--
SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# MLS-TLS protocol

This Rust crate defines a sans-IO API for the ordered two-party MLS
profile over TCP. The application owns transport I/O, scheduling,
authorization, and persistent storage. The public API lives in
`src/ordered/` and is re-exported from `src/lib.rs`.

## Repository map

- `src/ordered/engine.rs` defines the engine, admission, jobs, and
  messages exchanged with connection owners.
- `src/ordered/stream.rs` and `buf.rs` define the TCP connection and
  caller-owned record buffers.
- `src/ordered/wire/` contains bounded wire codecs. `record.rs` handles
  directional record keys, nonces, in-place encryption, and key usage.
- `src/ordered/config.rs`, `auth.rs`, `storage.rs`, and `time.rs` define
  the application interfaces for configuration, authorization, storage,
  and clocks.
- `tests/ordered_api.rs` checks API guardrails. The OpenMLS and crypto
  probes in `tests/openmls_operations.rs` and `tests/crypto_operations.rs`
  use the pinned backend with production OpenMLS features.

## Documentation

- Update [the architecture guide](docs/architecture.md) alongside changes
  to ownership, message routing, record ordering, or the caller's role.
- Update [the storage guide](docs/storage.md) alongside changes to record
  contents, transactions, durability gates, or crash recovery.
- Both guides appear in the crate's rustdoc. Keep the crate-level
  implementation status current and verify links when changing headings.
  Keep method and type requirements in their own rustdoc.

## Checks

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo +nightly careful test --locked --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
```

Run `cargo deny --locked check` when dependencies change and before a release.
Run `bash fuzz/run.sh` with `cargo-afl` installed to reproduce the wire
fuzz smoke test in CI. Use `bash fuzz/run.sh -V 90` for a longer local run.
Regenerate the independent record vectors with
`ruby tests/vectors/record_vectors.rb > tests/vectors/records.txt` when their
inputs change.
