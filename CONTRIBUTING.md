# Contributing

Run formatting, linting, and the workspace tests before submitting changes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Raw socket and datalink changes also require the manual checks in
`docs/PRIVILEGED_TESTING.md`. Packet hot-path changes should be measured using
`docs/BENCHMARKING.md`.

## Fuzzing

Install the nightly fuzzing frontend and list the available targets:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
```

Run a target with its checked-in seed corpus:

```sh
cargo +nightly fuzz run frame_parse
cargo +nightly fuzz run ethernet_vlan
cargo +nightly fuzz run dns_records
```

Use `cargo +nightly fuzz run <target> -- -max_total_time=60` for a bounded local
run. Crashes are written under `fuzz/artifacts/<target>`. Minimize a finding
before diagnosing it:

```sh
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash>
```

Every confirmed parser defect must receive a deterministic unit or integration
regression test before the implementation is fixed. Keep only sanitized,
minimal corpus inputs. The checked-in `hex:` format is decoded by targets that
use it and makes packet seeds reviewable without committing opaque binaries.

## Repository conventions

Documentation, comments, public APIs, and commit messages are written in
English. Avoid unrelated formatting or generated-file changes, and keep each
commit focused on one reviewable concern.
