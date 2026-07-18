# nex — Road to v1.0.0

A backlog for taking `nex` to a v1.0.0.

---

## 0. Assessment (2026-07)

What blocks a credible v1.0 (the rest of this document):

- **API inconsistency is the #1 problem.** Parsing entry points have proliferated
  into 8+ shapes with overlapping semantics. This must be unified before 1.0
  freezes the surface.
- **Builders cannot fail.** `build()`/`to_bytes()` never return `Result`; malformed
  or over-length input produces silently wrong bytes.
- **Dependency & feature hygiene is weak.** `nex-socket` forces `tokio` on sync
  users; `nex-packet` pulls all of `rand` for one line.
- **CI is effectively unverified.** Only `cargo build` on 3 OSes — no tests, no
  clippy, no fmt, no feature matrix, no MSRV, no supply-chain checks.
- **Unsafe boundary is undocumented.** 9 `unsafe impl Send/Sync` and ~141 unsafe
  sites in `nex-datalink` with no safety rationale comments.
- **No release scaffolding.** No CHANGELOG,MSRV, or semver/API-snapshot tracking.

---

## P0 — Blockers for a Stable v1.0 Surface

### P0.1 Unify the packet parsing API

Today the surface is inconsistent and confusing. Observed across `nex-packet`:

- `Packet` trait: `from_buf(&[u8]) -> Option`, `from_bytes(Bytes) -> Option`.
- Per-type: `try_from_buf -> Result<_, ParseError>`, `try_from_bytes`,
  `try_from_buf_strict`, `try_from_bytes_strict`, `from_buf_strict -> Option`,
  `from_bytes_strict -> Option`.
- DNS: `from_buf_mut(&mut &[u8]) -> Option`, `from_bytes(&[u8]) -> Result<_, Utf8Error>`.
- Ethernet: `from_bytes(Bytes) -> Result<EthernetHeader, String>` ← String error.

Actions:

- [ ] Define ONE canonical parsing contract and document it in `parse.rs`:
  - [ ] `try_from_bytes(Bytes) -> Result<Self, ParseError>` — owned, zero-copy view.
  - [ ] `try_from_buf(&[u8]) -> Result<Self, ParseError>` — borrowed.
  - [x] A single explicit "strict payload-length" opt-in (e.g. a `Strictness`/
        `ParseOption` arg) instead of `*_strict` name-doubling every method.
- [x] Remove `EthernetHeader::from_bytes -> Result<_, String>`; replace with the
      canonical `ParseError` form (`nex-packet/src/ethernet.rs:165`).
- [x] Fold `DnsName::from_bytes -> Result<_, Utf8Error>` into `ParseError::InvalidUtf8`
      so DNS matches every other module (`nex-packet/src/dns.rs:1216`).
- [x] Decide the fate of `from_* -> Option` on the `Packet` trait
      (`nex-packet/src/packet.rs:9-12`): either make the trait `try_from_*`-based
      with `ParseError`, or keep `Option` only as a thin infallible-intent shim.
- [x] Provide `#[deprecated]` aliases for one release wherever a public name changes.
- [x] Write a doc table mapping every old parsing fn → its v1.0 replacement.

Acceptance: every protocol module exposes the *same* small set of parse fns with
the *same* signatures and error type; `grep -r "Result<.*String>"` returns nothing
in `nex-packet`.

### P0.2 Make builders fallible and validating

Every builder currently returns infallibly (`nex-packet/src/builder/*.rs`):
`build(self) -> Packet` and `to_bytes(self) -> Bytes`, with no bounds checks.

- [x] Change builder finalizers to `build(self) -> Result<Packet, BuildError>`
      (or a `try_build`) wherever a field can exceed protocol limits:
  - [x] IPv4/IPv6 total length, IHL/options length, payload length.
  - [x] TCP data offset / options length; UDP length; ICMP/ICMPv6 sizing.
  - [x] DHCP options length; NDP option length; ARP fixed sizing.
- [x] Validate checksum prerequisites (pseudo-header context present) before emit.
- [x] Introduce a typed `BuildError` (see P0.4) with actionable variants.
- [x] Keep an infallible fast path only where inputs are provably in-range (e.g.
      fixed-size headers), and document why.

Acceptance: constructing an over-length packet returns `Err`, never wrong bytes;
property tests (P1.5) confirm build→parse round-trips for valid inputs only.

### P0.3 Freeze the public API surface (semver contract)

- [ ] Audit every `pub` item per crate; mark internal helpers `pub(crate)`.
- [ ] `nex-core::bitfield` (`pub type u1 = u8 …`): make private or move behind a
      documented `#[doc(hidden)]` implementation-detail boundary — these aliases
      should not be part of the stable contract.
- [ ] Decide `nex-sys`'s status: it is a low-level internal crate — either mark it
      clearly "internal, no semver guarantees" in its docs or make its surface
      `pub(crate)`-equivalent via `#[doc(hidden)]`.
- [ ] Normalize accessor naming: replace `get_*` (73 occurrences in `nex-packet`)
      with idiomatic Rust names; keep `#[deprecated]` aliases for one release.
- [ ] Audit public struct fields (e.g. `datalink::Config`, packet headers): decide
      field-access vs accessor policy; document undocumented `pub` fields
      (`Config.linux_fanout`, `Config.promiscuous` lack doc comments).
- [ ] Apply `#[non_exhaustive]` to all enums/structs expecting future variants
      (protocol number enums, `Channel`, error types, config structs).
- [ ] Audit `pub const` protocol constants for naming + semver stability.
- [ ] Document `new_unchecked` invariants (`GenericMutablePacket::new_unchecked`,
      any `*_unchecked`) with `# Safety` sections.
- [ ] Generate a machine-readable public API snapshot per crate (e.g.
      `cargo public-api`) and diff it in CI to catch accidental breaks.

Acceptance: a documented, intentional surface; `cargo public-api` diff is clean and
tracked; no accidental `pub` internals.

### P0.4 A real error model (kill `String` errors)

- [x] `nex-core::interface`: replace `Result<_, String>` with a typed error
      (`nex-core/src/interface.rs:359,592,597` — `default`, `get_default_interface`,
      `get_default_gateway`).
- [x] Add `nex-packet::BuildError` for builders (P0.2).
- [ ] Keep `io::Error` only at raw syscall/socket boundaries; convert to typed
      errors where the library adds semantic meaning (datalink/socket config).
- [ ] Ensure `ParseError` carries enough context for fuzz triage and diagnostics
      (it already has `context`; verify every construction site sets a useful one).
- [ ] All public error types implement `std::error::Error + Send + Sync + 'static`.
- [ ] No `panic!`/`unreachable!`/`unwrap` reachable from public APIs on malformed
      input. (Current `unreachable!`/`panic!` sites are test-only — keep it that way
      and add a CI grep guard.)

Acceptance: no `-> Result<_, String>` in any public API; a documented error taxonomy.

### P0.5 Feature flags & dependency diet

- [x] `nex-socket`: gate async behind an `async` (tokio) feature. Sync users must
      not pull `tokio` (`nex-socket/Cargo.toml` currently hard-depends on tokio
      with `time,sync,net,rt`). Split sync/async cleanly.
- [x] `nex-packet`: `rand` is a full dependency used in exactly one place
      (`builder/ipv4.rs:33`, random IP identification). Either feature-gate it,
      replace with a lightweight PRNG, or let the caller supply the id. Do not force
      `rand` on every packet-parsing consumer.
- [x] `nex-datalink`: consider gating `async_io` + `futures-core` behind an `async`
      feature; sniffers that only send/recv synchronously shouldn't compile it.
- [x] Define default features intentionally and document each (`nex-core` defaults
      to `gateway` — confirm that's the right default).
- [x] Wire facade features through: `nex` exposes `pcap`, `serde`; add `async` and
      any new sub-crate features so the facade stays a faithful superset.
- [x] Verify all feature combos build: default, `--no-default-features`, `serde`,
      `pcap`, `async`, `--all-features` (enforce in CI, P0.6).

Acceptance: `cargo tree` for a sync-only `nex-socket` user contains no `tokio`;
`nex-packet` with default features contains no `rand` unless opted in.

### P0.6 Quality gates in CI (the current CI proves almost nothing)

Current `.github/workflows/rust.yml` runs only `cargo build` on Linux/macOS/Windows.

- [x] Replace with a matrix that runs, per OS:
  - [x] `cargo test --workspace --lib`
  - [x] `cargo test --workspace --doc`
  - [x] `cargo build --workspace --all-targets` (examples included)
- [x] Lint job: `cargo fmt --all -- --check` +
      `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [x] Feature-combo job: default / `--no-default-features` / `serde` / `pcap` /
      `async` / `--all-features`.
- [ ] MSRV job: pin and verify an MSRV (edition 2024 ⇒ MSRV ≥ 1.85; declare
      `rust-version` in every `Cargo.toml` and test it).
- [ ] Supply chain: `cargo deny check` (licenses, advisories, bans, sources) +
      add `deny.toml`.
- [ ] Public API snapshot diff job (P0.3).
- [x] Remove `#![deny(warnings)]` from `nex-datalink/src/lib.rs` (line 3): it makes
      builds break on future compilers/new lints. Enforce warnings in CI via
      `RUSTFLAGS=-Dwarnings`, not in source.
- [ ] A documented, manual privileged-test matrix for raw sockets / datalink I/O
      that CI cannot run (see P1.2 / P1.3).

Acceptance: a red/green CI that actually gates merges on tests, lints, features,
MSRV, and supply chain across all three OSes.

### P0.7 Unsafe & OS-resource safety hardening

- [ ] Add a `# Safety` comment to every `unsafe` block and every `unsafe impl` in
      `nex-datalink` (~141 sites) and `nex-sys`, justifying the invariant.
- [ ] Justify or remove the 9 `unsafe impl Send/Sync` in `nex-datalink`
      (`wpcap.rs`, `async_io/wpcap.rs`): document what makes the raw Npcap handles
      actually thread-safe, or wrap them so the impl is sound.
- [ ] Ensure every OS handle (fd, BPF device, Npcap adapter, packet buffer) is
      owned by an RAII type that closes on *all* error paths.
  - `nex-sys::FileDesc` already drops the fd — audit that every fd flows through it
    and that no early-return leaks a half-opened resource.
- [ ] Prefer typed wrappers over raw integer/pointer handles at module boundaries.
- [ ] Add error-path tests that open then fail to confirm no leak/double-close.
- [ ] Run Miri on pure `nex-packet`/`nex-core` parsing/building where feasible.
- [ ] Run ASan/UBSan on Linux packet parse + datalink where feasible.

Acceptance: `cargo miri test` passes for pure logic crates; every unsafe site has a
rationale; a reviewer can audit the FFI boundary from comments alone.

---

## P1 — Correctness, Performance, Robustness

### P1.1 Packet layer architecture

- [ ] Cleanly separate the four packet categories and document which is which:
  read-only borrowed views, mutable borrowed views, owned decoded packets, builders.
- [ ] Fix `GenericMutablePacket` re-parsing: `header()`, `header_mut()`, `payload()`,
      `payload_mut()` each call `lengths()` which re-runs `P::from_buf` on every
      access (`nex-packet/src/packet.rs:124-165`). Cache lengths on construction or
      on first use.
- [ ] Define clear freeze/commit semantics for mutable views (`freeze()` currently
      re-parses via `from_buf`); document cost and invalidation rules.
- [ ] Consolidate/trim the `Packet` trait: `to_bytes_mut`/`header_mut`/`payload_mut`
      allocate fresh `BytesMut` each call — confirm these belong on the trait or move
      to explicit conversion helpers.
- [ ] Decide whether generated bitfield accessors are public API or hidden detail
      (ties to P0.3 `bitfield`).
- [ ] Extension-header / options parsing: audit IPv4 options, IPv6 ext headers, TCP
      options, DNS compression, DHCP options for strict-length correctness and
      truncation handling.

### P1.2 Datalink backends

- [ ] Document per-platform behavior of the stable `channel()` / async channel API:
      blocking vs timeout vs nonblocking vs async semantics.
- [ ] Linux packet socket: verify Layer2/Layer3 modes, promiscuous, fanout, buffer
      sizing, timeout behavior.
- [ ] BPF (macOS/BSD): device selection, header-complete mode, buffer sizing,
      poll/read iteration, `bpf_fd_attempts` behavior.
- [ ] Windows/Npcap: adapter name conversion, packet alloc/cleanup, send/recv thread
      safety (ties to the `unsafe impl` audit in P0.7).
- [ ] Confirm backend submodules stay private (already done per `API_SURFACE`);
      keep only the generic API public.
- [ ] `RawSender::send`/`build_and_send` return `Option<io::Result<()>>` — the
      `Option` (capacity) vs `Result` (I/O) split is subtle; document it precisely
      or model it as one typed error.
- [ ] Add manually-enabled integration tests per OS (loopback / veth where possible).

### P1.3 Socket layer

- [ ] Symmetry: ensure TCP/UDP/ICMP each expose the same shape sync and async.
- [ ] Constructor policy: infallible config + fallible builder is the current shape
      (`TcpConfig` etc.) — apply it consistently to UDP/ICMP and document it.
- [ ] Normalize bind/connect/timeout behavior across platforms.
- [ ] Tests for socket options: TTL/hop limit, broadcast, multicast, device binding,
      IPv4/IPv6 family mismatch (config `validate()` covers some — extend to runtime),
      nonblocking-state preservation across operations.
- [ ] Document privilege requirements for raw ICMP / raw TCP per platform.
- [ ] Confirm sync impls never transitively require the async runtime (P0.5).

### P1.4 Performance

- [ ] Establish Criterion baselines beyond the single `packet_parse` bench:
      Ethernet/VLAN parse, IPv4/IPv6 parse, TCP/UDP parse, DNS name decompression,
      serialization, checksum, and datalink send/recv loops where measurable.
- [ ] Measure allocations in parsers/builders; ensure borrowed views don't clone
      `Bytes` or allocate where a slice suffices.
- [ ] Review checksum impl (`nex-packet/src/checksum.rs` + call sites) for alignment
      and portable vectorization; verify the folding/carry handling on odd lengths.
- [ ] Fix the `GenericMutablePacket` re-parse hot path (also in P1.1) — it's a real
      throughput cost for in-place mutation workloads.
- [ ] Add a documented benchmark workflow and/or CI regression tracking.

### P1.5 Fuzzing & robustness

- [ ] Keep the 5 existing targets; add: Ethernet/VLAN, IPv4 options, IPv6 ext
      headers, ICMPv6/NDP options, DNS records + compressed names, DHCP options,
      GRE optional fields, VXLAN.
- [ ] Add seed corpora from real captures and protocol edge cases.
- [ ] Wire fuzz findings back as regression unit tests.
- [ ] Add property tests (proptest) for parse↔serialize round-trips per family.
- [ ] Document `cargo fuzz` usage in `CONTRIBUTING.md`.
- [ ] Guarantee (and test) panic-free parsing on arbitrary bytes for every module.

---

## P2 — Documentation, Ergonomics, Release

### P2.1 Documentation

- [ ] Crate-level docs for every published crate; module docs for every stable module.
- [ ] Rich, compile-tested doc examples for: parse an Ethernet frame; build IPv4/UDP
      and IPv6/UDP; compute checksums; datalink send/recv; async datalink recv;
      TCP/UDP/ICMP sockets (sync + async).
- [ ] Document platform support matrix and privilege requirements in one place.
- [ ] Document the safety model, error taxonomy, feature flags, and performance
      expectations.
- [ ] `docs.rs` metadata: `all-features` (or curated) docs build per crate; verify
      feature-gated items render.
- [ ] Rewrite `README.md`: it omits `nex-core`/`nex-socket` from the crate list,
      predates the feature set, and states version `0.26`. Make it accurate for 1.0
      without overpromising unsupported protocols/platforms.

### P2.2 Migration & compatibility

- [ ] Write `MIGRATION.md` / migration notes `0.26.x → 1.0.0` covering: parse API
      unification, fallible builders, `get_*` renames, error-type changes, feature
      changes (`tokio`/`rand`).
- [ ] Add a v1.0 semver/compatibility policy (what's covered, MSRV policy, platform
      tiers, `#[non_exhaustive]` implications).

### P2.3 Repository & release readiness

- [ ] Add `CHANGELOG.md` with an Unreleased section (keep-a-changelog style).
- [ ] Verify workspace version/dependency pinning is release-consistent.

---

## Suggested Execution Order

1. **P0.6 CI + P0.7 unsafe comments** — get a truthful baseline and stop regressions.
2. **P0.5 features/deps** — cheap, high-impact; unblocks clean downstream trees.
3. **P0.1 parse unification + P0.4 error model** — the biggest, most breaking surface
   change; do it once, early, behind deprecations.
4. **P0.2 fallible builders** — depends on the error model.
5. **P0.3 API freeze + public-api snapshot** — lock the surface after 1–4 settle.
6. **P1.1–P1.3 correctness** (packet arch, datalink, socket) with the manual test
   matrix.
7. **P1.4 perf + P1.5 fuzz/property tests** — prove robustness and speed.
8. **P2 docs, migration, release scaffolding** — last, once the surface is final.

## Definition of Done for v1.0.0

- [ ] One consistent parse API and one error taxonomy across all crates.
- [ ] Builders validate and cannot silently emit invalid packets.
- [ ] Sync users pull no async runtime; parsers pull no needless deps.
- [ ] Green CI: tests + doc-tests + clippy + fmt + feature matrix + MSRV +
      `cargo deny` + public-api diff on Linux/macOS/Windows.
- [ ] Every `unsafe` justified; Miri-clean pure crates; no reachable panics on
      malformed input; fuzz + property tests in place.
- [ ] Complete docs, accurate README, migration guide, CHANGELOG.
