# Changelog

All notable changes to the Label 309 gateway are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The gateway is
distributed as source and as a container image; its version is independent of
the Label 309 SDK and CLI packages.

## [Unreleased]

## [0.1.3] - 2026-09-10

### Security

- `h2` 0.4.15 → 0.4.19 in the lockfile, closing an unbounded empty-DATA-frame
  denial of service (RUSTSEC-2026-0258). The crate sits under both the HTTP
  server that serves the data and control planes and the outbound client the
  chain and storage backends call, so the fix covers ingress and egress alike.
- `rust_decimal` 1.42.1 → 1.43.0, which drops the crate's `rkyv` 0.7 feature
  bridge and with it removes `rkyv` and its sixteen-crate subtree from the
  lockfile, closing RUSTSEC-2026-0235 (insufficient archive validation causing
  out-of-bounds reads on archives containing `Rc`/`Arc`). No feature this
  workspace enables ever activated that bridge, so the advisory was not
  reachable in a built binary; the bump removes the entry outright rather than
  leaving it to be argued away at every audit.
- `event-listener` 5.4.1 → 5.4.2 and `anyhow` 1.0.102 → 1.0.104 take the fixes
  for two soundness advisories (RUSTSEC-2026-0221, RUSTSEC-2026-0190), and
  `chacha20`, `der` and `spin` move off yanked releases. `cargo audit` is clean
  for the workspace.

## [0.1.2] - 2026-07-28

### Changed

- Adopt the `cardanowall` Label 309 SDK 0.12.0: the exact crates.io pin the
  public source resolves and the version the conformance suite drives the
  gateway's wire shape against. The SDK's additions in that release (streaming
  passphrase sealing and opening, the size estimator's explicit envelope
  shapes) are client-side surfaces the gateway does not call, so nothing in its
  behaviour, API, or schema changes.

### Security

- `quinn-proto` 0.11.14 → 0.11.16 in the lockfile, closing a denial-of-service
  advisory in the QUIC transport pulled in through the HTTP client stack.

## [0.1.1] - 2026-07-06

### Changed

- Adopt the `cardanowall` Label 309 SDK 0.11.0: the exact crates.io pin the
  public source resolves and the version the conformance suite drives the
  gateway's wire shape against. Picks up the SDK's multi-hash sealed prepare,
  passphrase two-phase publish, and `supersedes` / `uris` on the Merkle and
  content inputs. No gateway API or schema change; the wire shape the gateway
  produces and indexes is unchanged.

## [0.1.0] - 2026-07-03

First public release: the open-source backend of a Label 309 Proof-of-Existence
service. A single Rust binary plus Postgres that owns the whole publish pipeline
and the money, chain, and storage state behind it.

### Added

- **Publish pipeline** — quote, resumable content upload, and publish, with a
  two-phase quote/consume balance protocol so a publish is priced and debited
  atomically.
- **Cardano** — an in-tree transaction builder with fee estimation, plus submit,
  confirmation tracking, reorg handling, and automatic refund on permanent
  failure. Koios is the primary chain provider, with optional Blockfrost
  failover and support for a self-hosted Koios instance.
- **Arweave storage** — streamed, resumable content and ciphertext uploads
  through Turbo in production (or the ArLocal emulator in development), with a
  crash-recoverable reservation lifecycle and prepaid-credit reconciliation.
- **Records index** — a forward on-chain scan feeding an operator- and
  account-agnostic global records feed.
- **Balance ledger** — an append-only per-account journal with an
  overdraft-refused balance and a vendor-extensible adjustment-kind registry.
- **FX and pricing** — a live price-oracle refresh loop (keyless CoinPaprika by
  default, optional CoinGecko) that caches one snapshot per tick, with an
  operator-default margin and a per-account override. No hardcoded fallback rate.
- **HTTP planes** — a per-account data plane (`/api/v1`) authenticated with API
  keys, an operator-only control plane (`/control/v1`), a Standard-Webhooks
  lifecycle firehose, and a bundled static admin console at `/admin`. Each plane
  versions its OpenAPI contract independently.
- **Interactive API reference** — an interactive documentation page for each
  plane (`/api/v1/docs`, `/control/v1/docs`) that renders the plane's OpenAPI
  document. Served fully offline: the renderer is vendored into the binary, so a
  self-hosted deployment never reaches a third-party CDN.
- **Multi-tenancy** — an operator → account → credential model with scoped
  wallet and storage-funding grants, over a shared, tenant-agnostic records index.
- **Operator tooling** — an age-encrypted keyring holding every signing key, and
  `keyring`, `operator bootstrap`, `storage bootstrap`, and `admin` subcommands.
  The `admin` CLI gives full control-plane coverage — every `/control/v1/*` route
  (accounts, keys, credentials, wallets, storage sources and top-ups, margins,
  webhooks, pricing/FX, chain provider usage, and the audit log) is drivable
  without curl.
- **Operations** — a container image, an example single-host Docker Compose
  deployment, and optional error monitoring for any Sentry-compatible backend.

[Unreleased]: https://github.com/cardanowall/label-309-gateway/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/cardanowall/label-309-gateway/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cardanowall/label-309-gateway/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cardanowall/label-309-gateway/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cardanowall/label-309-gateway/releases/tag/v0.1.0
