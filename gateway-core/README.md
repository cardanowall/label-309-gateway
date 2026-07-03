# gateway-core

The gateway engine: the library the `gateway` binary is assembled from. It owns
the whole publish pipeline and the money, chain, and storage state behind it,
exposed as composable seams (a router factory, a pricing source, a storage
backend) so the binary wires them and an embedding application could too.

Everything the engine creates lives in its own `cw_core` schema (all volatile
state, plus sqlx's migration-tracking table) and a stable `cw_api` extension
contract (the small set of anchor tables an embedding application may
FK-reference). Neither touches the host database's `public` schema, so the
engine coexists with another application's tables in one database. `MIGRATOR`
embeds the schema corpus; the companion `sqlx.toml` redirects the tracking table
into `cw_core` and creates that schema before the first migration.

## Modules

- **`runtime`** — the Postgres-backed job runtime. Jobs are claimed with `FOR
UPDATE SKIP LOCKED` and fenced by a per-claim token, so a worker whose lease
  expired cannot corrupt a row it no longer owns. Retries, backoff, deadline
  enforcement, deferral, and an in-process cron scheduler with double-fire
  protection are all driven from the database; no leader election.
- **`events`** — durable per-subject events appended in a commit-ordered
  sequence, plus the outbound delivery outbox that feeds SSE and webhooks.
- **`webhook`** — the fan-out spine: a presence-based set-drain reader over the
  delivery outbox, subject-owner resolution, per-subscription delivery rows,
  HMAC-signed delivery, retry/auto-disable, and the SSRF egress guard.
- **`chain`** — the Cardano side: protocol-parameter caching per epoch, the
  transaction submit/confirm/reorg loops, permanent-failure auto-refund, and the
  forward records index that feeds the account-blind global feed. Koios is the
  primary provider with optional Blockfrost failover.
- **`wallet`** — operator wallets: the age-encrypted keyring, the durable
  per-UTxO state machine submits lease against, the least-loaded wallet
  scheduler, the canonical-shape fee quote, and the replenish job.
- **`storage`** — Arweave content storage: streamed resumable uploads, the
  charge-at-upload reservation lifecycle with crash recovery, ANS-104 data-item
  signing, and the Turbo winc-credit reconcile loop (arlocal in dev).
- **`ledger`** — the tenant money primitives: account provisioning, the
  append-only balance journal with a vendor-extensible kind registry, and the
  two-phase quote/consume publish-cost protocol.
- **`pricing`** — the live FX lane: a scheduled refresh loop that reads the price
  oracles and caches one snapshot per tick (the only oracle caller), plus the
  DB-backed pricing seam every quote resolves through. Live-data only: no
  hardcoded fallback ratio, skip-and-serve-the-last-row on a per-byte miss.
- **`maintenance`** — the create-ahead / drop-old partition framework that keeps
  the range-partitioned history and event tables small.
- **`api`** — the HTTP surface: the data-plane and control-plane router
  factories, request auth, the RFC 7807 error envelope, the SSE streams, and the
  `AppState` / `ControlState` seams the binary populates.
- **`http`** — capped reads of external-provider response bodies, so a hostile or
  compromised provider cannot OOM the process with an oversized body.
