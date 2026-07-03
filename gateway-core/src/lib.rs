//! The gateway engine.
//!
//! A Postgres-backed job runtime, a durable per-subject event log, and a
//! namespaced migration set. The engine owns two schemas: its private `cw_core`
//! namespace (everything volatile, plus sqlx's migration-tracking table) and the
//! stable `cw_api` extension contract (the small set of anchor tables an
//! embedding application may FK-reference). Neither schema touches the host's
//! `public` schema, so the engine can be embedded alongside another
//! application's tables in the same database.
//!
//! # Components
//!
//! - [`runtime`] — the job runtime: claim/heartbeat/complete/fail/defer with
//!   per-claim fencing, a sweeper that reclaims expired leases, retry with
//!   fixed or exponential backoff, deadline enforcement, an in-process cron
//!   scheduler, a queue-policy registry, and detached-connection session
//!   advisory locks.
//! - [`events`] — durable per-subject events appended in a commit-ordered
//!   sequence, plus the outbound delivery outbox.
//! - [`webhook`] — the webhook fan-out spine: a presence-based set-drain reader
//!   over the delivery outbox and subject-owner resolution for the three subject
//!   kinds, feeding per-subscription delivery rows.
//! - [`maintenance`] — partition create-ahead / drop-old framework for the
//!   range-partitioned history and event tables.
//! - [`chain`] — Cardano chain data the engine caches: a background loop fetches
//!   protocol parameters per epoch and stores them, and a read-only loader
//!   serves them to quotes and builds without any network call.
//! - [`wallet`] — operator wallets: the age-encrypted keyring, the durable
//!   per-UTxO state machine submits lease against, the least-loaded wallet
//!   scheduler, the canonical-shape fee quote, and the replenish job.
//! - [`ledger`] — the tenant money primitives: account provisioning, the
//!   append-only balance journal (policy-neutral, with a vendor-extensible kind
//!   registry), and the two-phase publish-cost quote/consume protocol.
//! - [`pricing`] — the live FX lane: a scheduled refresh loop that reads the
//!   price oracles and caches one snapshot per tick (the only oracle caller), and
//!   the DB-backed pricing seam every quote resolves through. Live-data-only: no
//!   hardcoded fallback ratio, skip-and-serve-the-last-row on a per-byte miss.
//! - [`http`] — capped reads of external-provider response bodies: every
//!   outbound provider JSON/text body is streamed into a bounded buffer with a
//!   hard byte ceiling, so a hostile or compromised provider cannot OOM the
//!   process with an oversized body.
//! - `testsupport` — a Postgres harness for the feature-gated integration
//!   tests (compiled only under the `pg-tests` feature).
//!
//! # Migrations
//!
//! [`MIGRATOR`] embeds the schema corpus and applies it via sqlx. The
//! companion `sqlx.toml` redirects the migration-tracking table into `cw_core`
//! and creates that schema ahead of the first migration.

pub mod api;
pub mod chain;
pub mod error;
pub mod events;
pub mod http;
pub mod ledger;
pub mod maintenance;
pub mod pricing;
pub mod runtime;
pub mod storage;
pub mod wallet;
pub mod webhook;

#[cfg(feature = "pg-tests")]
pub mod testsupport;

pub use error::{Error, Result};

/// The embedded migration set for the engine's `cw_core` schema.
///
/// The `sqlx.toml` next to this crate's manifest redirects sqlx's own
/// migration-tracking table to `cw_core._sqlx_migrations` and creates the
/// `cw_core` schema before the first migration runs, so applying this migrator
/// against a fresh database bootstraps the engine without writing to `public`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The Postgres channel the job-insert trigger NOTIFYs and the runtime LISTENs.
///
/// Used purely as a wake-hint for the claim loop; correctness never depends on
/// a notification arriving (the loop always polls on an interval fallback).
pub const JOB_AVAILABLE_CHANNEL: &str = "cw_core_job_available";

/// The Postgres channel the subject-event trigger NOTIFYs and an SSE stream
/// LISTENs on. The payload is `<subject_kind>:<subject_id>`.
///
/// Used purely as a wake-hint for an open event stream; correctness never
/// depends on a notification arriving (the stream always re-reads the durable
/// event log on a poll interval fallback).
pub const SUBJECT_EVENT_CHANNEL: &str = "cw_core_subject_event";
