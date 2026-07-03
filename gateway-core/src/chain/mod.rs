//! Cardano chain data the engine caches and reads.
//!
//! A Proof-of-Existence transaction's fee and the minimum-ADA its change output
//! must clear are both functions of the network's on-chain protocol parameters.
//! Those parameters change at most once per epoch, so the engine caches them per
//! `(network, epoch)` in `cw_core.cardano_protocol_params` and serves every
//! quote and build from that cache. A single background loop is the only thing
//! that ever calls the network; readers are pure database loaders and never
//! reach a provider.
//!
//! - [`attempt`] — the chain-effect ledger: a durable per-action row recorded
//!   before broadcast (publish, cancelling replacement, replenish split), its
//!   status lifecycle, and the replacement linkage the confirm authority
//!   reconciles against chain truth.
//! - [`params`] — the protocol-parameter source trait, a Koios implementation
//!   (keyless public tier by default; operator API key and self-hosted base URL
//!   via `KoiosConfig`), the populate loop, and the read-only loaders.
//! - [`gateway`] — the chain-data seam (submit, confirmation lookup, block and
//!   tip reads, raw-transaction fetch) behind one trait, a Koios
//!   implementation, a primary/secondary failover wrapper, a restart-survivable
//!   per-provider rate-limit cooldown, and an offline test gateway.
//! - [`egress`] — the per-provider request budget every provider HTTP call is
//!   admitted through (a token bucket that makes a runaway loop physically
//!   unable to stampede a provider) plus the per-day request accounting the
//!   control plane exposes.
//! - [`submit`] — the submission pipeline: claim a wallet UTxO under a per-wallet
//!   advisory lock, build and sign a Proof-of-Existence transaction (forcing the
//!   rolled-back inputs of a cancelling replacement), submit through the failover
//!   gateway, and apply the spend locally on acceptance.
//! - [`confirm`] — the singleton confirmation loop: tip-derived settlement, a
//!   two-source reorg gate, the rollback-retry / refund decision, the monotonic
//!   tip upsert, and the durable single-refund hook.
//! - [`recover`] — the crash-recovery sweep over stranded chain attempts: an
//!   attempt recorded before broadcast whose broadcast never reached the wire (a
//!   provider storm, a transport error) is re-enqueued for re-broadcast past a
//!   grace, and refunded through the single-refund hook past an absolute backstop,
//!   so a stranded record always reaches a terminal state rather than sitting in
//!   `submitting` forever.
//! - [`records`] — the single writer of the issuer-agnostic on-chain record
//!   index, fed by an `index_tx` job from the confirm threshold-flip and by the
//!   forward scan's own write transaction through its tx-scoped DML.
//! - [`scan`] — the singleton forward-scan indexer loop: a durable cursor and
//!   below-threshold pool, head-of-tick tip refresh, reorg detection and rewind,
//!   record validation and persistence, and bounded tx_cbor backfill, all on a
//!   self-paced active/idle/reorg cadence.

pub mod attempt;
pub mod confirm;
pub mod egress;
pub mod gateway;
pub mod params;
pub mod records;
pub mod recover;
pub mod scan;
pub mod submit;
