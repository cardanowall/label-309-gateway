//! The tenant ledger: accounts, the append-only money journal, and publish
//! quotes.
//!
//! This module owns the engine's money primitives. They are deliberately
//! POLICY-NEUTRAL: the engine records balances and prices publishes, but it
//! never decides who gets credited, what a refund is worth, or whether an
//! account is delinquent. Those are vendor concerns, expressed through the kind
//! registry and the pricing hook rather than baked into the engine.
//!
//! # Account provisioning
//!
//! A tenant ("account") is the unit a balance, a quote, and a published record
//! belong to. [`account`] creates one (writing the stable `cw_api.account`
//! anchor and its volatile `cw_core.account_detail` satellite in one
//! transaction) and soft-deletes it (`deleted_at`, never a hard row delete, which
//! the RESTRICT foreign keys make impossible anyway).
//!
//! # The append-only ledger
//!
//! [`journal`] is the append-only money ledger. Every balance change is one
//! immutable row; the materialised balance is maintained by a database trigger.
//! The engine seeds a small set of neutral kinds (a publish debit and two refund
//! credits); a vendor registers its own (top-ups, grants, disputes), declaring
//! per kind whether an entry may overdraw the balance. The non-negativity
//! invariant is enforced in the database from a flag stamped on each entry, so
//! the engine's enforcement has no dependency on vendor policy.
//!
//! # Publish quotes
//!
//! [`quote`] is the two-phase publish-cost protocol. A quote captures the full
//! cost of a publish (the engine-computed network fee and storage cost plus a
//! hook-supplied markup) in one durable, idempotent row. Consuming a quote is a
//! single transaction that checks affordability and inserts the signed-negative
//! publish debit, binding the quote to the record. A maintenance job expires
//! quotes whose TTL lapsed.

pub mod account;
pub mod journal;
pub mod quote;
