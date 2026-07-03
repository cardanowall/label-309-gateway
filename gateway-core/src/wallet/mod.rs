//! Operator wallets: keyring, UTxO state machine, scheduler, quote, replenish.
//!
//! This module is the gateway's submit-throughput substrate. An operator
//! registers any number of signing wallets; submits fan out across them, and
//! within a wallet two in-flight transactions can never select the same UTxO.
//! The design holds two guarantees by construction:
//!
//! - **Exact quotes with no wallet reads.** Every canonical UTxO has the same
//!   CBOR width, so a one-input + one-change-output transaction's fee depends
//!   only on the record length. [`quote`] prices that canonical shape against a
//!   synthetic input and returns a fee a later submit pays byte-for-byte, never
//!   touching wallet state.
//! - **No double-spend within a wallet.** A UTxO is leased (not merely hoped
//!   for) only at submit time: [`utxo::claim`] flips one canonical row to
//!   `in_flight` under a fencing token, and the submit runs under a per-wallet
//!   session advisory lock ([`pool::lock_wallet`]) held across build, sign, and
//!   submit. On acceptance the spend and its expected change are recorded
//!   locally so the wallet's balance stays honest before confirmation.
//!
//! # Components
//!
//! - [`config`] — the network enum, the canonical lovelace band, lease duration,
//!   and minimum canonical count; every path is parameterised by these.
//! - [`operator`] — operator and operator-wallet rows and their lifecycle.
//! - [`grant`] — wallet spend authority: the scope-bound [`grant::AuthorizedWallet`]
//!   capability, the [`grant::authorize_spend`] check, and grant issue/revoke.
//! - [`keyring`] — the age-encrypted keyring envelope, passphrase unlock, and
//!   per-entry address verification, holding both the zeroizing
//!   [`keyring::WalletSigner`] (Cardano anchoring keys) and the
//!   [`keyring::ArweaveFundingSigner`] (Arweave storage keys) in one store.
//! - [`keyring_edit`] — the write side of the keyring: the
//!   [`keyring_edit::KeyringEditor`] creates, grows, shrinks, and re-encrypts
//!   envelopes, round-tripping every result through the real unlock before it
//!   is handed back. This is what the `gateway keyring` subcommands drive.
//! - [`utxo`] — the durable per-UTxO state machine: ingest, claim/release,
//!   apply-change-locally, confirmation, the lease reaper, and the canonical
//!   predicate.
//! - [`pool`] — the least-loaded wallet scheduler, per-wallet advisory locks,
//!   submission counters, and the daily decay + retire sweep.
//! - [`quote`] — the canonical-shape fee quote.
//! - [`replenish`] — the split planner and the per-wallet replenish job that
//!   keeps each wallet stocked with canonical UTxOs.
//! - [`submitter`] — the submission seam: the [`submitter::Submitter`] trait and
//!   the non-production [`submitter::StubSubmitter`].

pub mod config;
pub mod grant;
pub mod keyring;
pub mod keyring_edit;
pub mod operator;
pub mod pool;
pub mod quote;
pub mod replenish;
pub mod submitter;
pub mod utxo;
