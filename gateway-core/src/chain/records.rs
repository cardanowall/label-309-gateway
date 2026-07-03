//! The single writer of `cw_core.chain_records` and its verified-signer set.
//!
//! `chain_records` is the issuer-agnostic on-chain PoE index, and it has exactly
//! one mutation path: this module. Every statement that writes the table — and
//! its `cw_core.chain_record_signer` verified-signer set — lives here, behind one
//! column-derivation function ([`derive_chain_record_columns`]), and two
//! producers feed it:
//!
//! - The **confirm loop's threshold-flip** enqueues an [`INDEX_TX_QUEUE`] job
//!   carrying the transaction's hash, its block coordinates, and the metadata
//!   source; the single-writer loop ([`IndexTxHandler`]) drains the queue,
//!   derives the columns, and inserts `ON CONFLICT (tx_hash) DO UPDATE` that
//!   re-pins the block coordinates when the same transaction is re-observed at a
//!   new height, and is a no-op at the same height.
//! - The **forward scan** calls this module's [`insert_chain_record_in_tx`]
//!   helper directly inside its own atomic iteration transaction, so the reorg
//!   delete, the record insert, and the cursor advance all commit in lockstep
//!   (a job hop would split that atomicity). That path inserts `ON CONFLICT
//!   (tx_hash) DO UPDATE` that re-pins the block coordinates on a new-height
//!   re-observation and backfills the nullable `tx_cbor` enrichment, never the
//!   identity columns.
//!
//! Routing every statement through this one module is what keeps the derived
//! columns consistent regardless of which producer observed the transaction
//! first: the derivation is one function, and the conflict clauses make a second
//! observation of the same transaction converge (re-pinning a re-included
//! transaction to its new height) rather than fork or serve a stale height. An
//! architecture test asserts no other module references `chain_records` (or its
//! `chain_record_signer` set) in SQL.
//!
//! # The verified-signer set
//!
//! `chain_records.signer_ed25519` holds the FIRST verified signer of a record
//! (the primary, projected column). `cw_core.chain_record_signer` holds one row
//! per VERIFIED signer, so the public `?signer=` filter discovers a record by ANY
//! of its verified signers, not only the first. It is written here too, in the
//! same insert path and from the same single verification pass, so the set and
//! the primary column can never disagree about who verified. The foreign key to
//! `chain_records(tx_hash)` is `ON DELETE CASCADE`, so a reorg that deletes a
//! rich row drops its signer rows in lockstep with no separate statement.
//!
//! # The thin record anchor
//!
//! `cw_core.chain_records.tx_hash` foreign-keys the stable `cw_api.records`
//! anchor (a thin `{tx_hash, indexed_at}` row a vendor may reference instead of
//! the rich, evolving `chain_records` columns). The anchor must exist before the
//! rich row, so every insert here writes the anchor row in the SAME statement as
//! the rich row, via a CTE that inserts `cw_api.records ON CONFLICT DO NOTHING`
//! first. This module is therefore also the single writer of `cw_api.records`,
//! and the same architecture test asserts no other module names it in SQL: the
//! anchor and its rich row are created together, atomically, by this one path.
//!
//! # Derived columns
//!
//! [`ChainRecordColumns`] is the verified contract: `signer_ed25519` is the raw
//! Ed25519 public key of the first record signer whose signature
//! CRYPTOGRAPHICALLY VERIFIES over the record body under the carrying
//! transaction's network (a record whose signature entries all fail
//! verification indexes as unsigned), `item_count` is the number of content
//! items, and `scheme` is the encryption scheme of the first item (0 open, 1
//! recipient-sealed, 2 passphrase). The signer column feeds the public feed's
//! publisher filters and counts, so it must never carry a key a forged entry
//! merely names — only one that actually signed. No per-recipient value is ever
//! derived or stored: the index is zero-knowledge about a sealed record's
//! recipients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::runtime::{JobContext, JobHandler, JobOutcome};
use crate::Result;

/// The queue the single chain-records writer consumes.
pub const INDEX_TX_QUEUE: &str = "index_tx";

/// The standard policy for the index-tx queue: a worker-pool queue with a small
/// attempt budget and a fixed backoff. The insert converges on conflict (a
/// same-height redelivery is a no-op, a new-height re-inclusion re-pins the
/// coordinates), so a redelivery is harmless, and the work is a single
/// derive-and-insert, so a short lease reclaims promptly.
#[must_use]
pub fn index_tx_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::standard(
        INDEX_TX_QUEUE,
        5,
        crate::runtime::Backoff::Fixed { base_secs: 20 },
        120,
        1,
    )
}

/// Where the writer obtains the record's metadata CBOR for a job.
///
/// The threshold-flip already holds the record bytes it submitted, so it passes
/// them inline; the forward scan passes the bytes it decoded from the block. A
/// future source that knows only the hash can ask the writer to fetch the CBOR
/// from chain, kept as a distinct variant so the inline fast path never makes a
/// network call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetadataSource {
    /// The Label 309 metadata CBOR is carried inline in the job payload.
    Inline {
        /// The verbatim metadata CBOR bytes.
        #[serde(with = "crate::chain::records::hex_bytes")]
        metadata_cbor: Vec<u8>,
    },
    /// The writer must fetch the transaction's CBOR from chain by its hash.
    FetchByHash,
}

/// The payload of an [`INDEX_TX_QUEUE`] job: one transaction to index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexTxJob {
    /// 32-byte transaction id, hex-encoded.
    pub tx_hash: String,
    /// The block height the transaction landed in.
    pub block_height: u64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
    /// Where to obtain the metadata CBOR.
    pub metadata: MetadataSource,
}

/// The indexed columns derived from a validated Label 309 record.
///
/// This is the verified contract every writer produces, so two sources observing
/// the same transaction insert identical values: the derivation is pure over the
/// record bytes and the carrying network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecordColumns {
    /// The raw 32-byte Ed25519 public key of the first signer whose record-level
    /// signature verifies, or `None` when the record carries no signatures or
    /// none of its signature entries verify. The primary, projected signer: the
    /// record resource surfaces it as `signer_ed25519`. Never a merely-claimed
    /// key — a forged entry naming someone else's key must not surface as a
    /// signer — because it is the first member of [`Self::verified_signers`],
    /// which holds only verified keys.
    pub signer_ed25519: Option<[u8; 32]>,
    /// EVERY verified signer's raw 32-byte Ed25519 public key, in `sigs[]` order
    /// with duplicates removed: the complete set of keys whose record-level
    /// signatures cryptographically verify. The signer-set side table is
    /// populated from this, so the public `?signer=` filter discovers a record by
    /// ANY of its verified signers, not only the first. Empty for an unsigned
    /// record or one whose every signature entry fails verification. By
    /// construction `signer_ed25519 == verified_signers.first().copied()`: both
    /// come from the same single verification pass, so a forged entry can never
    /// enter either.
    pub verified_signers: Vec<[u8; 32]>,
    /// The number of content items in the record.
    pub item_count: u32,
    /// The encryption scheme of the first item (0 open, 1 sealed, 2 passphrase).
    pub scheme: u8,
}

/// The encryption-scheme value a content item with no sealed envelope indexes
/// as: an open (plaintext) record.
const SCHEME_OPEN: u8 = 0;

/// The scheme value of a sealed item whose envelope carries recipient slots —
/// and of any sealed envelope this build cannot read further (the validator's
/// opaque arm), so an unsupported-suite sealed item is never hidden from
/// sealed-record scans.
const SCHEME_SEALED: u8 = 1;

/// The scheme value of a sealed item whose envelope carries a passphrase block.
const SCHEME_PASSPHRASE: u8 = 2;

/// Derive the indexed columns from a record's metadata CBOR, against the
/// network of the transaction that carries it.
///
/// Validates the bytes as a Label 309 record under the public reading (an
/// envelope under unsupported identifiers degrades to opaque and stays
/// indexable — the global feed must not drop records a public verifier
/// accepts), then derives the VERIFIED signer set (see
/// `verified_signers_ed25519`) — whose first member is the primary projected
/// signer — the item count, and the first item's encryption scheme. `network`
/// is the chain this gateway instance serves; its
/// CIP-19 class selects the header byte wallet-path signatures bind their stake
/// address against. The instance is single-network, so every caller threads its
/// configured network here. Returns an error when the bytes are not a
/// structurally valid record, so a malformed transaction is skipped rather
/// than indexed with fabricated columns.
pub fn derive_chain_record_columns(
    metadata_cbor: &[u8],
    network: crate::chain::params::Network,
) -> Result<ChainRecordColumns> {
    let options = cardanowall::poe_standard::ValidatorOptions::default();
    let record = match cardanowall::poe_standard::validate_poe_record(metadata_cbor, &options) {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => record,
        cardanowall::poe_standard::ValidateResult::Fail { issues } => {
            let codes: Vec<String> = issues.iter().map(|i| format!("{:?}", i.code)).collect();
            return Err(crate::Error::Config(format!(
                "transaction metadata is not a valid Label 309 record: {}",
                codes.join(", ")
            )));
        }
    };

    let items = record.items.as_deref().unwrap_or(&[]);
    let item_count = u32::try_from(items.len())
        .map_err(|_| crate::Error::Config("item count overflow".into()))?;

    // One verification pass yields the whole verified set; the primary projected
    // signer is its first member, so the rich row's `signer_ed25519` and the
    // signer-set side table can never disagree about who verified.
    let verified_signers = verified_signers_ed25519(&record, network.verifier_network());
    Ok(ChainRecordColumns {
        signer_ed25519: verified_signers.first().copied(),
        verified_signers,
        item_count,
        scheme: scheme_of_first_item(items),
    })
}

/// The encryption-scheme projection of the first content item, as the `scheme`
/// column stores it: `0` open (no envelope), `1` recipient-sealed (the envelope
/// carries recipient slots), `2` passphrase-sealed (the envelope carries a
/// passphrase block).
///
/// The wire's `enc.scheme` field does not discriminate the two sealed paths —
/// both carry `scheme: 1` on the wire, distinguished by which key-recovery
/// block is present — so the projection reads the envelope's shape. An envelope
/// under identifiers this build cannot read (the validator's opaque arm) indexes
/// as the generic sealed value `1`: it is still a sealed item, and indexing it
/// as open would hide it from sealed-record scans (`sealed=true` / `scheme=1`).
/// This is the single scheme derivation; the publish-response projection
/// consumes it too, so the indexed column and the wire response always agree.
pub(crate) fn scheme_of_first_item(items: &[cardanowall::poe_standard::ItemEntry]) -> u8 {
    use cardanowall::poe_standard::EncryptionEnvelope;
    match items.first().and_then(|item| item.enc.as_ref()) {
        None => SCHEME_OPEN,
        Some(EncryptionEnvelope::Scheme1(env)) if env.passphrase.is_some() => SCHEME_PASSPHRASE,
        Some(_) => SCHEME_SEALED,
    }
}

/// Resolve the raw Ed25519 public keys of EVERY record signer whose signature
/// cryptographically verifies, in `sigs[]` order with duplicates removed, or an
/// empty vec when the record carries no signatures or none of its entries
/// verify. The first member is the primary projected signer.
///
/// The signer set is the queryable claim — "this key signed this record" — that
/// the public feed's publisher filter and count are built on, so it must hold
/// only keys that actually verified. A structurally well-formed `sigs[]` entry
/// can name ANY key (a valid-shaped `cose_key` sidecar or protected-header
/// `kid`); resolving a key without verifying the signature would let a forged
/// entry plant an arbitrary key into another publisher's feed. Verification is
/// the canonical verifier's: strict Ed25519 over the domain-prefixed canonical
/// record body, with wallet-path (path-2) entries additionally bound to their
/// CIP-19 stake address under the carrying transaction's `network`. The set is
/// derived in entry order and deduplicated, so it is deterministic across
/// re-observations (and a record that signs twice under one key contributes one
/// membership row, matching the side table's `(signer, tx_hash)` key).
///
/// This is the ONE verification pass: the caller takes the first member as the
/// primary signer and the whole vec as the side-table set, so a record is never
/// verified twice.
///
/// Unsigned records return immediately with an empty vec: the scan path verifies
/// signatures only for records that already passed structural validation AND
/// carry entries, so the common unsigned record costs no body re-encode and no
/// curve math.
fn verified_signers_ed25519(
    record: &cardanowall::poe_standard::PoeRecord,
    network: cardanowall::verifier::types::CardanoNetwork,
) -> Vec<[u8; 32]> {
    if record.sigs.as_deref().is_none_or(<[_]>::is_empty) {
        return Vec::new();
    }
    let mut signers: Vec<[u8; 32]> = Vec::new();
    for check in cardanowall::verifier::verify_record_signatures(record, network) {
        if !check.valid {
            continue;
        }
        let Some(hex_key) = check.signer_pub else {
            continue;
        };
        let Some(key) = hex::decode(hex_key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        else {
            continue;
        };
        // De-dup in entry order: two verifying entries under the same key (or the
        // same key reached by both COSE paths) are one membership, matching the
        // side table's (signer_ed25519, tx_hash) primary key.
        if !signers.contains(&key) {
            signers.push(key);
        }
    }
    signers
}

/// Insert one indexed record (with its verified-signer set and thin
/// `cw_api.records` anchor), re-pinning its block coordinates when a re-fired
/// index job reports the transaction at a new height.
///
/// One of the two entry points into the sole write path; the confirm
/// threshold-flip's writer loop and the conformance harness use it (the forward
/// scan uses [`insert_chain_record_in_tx`] so its insert rides the scan's own
/// transaction). It opens its own transaction and delegates to
/// [`insert_chain_record_in_tx`] so the rich row, its anchor, and its signer-set
/// rows all commit together; there is no separate SQL here to keep in sync.
///
/// Returns `true` when this call inserted a new rich row or re-pinned an existing
/// one's coordinates, and `false` when a same-height re-observation folded into a
/// no-op. (The signer-set fan-out is idempotent and does not affect this flag,
/// which tracks the rich row exactly as before.)
pub async fn insert_chain_record(
    pool: &sqlx::PgPool,
    tx_hash: [u8; 32],
    block_height: u64,
    block_time: DateTime<Utc>,
    metadata_cbor: &[u8],
    columns: &ChainRecordColumns,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    // The pool-less entry point carries no full transaction CBOR (the confirm
    // threshold-flip and the conformance stub both have only the record bytes);
    // the backfill pass fills `tx_cbor` later.
    let inserted = insert_chain_record_in_tx(
        &mut tx,
        tx_hash,
        block_height,
        block_time,
        metadata_cbor,
        None,
        columns,
    )
    .await?;
    tx.commit().await?;
    Ok(inserted)
}

/// Insert one scanned record inside a caller-supplied transaction, re-pinning its
/// block coordinates on a new-height re-observation and preserving any transaction
/// CBOR already on the row.
///
/// The forward scan's single write transaction calls this for every record it
/// promotes, and [`insert_chain_record`] calls it inside a transaction it opens.
/// It takes the caller's connection by mutable reference (so it can issue more
/// than one statement on it) and rides that connection's transaction, keeping the
/// rich row, its anchor, the signer-set rows, the reorg delete, the pool
/// mutations, and the cursor advance all in one atomic commit.
///
/// It issues two statements on the connection:
///
/// 1. The rich `chain_records` row and its `cw_api.records` anchor, in one CTE.
/// 2. The verified-signer fan-out into `chain_record_signer`, one row per key in
///    `columns.verified_signers`. An unsigned record has an empty set and writes
///    no signer rows. The fan-out's height is re-pinned on a re-inclusion exactly
///    as the rich row's coordinates are, so the denormalized height never drifts.
///    The rich row is written first so the side rows' foreign key resolves.
///
/// On conflict the rich-row statement does two independent things:
///
/// - **Re-pin the coordinates:** set `block_height`/`block_time` from the new
///   observation. A reorg that crosses the scan's rewind boundary deletes the
///   stale row first, so the fresh insert records the new height; but a re-scan
///   that re-discovers a transaction re-included at a new height *without*
///   crossing the rewind boundary would otherwise leave the row pinned to the old
///   height. Updating the coordinates on conflict closes that same-tx, new-height
///   gap so the index never serves a stale height.
/// - **Backfill `tx_cbor`:** the forward scan may insert a record with a NULL
///   `tx_cbor` (the heavier full-transaction fetch had not resolved yet) that a
///   later backfill fills in; a second observation that arrives with the bytes
///   adds them only when the row is still missing them
///   (`COALESCE(existing, excluded)`), never clobbering bytes already stored.
///
/// The identity columns (`metadata_cbor`, `signer_ed25519`, `item_count`,
/// `scheme`) are derived from the transaction's own bytes and are never touched
/// on conflict. Returns `true` when this call inserted a new rich row or updated
/// an existing one (a coordinate re-pin or a CBOR backfill), `false` when the
/// rich-row conflict folded into a no-op (same height, CBOR already present); the
/// idempotent signer-set fan-out does not affect this flag.
///
/// The rich row's leading CTE inserts the thin `cw_api.records` anchor (`ON
/// CONFLICT DO NOTHING`) in the same statement, so the rich row's foreign key
/// resolves and the anchor rides the same write transaction as the signer-set
/// fan-out, the reorg delete, and the cursor advance.
pub async fn insert_chain_record_in_tx(
    conn: &mut sqlx::PgConnection,
    tx_hash: [u8; 32],
    block_height: u64,
    block_time: DateTime<Utc>,
    metadata_cbor: &[u8],
    tx_cbor: Option<&[u8]>,
    columns: &ChainRecordColumns,
) -> Result<bool> {
    let block_height = i64::try_from(block_height)
        .map_err(|_| crate::Error::Config("block height overflow".into()))?;
    let item_count = i32::try_from(columns.item_count)
        .map_err(|_| crate::Error::Config("item count overflow".into()))?;
    let affected = sqlx::query(
        "WITH anchor AS ( \
           INSERT INTO cw_api.records (tx_hash) VALUES ($1) ON CONFLICT (tx_hash) DO NOTHING \
         ) \
         INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, tx_cbor, signer_ed25519, item_count, scheme) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (tx_hash) DO UPDATE SET \
           block_height = EXCLUDED.block_height, \
           block_time = EXCLUDED.block_time, \
           tx_cbor = COALESCE(cw_core.chain_records.tx_cbor, EXCLUDED.tx_cbor) \
         WHERE EXCLUDED.block_height IS DISTINCT FROM cw_core.chain_records.block_height \
            OR (cw_core.chain_records.tx_cbor IS NULL AND EXCLUDED.tx_cbor IS NOT NULL)",
    )
    .bind(tx_hash.as_slice())
    .bind(block_height)
    .bind(block_time)
    .bind(metadata_cbor)
    .bind(tx_cbor)
    .bind(columns.signer_ed25519.as_ref().map(<[u8; 32]>::as_slice))
    .bind(item_count)
    .bind(i16::from(columns.scheme))
    .execute(&mut *conn)
    .await?
    .rows_affected();

    upsert_signer_set_in_tx(conn, tx_hash, block_height, &columns.verified_signers).await?;

    Ok(affected == 1)
}

/// Fan the record's verified-signer set into `cw_core.chain_record_signer`, one
/// row per key, re-pinning the denormalized height on a re-inclusion exactly as
/// the rich row's coordinates are re-pinned.
///
/// Runs on the same connection (and therefore the same transaction) as the rich
/// row, immediately after it, so the side rows' foreign key to
/// `chain_records(tx_hash)` always resolves. An empty set (an unsigned record, or
/// one whose every signature failed verification) writes no rows: `unnest` over
/// an empty array yields no rows, so the statement is a clean no-op.
///
/// `ON CONFLICT (signer_ed25519, tx_hash) DO UPDATE ... WHERE block_height IS
/// DISTINCT FROM` mirrors the rich row: the membership identity is immutable, and
/// only the denormalized height moves, and only on an actual change, so a
/// same-height re-observation is a true no-op. Membership rows are never deleted
/// here; a reorg that removes the rich row cascades its signer rows away through
/// the foreign key.
async fn upsert_signer_set_in_tx(
    conn: &mut sqlx::PgConnection,
    tx_hash: [u8; 32],
    block_height: i64,
    verified_signers: &[[u8; 32]],
) -> Result<()> {
    if verified_signers.is_empty() {
        return Ok(());
    }
    // Bind the set as a bytea[] and fan it out with unnest, so the whole set is
    // one round trip regardless of how many keys co-signed.
    let signer_bytes: Vec<&[u8]> = verified_signers.iter().map(<[u8; 32]>::as_slice).collect();
    sqlx::query(
        "INSERT INTO cw_core.chain_record_signer (signer_ed25519, tx_hash, block_height) \
         SELECT sig, $2, $3 FROM unnest($1::bytea[]) AS u(sig) \
         ON CONFLICT (signer_ed25519, tx_hash) DO UPDATE SET \
           block_height = EXCLUDED.block_height \
         WHERE EXCLUDED.block_height IS DISTINCT FROM cw_core.chain_record_signer.block_height",
    )
    .bind(signer_bytes.as_slice())
    .bind(tx_hash.as_slice())
    .bind(block_height)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Delete every scanned record above a reorg rewind boundary inside a
/// caller-supplied transaction.
///
/// When the forward scan detects a reorg it rewinds the cursor and discards every
/// `chain_records` row strictly above the rewind height, because those rows sat
/// on the now-invalidated branch. The re-scan from the rewound cursor re-discovers
/// whatever survived on the valid branch and re-inserts it at its true height.
/// Runs in the scan's write transaction so the delete, the cursor rewind, and the
/// pool purge commit together. Returns how many rows were deleted.
pub async fn reorg_delete_above_in_tx<'e, E>(executor: E, rewind_from: u64) -> Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    let rewind_from = i64::try_from(rewind_from)
        .map_err(|_| crate::Error::Config("rewind height overflow".into()))?;
    let affected = sqlx::query("DELETE FROM cw_core.chain_records WHERE block_height > $1")
        .bind(rewind_from)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(affected)
}

/// Delete the single indexed record for a reorged-out transaction, by its hash,
/// inside a caller-supplied transaction.
///
/// When the confirm authority abandons an attempt whose transaction was already
/// indexed (a confirmed transaction lost to a settlement-deep conflicting spend),
/// the index must stop serving a transaction that no longer exists on the
/// canonical chain. This is the targeted, single-transaction counterpart to the
/// scan's height-bounded [`reorg_delete_above_in_tx`]: it removes exactly the one
/// row a known-dead transaction hash carries, so the abandon and the index purge
/// commit together. The thin `cw_api.records` anchor is left as the historical
/// reference. Returns how many rows were deleted (zero when the transaction was
/// never indexed). Stays in this module so `chain_records` is named in SQL only
/// here, preserving the single-writer invariant.
pub async fn delete_chain_record_by_tx_hash<'e, E>(executor: E, tx_hash: [u8; 32]) -> Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    let affected = sqlx::query("DELETE FROM cw_core.chain_records WHERE tx_hash = $1")
        .bind(tx_hash.as_slice())
        .execute(executor)
        .await?
        .rows_affected();
    Ok(affected)
}

/// Backfill the full transaction CBOR onto a scanned record, only when the row
/// still has none.
///
/// The bounded backfill pass repairs rows the forward scan inserted with a NULL
/// `tx_cbor`. The `tx_cbor IS NULL` guard makes the update lose any race against a
/// concurrent forward-scan insert that already filled the column, so the bytes a
/// row carries are never overwritten. Returns `true` when this call wrote the
/// bytes, `false` when the row was already filled or no longer exists.
pub async fn update_tx_cbor_backfill(
    pool: &sqlx::PgPool,
    tx_hash: [u8; 32],
    tx_cbor: &[u8],
) -> Result<bool> {
    let affected = sqlx::query(
        "UPDATE cw_core.chain_records SET tx_cbor = $2 WHERE tx_hash = $1 AND tx_cbor IS NULL",
    )
    .bind(tx_hash.as_slice())
    .bind(tx_cbor)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// Whether `chain_records` holds at least one row.
///
/// A read against the index, kept here so this module remains the sole place that
/// names `chain_records` in SQL (the single-path invariant the architecture test
/// enforces). The forward scan's startup self-heal uses it to detect a dropped
/// index left behind an advanced cursor.
pub async fn any_chain_record_exists(pool: &sqlx::PgPool) -> Result<bool> {
    // EXISTS yields a single boolean row, so the result type is unambiguous: a
    // bare `SELECT 1` returns an INT4 literal that a wider integer decode would
    // reject when a row is present.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cw_core.chain_records)")
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

/// One anchored record from the index: the public, issuer-agnostic columns only.
///
/// The on-chain index is zero-knowledge about who published a record, so this read
/// shape carries no tenancy at all. A caller that wants the owner-only projection
/// resolves ownership separately, against its own publishing state, and never asks
/// the index for it. This struct and the queries that produce it live in the index's
/// single SQL owner.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IndexedRecordRow {
    /// 32-byte transaction id.
    pub tx_hash: Vec<u8>,
    /// The block height the transaction landed in.
    pub block_height: i64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
    /// The verbatim Label 309 metadata CBOR.
    pub metadata_cbor: Vec<u8>,
    /// The first verified signer's raw Ed25519 public key, or `None` when the
    /// record is unsigned or no signature entry verified.
    pub signer_ed25519: Option<Vec<u8>>,
    /// The number of content items.
    pub item_count: i32,
    /// The encryption scheme of the first item (0 open, 1 sealed, 2 passphrase).
    pub scheme: i16,
}

/// The additive narrowing filters a records-list read may apply.
///
/// Every field is optional; an unset field is a `NULL` bind that disables its
/// predicate, so a default (all-`None`) filter selects the whole anchored set
/// exactly as the unfiltered list did. The predicates are backed by the existing
/// access paths: `sealed_only` and `scheme` ride the scheme partial / scan index,
/// and the block/time bounds ride the block-coordinate indexes. When `signer` is
/// set the read DRIVES FROM the verified-signer set (riding its `(signer_ed25519,
/// block_height DESC)` index for both membership and newest-first ordering) and
/// joins back for the projection; a record is matched by ANY of its verified
/// signers. Composing several filters intersects them (every set predicate must
/// hold).
#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    /// Back-compat coarse sealed filter: when true, drop open (scheme 0) records.
    /// Independent of [`Self::scheme`]; when both are set, both must hold.
    pub sealed_only: bool,
    /// Exact encryption scheme of the first item (`0` open, `1` sealed, `2`
    /// passphrase). Precise counterpart to the coarse `sealed_only`.
    pub scheme: Option<i16>,
    /// A verified signer's raw Ed25519 public key (32 bytes): list every record
    /// this key verifiably signed, whether or not it was the record's first
    /// signer. Matched against the verified-signer set, so a co-signed or
    /// non-first-ordered record is found.
    pub signer: Option<Vec<u8>>,
    /// Inclusive lower bound on block height.
    pub from_block: Option<i64>,
    /// Inclusive upper bound on block height.
    pub to_block: Option<i64>,
    /// Inclusive lower bound on block time.
    pub from_time: Option<DateTime<Utc>>,
    /// Inclusive upper bound on block time.
    pub to_time: Option<DateTime<Utc>>,
}

/// The per-statement wall-clock cap on the public records reads, in
/// milliseconds.
///
/// Every read on the anonymous surface (list page, count, single-record get)
/// runs under it via [`begin_records_read_txn`]. A healthy indexed read returns
/// in milliseconds, so five seconds only ever trips on a pathological plan (a
/// filter the planner could not drive from an index degrading to a wide scan)
/// or a degraded database — both cases where killing the statement and freeing
/// the backend beats letting an anonymous caller pin it.
const RECORDS_READ_STATEMENT_TIMEOUT_MS: u32 = 5_000;

/// Open the bounded read transaction every public records read runs in.
///
/// `SET LOCAL statement_timeout` scopes the cap to this transaction alone: the
/// connection's default is restored when the transaction ends (commit, or the
/// rollback a timeout forces), so the pool never leaks a lowered timeout into an
/// unrelated query. A timeout surfaces as a query error the API layer maps to a
/// 503 — never a wrong (partial) result. This is the anonymous surface's
/// backstop: the read is reachable with no credential, so its worst-case cost
/// must be bounded by the server, not by the caller's goodwill.
pub async fn begin_records_read_txn(
    pool: &sqlx::PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    // `SET` takes no bind parameters, so the cap is interpolated; it is a
    // compile-time integer constant, which is what the safety assertion states.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET LOCAL statement_timeout = {RECORDS_READ_STATEMENT_TIMEOUT_MS}"
    )))
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

/// Fetch a page of anchored records, newest-first, after an optional cursor.
///
/// Walks `(block_height DESC, tx_hash DESC)`. `after` is the last row of the
/// previous page; the next page is everything strictly before it. `filter` applies
/// the additive narrowing predicates ([`RecordFilter`]); a default filter selects
/// the whole anchored set. The page is the public anchored set regardless of who
/// reads it; the index reveals no tenancy. The read names `chain_records`, so it
/// lives in the index's single SQL owner. It runs in the bounded read
/// transaction ([`begin_records_read_txn`]), so a filter whose plan degrades to
/// a wide scan is killed at the statement timeout instead of pinning a backend
/// for an anonymous caller.
///
/// Two driving shapes, chosen by whether a `signer` is set, so each rides the
/// access path that bounds its cost:
///
/// - **Unfiltered (no signer):** drive from `chain_records cr`, ordered by
///   `(cr.block_height DESC, cr.tx_hash DESC)`, served by the block-coordinate
///   index. The scheme / sealed / block / time predicates are each `($n IS NULL OR
///   ...)`, so an unset field binds NULL and disables its clause.
/// - **Signer-filtered:** DRIVE FROM `chain_record_signer s` with a hard
///   `s.signer_ed25519 = $n` equality and order by `(s.block_height DESC,
///   s.tx_hash DESC)`, so both the membership lookup AND the newest-first ordering
///   ride `chain_record_signer_signer_idx` and read only that one key's slice —
///   never a `chain_records` scan with a membership filter, which would be
///   O(table). This is why `block_height` is denormalized onto the set. The join
///   back to `chain_records` (by its primary key) supplies the projection columns
///   and carries the same optional scheme / sealed / block / time narrowing. A
///   record is matched by ANY of its verified signers, not just the first.
///
/// The opaque keyset cursor is byte-identical across both shapes: `s.block_height`
/// equals `cr.block_height` (denormalized and re-pinned together) and the tx_hash
/// is the same row id, so a cursor minted on one shape decodes and applies on the
/// other unchanged.
pub async fn fetch_record_page(
    pool: &sqlx::PgPool,
    after: Option<(i64, &[u8])>,
    limit: i64,
    filter: &RecordFilter,
) -> Result<Vec<IndexedRecordRow>> {
    // The coarse `sealed_only` and the precise `scheme` are independent: both must
    // hold when both are set. Both driving shapes carry the identical narrowing
    // predicates; they differ only in the driving table, the keyset column source,
    // and the ORDER BY — but the keyset tuple `(block_height, tx_hash)` is the same
    // values either way, so the cursor stays byte-identical.
    let mut tx = begin_records_read_txn(pool).await?;
    let rows = match (filter.signer.as_deref(), after) {
        // -------------------------------------------------------------------
        // Signer-filtered: drive from the verified-signer set so the membership
        // lookup and the newest-first ordering both ride chain_record_signer_signer_idx.
        // -------------------------------------------------------------------
        // Cursored page: $1 signer, $2/$3 keyset boundary, $4..$9 narrowing, $10 limit.
        (Some(signer), Some((block_height, tx_hash))) => {
            sqlx::query_as::<_, IndexedRecordRow>(
                "SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_record_signer s \
                 JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
                 WHERE s.signer_ed25519 = $1 \
                   AND (s.block_height, s.tx_hash) < ($2, $3) \
                   AND ($4 = false OR cr.scheme <> 0) \
                   AND ($5::smallint IS NULL OR cr.scheme = $5) \
                   AND ($6::bigint IS NULL OR cr.block_height >= $6) \
                   AND ($7::bigint IS NULL OR cr.block_height <= $7) \
                   AND ($8::timestamptz IS NULL OR cr.block_time >= $8) \
                   AND ($9::timestamptz IS NULL OR cr.block_time <= $9) \
                 ORDER BY s.block_height DESC, s.tx_hash DESC LIMIT $10",
            )
            .bind(signer)
            .bind(block_height)
            .bind(tx_hash)
            .bind(filter.sealed_only)
            .bind(filter.scheme)
            .bind(filter.from_block)
            .bind(filter.to_block)
            .bind(filter.from_time)
            .bind(filter.to_time)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        }
        // First page: $1 signer, $2..$7 narrowing, $8 limit.
        (Some(signer), None) => {
            sqlx::query_as::<_, IndexedRecordRow>(
                "SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_record_signer s \
                 JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
                 WHERE s.signer_ed25519 = $1 \
                   AND ($2 = false OR cr.scheme <> 0) \
                   AND ($3::smallint IS NULL OR cr.scheme = $3) \
                   AND ($4::bigint IS NULL OR cr.block_height >= $4) \
                   AND ($5::bigint IS NULL OR cr.block_height <= $5) \
                   AND ($6::timestamptz IS NULL OR cr.block_time >= $6) \
                   AND ($7::timestamptz IS NULL OR cr.block_time <= $7) \
                 ORDER BY s.block_height DESC, s.tx_hash DESC LIMIT $8",
            )
            .bind(signer)
            .bind(filter.sealed_only)
            .bind(filter.scheme)
            .bind(filter.from_block)
            .bind(filter.to_block)
            .bind(filter.from_time)
            .bind(filter.to_time)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        }
        // -------------------------------------------------------------------
        // Unfiltered: drive from chain_records on the block-coordinate index.
        // -------------------------------------------------------------------
        // Cursored page: $1/$2 keyset boundary, $3..$8 narrowing, $9 limit.
        (None, Some((block_height, tx_hash))) => {
            sqlx::query_as::<_, IndexedRecordRow>(
                "SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_records cr \
                 WHERE (cr.block_height, cr.tx_hash) < ($1, $2) \
                   AND ($3 = false OR cr.scheme <> 0) \
                   AND ($4::smallint IS NULL OR cr.scheme = $4) \
                   AND ($5::bigint IS NULL OR cr.block_height >= $5) \
                   AND ($6::bigint IS NULL OR cr.block_height <= $6) \
                   AND ($7::timestamptz IS NULL OR cr.block_time >= $7) \
                   AND ($8::timestamptz IS NULL OR cr.block_time <= $8) \
                 ORDER BY cr.block_height DESC, cr.tx_hash DESC LIMIT $9",
            )
            .bind(block_height)
            .bind(tx_hash)
            .bind(filter.sealed_only)
            .bind(filter.scheme)
            .bind(filter.from_block)
            .bind(filter.to_block)
            .bind(filter.from_time)
            .bind(filter.to_time)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        }
        // First page: $1..$6 narrowing, $7 limit.
        (None, None) => {
            sqlx::query_as::<_, IndexedRecordRow>(
                "SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_records cr \
                 WHERE ($1 = false OR cr.scheme <> 0) \
                   AND ($2::smallint IS NULL OR cr.scheme = $2) \
                   AND ($3::bigint IS NULL OR cr.block_height >= $3) \
                   AND ($4::bigint IS NULL OR cr.block_height <= $4) \
                   AND ($5::timestamptz IS NULL OR cr.block_time >= $5) \
                   AND ($6::timestamptz IS NULL OR cr.block_time <= $6) \
                 ORDER BY cr.block_height DESC, cr.tx_hash DESC LIMIT $7",
            )
            .bind(filter.sealed_only)
            .bind(filter.scheme)
            .bind(filter.from_block)
            .bind(filter.to_block)
            .bind(filter.from_time)
            .bind(filter.to_time)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        }
    };
    tx.commit().await?;
    Ok(rows)
}

/// A records count is ALWAYS scoped to one publisher's key, plus optional
/// additional narrowing.
///
/// A count's cost is the cardinality of the matching set, and only the publisher
/// scope bounds that cardinality (one key's lifetime output), so the signer is a
/// REQUIRED field here, not an optional filter. This is the structural counterpart
/// to the API rule that rejects an unscoped count: the type cannot express one. The
/// remaining fields are optional narrowing applied on top of the already-bounded
/// signer set, mirroring the list route's filters.
#[derive(Debug, Clone)]
pub struct CountFilter {
    /// A verified signer's raw 32-byte Ed25519 public key. Required: the count is
    /// the total of every record this key verifiably signed (first or not),
    /// matching the list route's `?signer=` filter.
    pub signer: Vec<u8>,
    /// Back-compat coarse sealed filter: when true, drop open (scheme 0) records.
    pub sealed_only: bool,
    /// Exact encryption scheme of the first item (`0` open, `1` sealed, `2`
    /// passphrase).
    pub scheme: Option<i16>,
    /// Inclusive lower bound on block height.
    pub from_block: Option<i64>,
    /// Inclusive upper bound on block height.
    pub to_block: Option<i64>,
    /// Inclusive lower bound on block time.
    pub from_time: Option<DateTime<Utc>>,
    /// Inclusive upper bound on block time.
    pub to_time: Option<DateTime<Utc>>,
}

/// Count the anchored records a publisher signed (optionally narrowed further).
///
/// The counting counterpart to [`fetch_record_page`]: the cursor-paginated page
/// never returns a total, so a caller that needs "how many records did this
/// publisher anchor" (a public profile's proof count, an explorer's facet) asks
/// here. The count is over the verified-signer set, so it counts every record
/// this key signed — first or not — matching the list route's `?signer=` filter.
/// The signer is a REQUIRED equality predicate (`s.signer_ed25519 = $1`) against
/// `chain_record_signer`, not an optional NULL-guarded clause: that guarantees
/// the planner always derives a selective `Index Cond` on
/// `chain_record_signer_signer_idx` and reads only that one key's slice, under any
/// plan (generic or custom). The set's `(signer_ed25519, tx_hash)` primary key
/// means each matching record is counted exactly once even when the key co-signed
/// with others. The join back to `chain_records` (by primary key) carries the
/// optional scheme / sealed / block / time narrowing; each is `($n IS NULL OR
/// ...)`, so an unset one binds `NULL` and disables its clause.
///
/// Defense in depth: the count runs in the bounded read transaction
/// ([`begin_records_read_txn`]), so even a pathological scope (or a missing
/// index after a schema mistake) cannot tie up a connection indefinitely. A
/// timeout surfaces as a query error the caller maps to a 503, never a wrong
/// (partial) count.
pub async fn count_records(pool: &sqlx::PgPool, filter: &CountFilter) -> Result<u64> {
    let mut tx = begin_records_read_txn(pool).await?;
    let count: i64 = sqlx::query_scalar(
        // The signer is a hard equality ($1) against the verified-signer set, so the
        // planner always gets a selective Index Cond on chain_record_signer_signer_idx
        // and reads only that one key's slice; the join back to chain_records (by its
        // primary key) carries the rest as optional NULL-guards. The set's
        // (signer_ed25519, tx_hash) primary key counts each record once even when the
        // key co-signed.
        "SELECT count(*) \
         FROM cw_core.chain_record_signer s \
         JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
         WHERE s.signer_ed25519 = $1 \
           AND ($2 = false OR cr.scheme <> 0) \
           AND ($3::smallint IS NULL OR cr.scheme = $3) \
           AND ($4::bigint IS NULL OR cr.block_height >= $4) \
           AND ($5::bigint IS NULL OR cr.block_height <= $5) \
           AND ($6::timestamptz IS NULL OR cr.block_time >= $6) \
           AND ($7::timestamptz IS NULL OR cr.block_time <= $7)",
    )
    .bind(filter.signer.as_slice())
    .bind(filter.sealed_only)
    .bind(filter.scheme)
    .bind(filter.from_block)
    .bind(filter.to_block)
    .bind(filter.from_time)
    .bind(filter.to_time)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    // count(*) is a non-negative bigint; clamp the defensive lower edge to 0.
    Ok(u64::try_from(count.max(0)).unwrap_or(0))
}

/// Fetch a single anchored record by its transaction hash, or `None` when the
/// transaction is not indexed.
///
/// The read names `chain_records`, so it lives in the index's single SQL owner; it
/// carries no tenancy. The API layer maps a `None` to an oracle-safe 404 and
/// resolves any owner-only projection separately. A primary-key lookup can hardly
/// misplan, but it is anonymous-reachable, so it runs in the same bounded read
/// transaction as the list and count: one discipline for the whole public surface.
pub async fn fetch_record_by_tx_hash(
    pool: &sqlx::PgPool,
    tx_hash: &[u8],
) -> Result<Option<IndexedRecordRow>> {
    let mut tx = begin_records_read_txn(pool).await?;
    let row = sqlx::query_as::<_, IndexedRecordRow>(
        "SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                cr.signer_ed25519, cr.item_count, cr.scheme \
         FROM cw_core.chain_records cr \
         WHERE cr.tx_hash = $1",
    )
    .bind(tx_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// The lowest block height of a confirmed `poe_record` whose transaction is
/// absent from `chain_records`, or `None` when every confirmed record is indexed.
///
/// A confirmed record missing from the index means the scan advanced past its
/// block without persisting it; the self-heal rewinds below this height. The read
/// joins `chain_records` so it lives here, in the index's single owner.
pub async fn lowest_missing_confirmed_block_height(pool: &sqlx::PgPool) -> Result<Option<u64>> {
    let height: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(p.block_height) \
           FROM cw_core.poe_record p \
           LEFT JOIN cw_core.chain_records c ON c.tx_hash = p.tx_hash \
          WHERE p.status = 'confirmed' \
            AND p.block_height IS NOT NULL \
            AND p.tx_hash IS NOT NULL \
            AND c.tx_hash IS NULL",
    )
    .fetch_one(pool)
    .await?;
    Ok(height.map(|h| u64::try_from(h.max(0)).unwrap_or(0)))
}

/// The oldest `chain_records` transaction hashes still missing their full
/// transaction bytes, capped at `limit`, for the backfill pass.
///
/// A read against the index, kept here so `chain_records` has one SQL owner. The
/// forward scan's bounded backfill consumes these, fetches the bytes, and writes
/// them back through [`update_tx_cbor_backfill`].
pub async fn tx_cbor_backfill_candidates(pool: &sqlx::PgPool, limit: i64) -> Result<Vec<[u8; 32]>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT tx_hash FROM cw_core.chain_records \
         WHERE tx_cbor IS NULL ORDER BY block_height LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| crate::Error::Config("chain_records tx_hash is not 32 bytes".into()))
        })
        .collect()
}

/// Enqueue an index-tx job for a transaction, deduping on its hash so two sources
/// observing the same transaction enqueue it at most once.
///
/// Generic over the executor so the threshold-flip can enqueue inside the same
/// transaction that flips the record to `confirmed` (the in-tx enqueue that
/// closes the stranded-row gap), and the forward scan can enqueue against the
/// pool.
pub async fn enqueue_index_tx<'e, E>(
    executor: E,
    job: &IndexTxJob,
) -> Result<Option<crate::runtime::enqueue::JobId>>
where
    E: sqlx::PgExecutor<'e>,
{
    crate::runtime::enqueue::enqueue_dedupe(
        executor,
        INDEX_TX_QUEUE,
        job,
        crate::runtime::enqueue::EnqueueOptions {
            // Dedupe on the transaction hash: two sources observing the same
            // transaction (the confirm threshold-flip and the forward scan)
            // enqueue an index job at most once.
            singleton_key: Some(job.tx_hash.clone()),
            ..Default::default()
        },
    )
    .await
}

/// The single-writer job handler: derive columns and insert one record.
///
/// Register it on the runtime against [`INDEX_TX_QUEUE`] with
/// [`index_tx_policy`]. It owns its pool, the network its transactions are
/// carried on (the signature-verification context of the signer column), and,
/// when a job names [`MetadataSource::FetchByHash`], a chain gateway to fetch
/// the CBOR; the inline fast path needs no gateway.
pub struct IndexTxHandler<G: crate::chain::gateway::ChainGateway> {
    pool: sqlx::PgPool,
    gateway: G,
    network: crate::chain::params::Network,
}

impl<G: crate::chain::gateway::ChainGateway> IndexTxHandler<G> {
    /// Build a handler over a pool, a chain gateway (used only for the
    /// fetch-by-hash source), and the network the indexed transactions are
    /// carried on.
    pub fn new(pool: sqlx::PgPool, gateway: G, network: crate::chain::params::Network) -> Self {
        Self {
            pool,
            gateway,
            network,
        }
    }

    /// Index one transaction: resolve its metadata CBOR, derive the columns, and
    /// insert the row. Returns whether a new row was inserted.
    pub async fn index_once(&self, job: &IndexTxJob) -> Result<bool> {
        let tx_hash = parse_tx_hash(&job.tx_hash)?;

        // Resolve the metadata CBOR: carried inline on the fast path, or fetched
        // from chain by hash for a source that knows only the hash.
        let metadata_cbor = match &job.metadata {
            MetadataSource::Inline { metadata_cbor } => metadata_cbor.clone(),
            MetadataSource::FetchByHash => {
                let map = self.gateway.fetch_tx_cbor_by_hashes(&[tx_hash]).await?;
                map.get(&tx_hash).cloned().ok_or_else(|| {
                    crate::Error::ChainProvider(format!(
                        "no transaction CBOR on chain for {}",
                        job.tx_hash
                    ))
                })?
            }
        };

        let columns = derive_chain_record_columns(&metadata_cbor, self.network)?;
        insert_chain_record(
            &self.pool,
            tx_hash,
            job.block_height,
            job.block_time,
            &metadata_cbor,
            &columns,
        )
        .await
    }
}

impl<G: crate::chain::gateway::ChainGateway + 'static> JobHandler for IndexTxHandler<G> {
    async fn handle(&self, ctx: JobContext) -> JobOutcome {
        let job: IndexTxJob = match serde_json::from_value(ctx.payload) {
            Ok(job) => job,
            Err(e) => {
                return JobOutcome::Fail {
                    error: crate::runtime::JobError::new(
                        "index_tx_payload_invalid",
                        format!("could not parse index_tx job payload: {e}"),
                    ),
                }
            }
        };
        // The insert converges on conflict: a redelivery at the same height is a
        // no-op, and a re-fired job from a new-height re-inclusion re-pins the
        // coordinates, so re-indexing an already-present transaction completes
        // cleanly either way.
        match self.index_once(&job).await {
            Ok(_) => JobOutcome::Complete,
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("index_tx_failed", e.to_string()),
            },
        }
    }
}

/// Parse a 64-character hex transaction hash into its 32 bytes.
fn parse_tx_hash(hex_hash: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_hash)
        .map_err(|e| crate::Error::Config(format!("transaction hash is not hex: {e}")))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        crate::Error::Config(format!(
            "transaction hash must be 32 bytes, got {}",
            b.len()
        ))
    })
}

/// Hex (de)serialisation for the inline metadata CBOR, so an `index_tx` job
/// payload carries bytes as a compact hex string in JSON.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialise bytes as a lowercase hex string.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialise bytes from a hex string.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::params::Network;
    use blake2::digest::consts::U28;
    use blake2::{Blake2b, Digest};
    use cardanowall::cbor::{encode_canonical_cbor, CborValue};
    use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
    use cardanowall::poe_standard::{
        encode_poe_record, encode_record_body_for_signing, EncScheme1, EncryptionEnvelope,
        ItemEntry, PassphraseBlock, PoeRecord, SigEntry, Slot,
    };

    /// A 32-byte digest filled with one repeated byte.
    fn hash32(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    /// The CIP-19 stake address that binds `pubkey` on a network: the stake
    /// header byte (`0xe1` mainnet, `0xe0` testnet) followed by the BLAKE2b-224
    /// hash of the key. This is the claim a wallet-path signature must carry and
    /// the verifier recomputes.
    fn stake_address(network_header: u8, pubkey: &[u8; 32]) -> Vec<u8> {
        let key_hash: [u8; 28] = Blake2b::<U28>::digest(pubkey).into();
        let mut address = vec![network_header];
        address.extend_from_slice(&key_hash);
        address
    }

    /// A minimal valid open record carrying `count` content items, each with a
    /// single sha2-256 hash.
    fn open_record(count: usize) -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(
                (0..count)
                    .map(|i| ItemEntry {
                        hashes: vec![("sha2-256".to_string(), hash32(0x10 + i as u8))],
                        uris: None,
                        enc: None,
                    })
                    .collect(),
            ),
            ..PoeRecord::default()
        }
    }

    /// A record whose first item carries a recipient-sealed envelope (slots).
    fn sealed_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                uris: None,
                enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                    scheme: 1,
                    aead: "chacha20-poly1305-stream64k".to_string(),
                    nonce: vec![0x05; 24],
                    kem: Some("x25519".to_string()),
                    slots: Some(vec![Slot {
                        epk: Some(vec![0x01; 32]),
                        kem_ct: None,
                        wrap: Some(vec![0x09; 48]),
                    }]),
                    slots_mac: Some(vec![0x07; 32]),
                    passphrase: None,
                })),
            }]),
            ..PoeRecord::default()
        }
    }

    /// A record whose first item carries a passphrase-sealed envelope. Both
    /// sealed paths are `scheme: 1` on the wire; the passphrase block is what
    /// discriminates them.
    fn passphrase_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), hash32(0xcd))],
                uris: None,
                enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                    scheme: 1,
                    aead: "chacha20-poly1305-stream64k".to_string(),
                    nonce: vec![0x06; 24],
                    kem: None,
                    slots: None,
                    slots_mac: None,
                    passphrase: Some(PassphraseBlock {
                        alg: "argon2id".to_string(),
                        salt: vec![0x0a; 16],
                        params: vec![
                            ("m".to_string(), 65_536),
                            ("t".to_string(), 3),
                            ("p".to_string(), 4),
                        ],
                    }),
                })),
            }]),
            ..PoeRecord::default()
        }
    }

    /// A record whose first item carries an envelope under an unsupported
    /// scheme, which the public validator reads as opaque.
    fn opaque_envelope_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), hash32(0xef))],
                uris: None,
                enc: Some(EncryptionEnvelope::Opaque(CborValue::Map(vec![
                    (
                        CborValue::Text("scheme".to_string()),
                        CborValue::Unsigned(7),
                    ),
                    (
                        CborValue::Text("aead".to_string()),
                        CborValue::Text("future-aead".to_string()),
                    ),
                    (
                        CborValue::Text("nonce".to_string()),
                        CborValue::bytes(vec![0x01; 24]),
                    ),
                ]))),
            }]),
            ..PoeRecord::default()
        }
    }

    /// The COSE_Key blob for an OKP/Ed25519 public key (the path-2 sidecar form).
    fn cose_key_blob(pubkey: &[u8; 32]) -> Vec<u8> {
        encode_canonical_cbor(&CborValue::Map(vec![
            (CborValue::int(1), CborValue::int(1)),  // kty: OKP
            (CborValue::int(3), CborValue::int(-8)), // alg: EdDSA
            (CborValue::int(-1), CborValue::int(6)), // crv: Ed25519
            (CborValue::int(-2), CborValue::bytes(pubkey.to_vec())), // x
        ]))
        .expect("encode cose_key")
    }

    /// A detached COSE_Sign1 over the record body whose protected header carries
    /// the signer's raw key as the `kid` (the path-1 form).
    fn path1_cose_sign1(record: &PoeRecord, seed: &[u8; 32], kid: &[u8; 32]) -> Vec<u8> {
        let body = encode_record_body_for_signing(record).expect("encode body");
        let protected = CoseHeader::new()
            .with_int(1, CborValue::int(-8)) // alg: EdDSA
            .with_int(4, CborValue::bytes(kid.to_vec())); // kid: raw pubkey
        cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Seed(seed),
        )
        .expect("build cose_sign1")
    }

    /// A detached COSE_Sign1 over the record body with NO `kid` in its protected
    /// header (the path-2 form: the key is carried out-of-band in `cose_key`),
    /// carrying the CIP-19 stake `address` claim the wallet path requires.
    fn path2_cose_sign1(record: &PoeRecord, seed: &[u8; 32], address: Vec<u8>) -> Vec<u8> {
        let body = encode_record_body_for_signing(record).expect("encode body");
        let protected = CoseHeader::new()
            .with_int(1, CborValue::int(-8)) // alg: EdDSA, no kid
            .with_text("address", CborValue::bytes(address));
        cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Seed(seed),
        )
        .expect("build cose_sign1")
    }

    /// A detached COSE_Sign1 over the record body with neither a `kid` nor an
    /// `address` claim: a wallet-path signature missing its REQUIRED address
    /// binding.
    fn path2_cose_sign1_without_address(record: &PoeRecord, seed: &[u8; 32]) -> Vec<u8> {
        let body = encode_record_body_for_signing(record).expect("encode body");
        let protected = CoseHeader::new().with_int(1, CborValue::int(-8)); // alg: EdDSA
        cose_sign1_label309_build(
            &protected,
            &CoseHeader::new(),
            &body,
            Label309Signer::Seed(seed),
        )
        .expect("build cose_sign1")
    }

    #[test]
    fn derives_item_count_and_open_scheme_from_a_plain_record() {
        let record = open_record(3);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.item_count, 3,
            "item count is the number of content items"
        );
        assert_eq!(cols.scheme, 0, "an item with no envelope indexes as open");
        assert_eq!(
            cols.signer_ed25519, None,
            "an unsigned record has no signer"
        );
    }

    #[test]
    fn derives_sealed_scheme_from_the_first_items_envelope() {
        let record = sealed_record();
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.scheme, 1,
            "a slots-bearing first item indexes as scheme 1"
        );
        assert_eq!(cols.item_count, 1);
    }

    #[test]
    fn derives_passphrase_scheme_from_the_envelope_shape_not_the_wire_field() {
        // Both sealed paths carry `enc.scheme = 1` on the wire; the projection
        // must read the passphrase block, not the wire scheme value.
        let record = passphrase_record();
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.scheme, 2,
            "a passphrase-bearing first item indexes as scheme 2"
        );
    }

    #[test]
    fn indexes_an_unsupported_suite_envelope_as_sealed_not_open() {
        // The public validator reads an envelope under an unsupported scheme as
        // opaque and still accepts the record. The item is sealed, so it must
        // stay visible to sealed-record scans (never index as open).
        let record = opaque_envelope_record();
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.scheme, 1,
            "an opaque sealed envelope indexes as the generic sealed value"
        );
    }

    /// CIP-19 stake-address header bytes: mainnet, and the shared testnet class.
    const STAKE_HEADER_MAINNET: u8 = 0xe1;
    const STAKE_HEADER_TESTNET: u8 = 0xe0;

    #[test]
    fn a_genuinely_signed_path1_record_indexes_its_verified_signer() {
        // Seed -> public key -> path-1 signature whose protected-header kid is the
        // raw public key AND whose signature verifies over the record body. Only
        // then does the key surface as the indexed signer.
        let seed = [0x42_u8; 32];
        let pubkey = cardanowall::cose::ed25519_public_key_from_seed(&seed);
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path1_cose_sign1(&record, &seed, &pubkey),
            cose_key: None,
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.signer_ed25519,
            Some(pubkey),
            "a verified path-1 signature surfaces its raw signer public key"
        );
    }

    #[test]
    fn a_genuinely_signed_path2_wallet_record_indexes_its_verified_signer() {
        // Path-2: the protected header carries no kid (the wire format forbids
        // carrying both a kid and a cose_key) but DOES carry the CIP-19 stake
        // address the wallet path binds; the signer's key is the out-of-band
        // cose_key sidecar. With a verifying signature and a matching address
        // under the carrying network, the key surfaces as the indexed signer.
        let seed = [0x11_u8; 32];
        let pubkey = cardanowall::cose::ed25519_public_key_from_seed(&seed);
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path2_cose_sign1(
                &record,
                &seed,
                stake_address(STAKE_HEADER_MAINNET, &pubkey),
            ),
            cose_key: Some(cose_key_blob(&pubkey)),
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.signer_ed25519,
            Some(pubkey),
            "a verified, address-bound path-2 signature surfaces its signer key"
        );
    }

    #[test]
    fn a_co_signed_record_yields_every_verified_signer_in_entry_order() {
        // Two genuinely-signed path-1 entries by distinct keys: both must surface
        // in `verified_signers`, in `sigs[]` order, and the first is the primary
        // projected `signer_ed25519`. This is what makes the side table — and so
        // the `?signer=` filter — find the record by EITHER signer.
        let seed_a = [0x61_u8; 32];
        let seed_b = [0x62_u8; 32];
        let pub_a = cardanowall::cose::ed25519_public_key_from_seed(&seed_a);
        let pub_b = cardanowall::cose::ed25519_public_key_from_seed(&seed_b);
        let mut record = open_record(1);
        record.sigs = Some(vec![
            SigEntry {
                cose_sign1: path1_cose_sign1(&record, &seed_a, &pub_a),
                cose_key: None,
            },
            SigEntry {
                cose_sign1: path1_cose_sign1(&record, &seed_b, &pub_b),
                cose_key: None,
            },
        ]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.verified_signers,
            vec![pub_a, pub_b],
            "both verified signers surface, in sigs[] order"
        );
        assert_eq!(
            cols.signer_ed25519,
            Some(pub_a),
            "the primary projected signer is the first verified one"
        );
    }

    #[test]
    fn a_co_signed_record_with_one_forged_entry_yields_only_the_verified_signer() {
        // One genuine entry and one forgery (a path-1 kid naming a victim's key the
        // signature was not produced under). Only the genuine signer enters the
        // verified set, so a forged co-signer can never plant a key into the
        // victim's publisher view through the side table.
        let seed_a = [0x71_u8; 32];
        let pub_a = cardanowall::cose::ed25519_public_key_from_seed(&seed_a);
        let attacker_seed = [0x72_u8; 32];
        let victim_pubkey = [0x73_u8; 32];
        let mut record = open_record(1);
        record.sigs = Some(vec![
            SigEntry {
                cose_sign1: path1_cose_sign1(&record, &seed_a, &pub_a),
                cose_key: None,
            },
            SigEntry {
                cose_sign1: path1_cose_sign1(&record, &attacker_seed, &victim_pubkey),
                cose_key: None,
            },
        ]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.verified_signers,
            vec![pub_a],
            "only the genuinely-signed key is in the verified set; the forgery is excluded"
        );
    }

    #[test]
    fn an_unsigned_record_yields_an_empty_verified_set() {
        let record = open_record(2);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert!(
            cols.verified_signers.is_empty(),
            "an unsigned record contributes no signer-set rows"
        );
        assert_eq!(cols.signer_ed25519, None);
    }

    #[test]
    fn a_forged_cose_key_naming_someone_elses_key_indexes_as_unsigned() {
        // The attack the verified derivation exists to stop: a structurally
        // valid-shaped cose_key sidecar names a victim's key, but the signature
        // was produced by a different key. Verification against the named key
        // fails, so the record indexes as unsigned — the victim's public feed
        // (signer filter, records count) is never poisoned by the forgery.
        let attacker_seed = [0x22_u8; 32];
        let victim_pubkey = [0x99_u8; 32];
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path2_cose_sign1(
                &record,
                &attacker_seed,
                stake_address(STAKE_HEADER_MAINNET, &victim_pubkey),
            ),
            cose_key: Some(cose_key_blob(&victim_pubkey)),
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.signer_ed25519, None,
            "a signature that does not verify under its named key surfaces no signer"
        );
    }

    #[test]
    fn a_forged_path1_kid_naming_someone_elses_key_indexes_as_unsigned() {
        // The path-1 flavour of the forgery: the protected-header kid is a
        // valid-shaped 32-byte key that did not produce the signature.
        let attacker_seed = [0x33_u8; 32];
        let victim_pubkey = [0x77_u8; 32];
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path1_cose_sign1(&record, &attacker_seed, &victim_pubkey),
            cose_key: None,
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.signer_ed25519, None,
            "a kid the signature does not verify under surfaces no signer"
        );
    }

    #[test]
    fn a_wallet_signature_without_its_address_binding_indexes_as_unsigned() {
        // The wallet path REQUIRES the CIP-19 address claim: a cryptographically
        // valid path-2 signature with no address binding cannot be safely
        // surfaced as a wallet signer, so it indexes as unsigned.
        let seed = [0x44_u8; 32];
        let pubkey = cardanowall::cose::ed25519_public_key_from_seed(&seed);
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path2_cose_sign1_without_address(&record, &seed),
            cose_key: Some(cose_key_blob(&pubkey)),
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");
        let cols = derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            cols.signer_ed25519, None,
            "an unbound wallet signature surfaces no signer"
        );
    }

    #[test]
    fn the_carrying_network_decides_wallet_address_binding() {
        // The same genuinely-signed wallet record, bound to a TESTNET stake
        // address: under a preprod gateway the binding holds and the signer
        // surfaces; under a mainnet gateway the recomputed header byte differs
        // and the record indexes as unsigned. This is why the scan threads its
        // configured network into the derivation.
        let seed = [0x55_u8; 32];
        let pubkey = cardanowall::cose::ed25519_public_key_from_seed(&seed);
        let mut record = open_record(1);
        record.sigs = Some(vec![SigEntry {
            cose_sign1: path2_cose_sign1(
                &record,
                &seed,
                stake_address(STAKE_HEADER_TESTNET, &pubkey),
            ),
            cose_key: Some(cose_key_blob(&pubkey)),
        }]);
        let bytes = encode_poe_record(&record).expect("encode record");

        let on_preprod =
            derive_chain_record_columns(&bytes, Network::Preprod).expect("derive columns");
        assert_eq!(
            on_preprod.signer_ed25519,
            Some(pubkey),
            "a testnet-bound wallet signature verifies on the testnet class"
        );

        let on_mainnet =
            derive_chain_record_columns(&bytes, Network::Mainnet).expect("derive columns");
        assert_eq!(
            on_mainnet.signer_ed25519, None,
            "the same record under a mainnet gateway surfaces no signer"
        );
    }

    #[test]
    fn malformed_metadata_is_rejected_not_indexed_with_fabricated_columns() {
        // A byte string that is not a valid Label 309 record must error so the
        // single writer skips it rather than inserting fabricated columns.
        let err = derive_chain_record_columns(&[0x00, 0x01, 0x02], Network::Mainnet)
            .expect_err("invalid record bytes must be rejected");
        assert!(matches!(err, crate::Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn index_tx_job_round_trips_through_json_with_inline_metadata() {
        let job = IndexTxJob {
            tx_hash: "ab".repeat(32),
            block_height: 1234,
            block_time: DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
            metadata: MetadataSource::Inline {
                metadata_cbor: vec![0xa1, 0x01, 0x82],
            },
        };
        let json = serde_json::to_string(&job).expect("serialise");
        // The inline bytes ride as hex, not a JSON array, so the payload stays
        // compact and human-readable.
        assert!(json.contains("a10182"));
        let back: IndexTxJob = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, job);
    }

    #[test]
    fn fetch_by_hash_source_round_trips() {
        let job = IndexTxJob {
            tx_hash: "cd".repeat(32),
            block_height: 9,
            block_time: DateTime::from_timestamp(1, 0).expect("valid timestamp"),
            metadata: MetadataSource::FetchByHash,
        };
        let json = serde_json::to_string(&job).expect("serialise");
        let back: IndexTxJob = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, job);
    }

    #[test]
    fn index_tx_policy_is_a_standard_worker_queue() {
        let policy = index_tx_policy();
        assert_eq!(policy.queue, INDEX_TX_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::Standard
        );
    }

    /// The path suffix that identifies the one sanctioned writer of the tables.
    ///
    /// The exemption is keyed on this full path suffix, not the bare basename: a
    /// basename match (`records.rs`) would also exempt any other file named
    /// `records.rs` anywhere in the tree (for example an `api/routes/records.rs`
    /// HTTP handler), which could then name `chain_records` / `cw_api.records`
    /// undetected. Matching the suffix exempts only the real chain writer.
    const SINGLE_WRITER_PATH_SUFFIX: &str = "chain/records.rs";

    /// Whether a source path is the single sanctioned writer, by full path suffix.
    /// Normalises Windows separators so the suffix match is platform-independent.
    ///
    /// The suffix must be a whole path component boundary: the path either equals
    /// the suffix or ends with `"/" + suffix`. This rejects a directory whose name
    /// merely ends in `chain` (so `notchain/records.rs` is NOT the chain writer),
    /// which a bare `ends_with("chain/records.rs")` would wrongly accept.
    fn is_single_writer_path(path: &std::path::Path) -> bool {
        let normalised = path.to_string_lossy().replace('\\', "/");
        normalised == SINGLE_WRITER_PATH_SUFFIX
            || normalised.ends_with(&format!("/{SINGLE_WRITER_PATH_SUFFIX}"))
    }

    /// Architecture guard: the rich `cw_core.chain_records` row, its verified-signer
    /// set `cw_core.chain_record_signer`, and its thin `cw_api.records` anchor each
    /// have exactly one writer, this module. No other source file may name any of
    /// them in SQL, so the single-writer invariant (the anchor, the rich row, and
    /// the signer set are always created together, here) can never erode by a stray
    /// query slipping into another module. Scans the crate source tree; the
    /// migration that defines the tables is not Rust and is excluded.
    ///
    /// The exemption matches the writer by full path suffix (`chain/records.rs`),
    /// not by basename, so a same-basename file elsewhere in the tree (such as an
    /// `api/routes/records.rs`) is still caught if it names the tables.
    ///
    /// `chain_record_signer` is checked as a whole token (the trailing `(` /
    /// whitespace boundary), so the existing `cw_core.chain_records` references in
    /// this very module are not mistaken for it (one is not a prefix of the other
    /// across the `s` vs `_signer` boundary, but the explicit boundary keeps the
    /// intent unambiguous).
    #[test]
    fn chain_records_and_its_anchor_have_a_single_writer() {
        use std::path::Path;

        // This test file IS the sanctioned writer, so its own suffix must match.
        assert!(
            is_single_writer_path(Path::new(file!())),
            "the writer module's own path must satisfy the suffix exemption"
        );

        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        visit_rs_files(&src_root, &mut |path, contents| {
            if is_single_writer_path(path) {
                return;
            }
            if contents.contains("cw_core.chain_records")
                || contents.contains("cw_core.chain_record_signer")
                || contents.contains("cw_api.records")
            {
                offenders.push(path.display().to_string());
            }
        });

        assert!(
            offenders.is_empty(),
            "chain_records, its chain_record_signer set, and its cw_api.records anchor must have a single writer (chain/records.rs); these files also reference one: {offenders:?}"
        );
    }

    /// Guard self-test: the exemption is keyed on the `chain/records.rs` path
    /// suffix, not the bare basename. A file named `records.rs` under a *different*
    /// directory that names the tables must NOT be exempt (it must trip the
    /// guard), and only the real `chain/records.rs` suffix is exempt.
    #[test]
    fn single_writer_exemption_is_keyed_on_path_suffix_not_basename() {
        use std::path::Path;

        // The real chain writer is exempt.
        assert!(
            is_single_writer_path(Path::new("/repo/src/chain/records.rs")),
            "the real chain writer must be exempt"
        );
        assert!(
            is_single_writer_path(Path::new("src/chain/records.rs")),
            "a relative path to the chain writer must be exempt"
        );

        // A same-basename file elsewhere is NOT exempt: it would be caught if it
        // named the tables. This is exactly the file a basename match would have
        // wrongly exempted.
        assert!(
            !is_single_writer_path(Path::new("/repo/src/api/routes/records.rs")),
            "an api/routes/records.rs must not be exempt: a basename match would have wrongly exempted it"
        );
        assert!(
            !is_single_writer_path(Path::new("/repo/src/storage/records.rs")),
            "any other same-basename file must not be exempt"
        );

        // A directory that merely ends in the segment names but is not the file is
        // not exempt either (suffix is on the full `chain/records.rs`, not a bare
        // `records.rs`).
        assert!(
            !is_single_writer_path(Path::new("/repo/src/notchain/records.rs")),
            "a directory whose name only ends with 'chain' does not exempt its records.rs"
        );
    }

    /// Recursively visit every `.rs` file under `dir`, calling `f` with its path
    /// and contents.
    fn visit_rs_files(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit_rs_files(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    f(&path, &contents);
                }
            }
        }
    }
}
