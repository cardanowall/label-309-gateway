//! The chain-gateway seam: submit, confirmation lookup, block and tip reads,
//! and raw-transaction fetch, behind one trait with a failover wrapper.
//!
//! # Roles
//!
//! - [`ChainGateway`] is the surface the submit and confirm paths call. Every
//!   method is batched where the underlying provider supports a batch, and every
//!   requested transaction hash is answered (a hash absent from the chain comes
//!   back as [`TxConfirmation::not_on_chain`]) so a caller never has to
//!   distinguish "missing from the map" from "not on chain".
//! - [`KoiosGateway`] is the Koios implementation, mirroring the
//!   protocol-parameter source's transport patterns (lenient numerics, per-network
//!   base URLs, the non-deprecated field names). It is keyless on the public
//!   tier by default; a [`KoiosConfig`] supplies an operator API key (sent as
//!   `Authorization: Bearer`) and/or a self-hosted base URL.
//! - [`BlockfrostGateway`] is the project-id-authenticated secondary. It has no
//!   batch confirmation endpoint, so it fetches per hash and reads the tip once
//!   per batch; the project id is read from a configured file path, never
//!   hardcoded.
//! - [`FailoverGateway`] wraps a primary and a secondary: a transient failure on
//!   the primary (timeout/connect, 5xx, 425, 429) fails over to the secondary;
//!   a non-transient error (a 4xx that is not 425/429) propagates without
//!   failover. The secondary is a Blockfrost gateway when a project id is
//!   configured, else a second Koios instance, so the wrapper's shape is the same
//!   on every deployment (see [`build_failover_gateway`]).
//! - [`StubChainGateway`] is the offline test gateway. Like the wallet's stub
//!   submitter it refuses to be constructed on the production network, so a stub
//!   can never answer for a real mainnet submit.
//!
//! # Error classification
//!
//! Each implementation classifies its own transport/status failure as it raises
//! it, carrying the class in [`Error::ChainProviderClassified`] via
//! [`chain_error`]. [`is_transient_chain_error`] and the failover wrapper read
//! that class with [`classify_chain_error`], so the failover decision (and the
//! 429-only cooldown write-through) never has to re-parse a provider's error
//! taxonomy.
//!
//! # Cooldown and the rate-limit storm
//!
//! A `cw_core.chain_provider_cooldown` row records a provider+network that
//! returned 429. It is consulted before a call and written through on a 429, so a
//! single provider's rate limit is skipped on the next call and the gate survives
//! a process restart. When BOTH providers are rate-limiting us (the primary is
//! parked or 429s, and the secondary then 429s as well) the wrapper engages the
//! cooldown on every parked provider and raises [`Error::ChainRateLimitStorm`]
//! carrying the soonest cooldown instant. The submit, confirm, and scan loops all
//! map that one typed error to a defer for the carried window, so a sustained
//! storm parks the loops without burning their attempts.
//!
//! # The local egress budget
//!
//! Independently of the provider's own limits, every HTTP request a provider
//! implementation issues is first admitted through a [`ProviderEgress`] token
//! bucket (see [`super::egress`]): the backstop that makes a runaway caller
//! physically unable to stampede a provider's daily quota. A denied request
//! fails with the same 429 class a real provider rate limit carries, so the
//! failover, cooldown, and storm semantics above apply unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use zeroize::Zeroizing;

use super::egress::{ChainEgress, EgressLimits, ProviderEgress};
use super::params::{KoiosConfig, Network};
use crate::http::{read_capped_json, read_capped_text, read_diagnostic_body, JSON_BODY_CEILING};
use crate::{Error, Result};

/// The confirmation status of a single transaction as observed on chain.
///
/// `num_confirmations` is `0` and the coordinates are `None` when the
/// transaction is not on chain (still in the mempool, or never submitted). A
/// caller distinguishes "in mempool" from "rolled back" with the record's own
/// `first_seen_on_chain_at`, never from this struct alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxConfirmation {
    /// Confirmations the transaction has accrued (`tip - block_height + 1`), or
    /// `0` when it is not on chain.
    pub num_confirmations: u64,
    /// The block height the transaction landed in, or `None` when not on chain.
    pub block_height: Option<u64>,
    /// The block time the transaction landed in, or `None` when not on chain.
    pub block_time: Option<DateTime<Utc>>,
    /// Whether the provider gave a POSITIVE signal that the transaction exists
    /// (a `/tx_status` confirmation count, a found transaction row) even though
    /// the complete coordinates above may be missing. This is what separates a
    /// positive-but-incomplete observation from affirmative absence when the
    /// numeric fields are the same not-on-chain shape; [`Self::presence`]
    /// derives the three-way verdict from it. The confirm/reorg authority never
    /// reads it — its incomplete-observation handling keys on the numeric
    /// fields alone and is unchanged by this flag.
    pub positively_seen: bool,
}

impl TxConfirmation {
    /// The sentinel for a transaction the provider AFFIRMATIVELY has no record
    /// of: not counted by a status endpoint and no transaction row (e.g. a
    /// Blockfrost 404, or a Koios `/tx_status` null).
    #[must_use]
    pub fn not_on_chain() -> Self {
        Self {
            num_confirmations: 0,
            block_height: None,
            block_time: None,
            positively_seen: false,
        }
    }

    /// A positive-but-incomplete observation: the provider signalled the
    /// transaction exists (a status count, a found row) but complete on-chain
    /// coordinates were not returned — cross-endpoint replica lag, a truncated
    /// response, a not-yet-in-a-block row, or a rollback race mid-poll.
    ///
    /// Numerically identical to [`Self::not_on_chain`], so the confirm
    /// authority still treats it as not-yet-observed and never settles on a
    /// fabricated coordinate; only [`Self::presence`] tells the two apart.
    #[must_use]
    pub fn inconclusive() -> Self {
        Self {
            num_confirmations: 0,
            block_height: None,
            block_time: None,
            positively_seen: true,
        }
    }

    /// A complete on-chain observation: a confirmation count with BOTH real
    /// coordinates.
    #[must_use]
    pub fn on_chain(num_confirmations: u64, block_height: u64, block_time: DateTime<Utc>) -> Self {
        Self {
            num_confirmations,
            block_height: Some(block_height),
            block_time: Some(block_time),
            positively_seen: true,
        }
    }

    /// The three-way presence verdict of this observation.
    ///
    /// Money decisions (the submit path's abandon-and-refund gate) MUST consume
    /// this, never the bare numeric fields: the not-on-chain numeric shape is
    /// shared by affirmative absence and a positive-but-incomplete observation,
    /// and treating the latter as absence refunds a transaction that may in
    /// fact be on chain. A non-zero count without coordinates is also read as
    /// inconclusive, so no constructor drift can ever make a partial
    /// observation look affirmatively absent.
    #[must_use]
    pub fn presence(&self) -> TxPresence {
        if self.block_height.is_some() && self.block_time.is_some() {
            TxPresence::OnChain
        } else if self.positively_seen || self.num_confirmations > 0 {
            TxPresence::Inconclusive
        } else {
            TxPresence::Absent
        }
    }
}

/// The three-way presence verdict a confirmation lookup yields for one
/// transaction, consumed by decisions that must not conflate "the provider is
/// mid-hydration" with "the transaction does not exist" (the submit path's
/// abandon-and-refund gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxPresence {
    /// On chain with complete coordinates (a block height AND a block time).
    OnChain,
    /// The provider affirmatively has no record of the transaction.
    Absent,
    /// A positive but incomplete signal: the provider indicated the transaction
    /// exists without returning complete coordinates. Neither presence nor
    /// absence is proven; a caller must re-observe later.
    Inconclusive,
}

/// A block's coordinates as read by height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    /// The block height.
    pub block_height: u64,
    /// The 32-byte block hash.
    pub block_hash: [u8; 32],
    /// The block time.
    pub block_time: DateTime<Utc>,
}

/// The chain tip as read in one `/tip` call: the tip block height and the epoch
/// the chain is currently in.
///
/// A provider's tip response carries the current epoch right next to the tip
/// height, so a single tip read yields both. The forward scan materialises both
/// into `cw_core.cardano_tip`, which lets the protocol-parameter populate loop
/// learn the current epoch from that row instead of making its own tip call. The
/// `epoch` is optional so a provider response that omits it (or a future
/// provider that does not surface it) still yields a usable tip height; the
/// populate loop falls back to a single tip call when the materialised epoch is
/// absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// The tip block height.
    pub block_height: u64,
    /// The epoch the chain is currently in, when the provider reported it.
    pub epoch: Option<u64>,
}

/// One Label 309 record the forward scan discovered on chain, with the block
/// coordinates and confirmation count the scan reconciles against.
///
/// `metadata_cbor` is the bare canonical record bytes (the on-chain chunked-bstr
/// wrapper already unwrapped), so the structural validator and column derivation
/// receive exactly the input they expect, byte-identical across providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label309Record {
    /// 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// 32-byte hash of the block the transaction landed in (the reorg anchor the
    /// cursor carries when it stops below the tip).
    pub block_hash: [u8; 32],
    /// The block height the transaction landed in.
    pub block_height: u64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
    /// Confirmations derived against the tip the call was given
    /// (`max(0, tip - block_height + 1)`).
    pub num_confirmations: u64,
    /// The verbatim, unwrapped Label 309 metadata CBOR.
    pub metadata_cbor: Vec<u8>,
}

/// Where the cursor may safely advance to after one forward-scan fetch.
///
/// The cursor advances by block height and the next tick requests records
/// STRICTLY above it, so it must never pass a height that is not PROVEN both
/// fully indexed by the answering provider AND fully hydrated this fetch. A
/// provider whose metadata index lags the externally-observed tip, or a listed
/// transaction that did not hydrate, both lower this frontier below a naive
/// "jump to the tip" — anchoring there turns a lagging provider or a hydration
/// gap into a re-tried barrier instead of a permanent skip. The one place a
/// height frontier cannot express progress — a single block carrying more
/// label-309 transactions than one window holds — is the [`Self::IntraBlock`]
/// variant: the block is consumed piecemeal across ticks against a durable
/// per-transaction exclusion set, so the per-tick cap is a page size, never a
/// liveness wall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanFrontier {
    /// Advance the cursor to exactly `height`, anchored at `block_hash`. This is
    /// the highest block the fetch proved fully indexed AND fully hydrated; the
    /// next tick resumes strictly above it. A capped window, a split boundary
    /// block, or a hydration gap all land here so the un-covered remainder above
    /// `height` is re-fetched next tick rather than skipped.
    Anchor { height: u64, block_hash: [u8; 32] },
    /// The boundary block at `height` holds more un-consumed label-309
    /// transactions than one window: this fetch consumed PART of it (the
    /// returned records, plus `consumed_no_record` — transactions observed to
    /// carry no chunk-array record, a verdict on the transaction, consumed with
    /// nothing to index). The caller anchors the cursor AT `height` with
    /// `block_hash`, remembers every consumed transaction hash durably, and the
    /// next fetch re-reads the block excluding exactly those hashes. Which
    /// subset a tick consumes is deliberately irrelevant — the exclusion set
    /// makes the intra-block paging order-free, so both providers (and a
    /// mid-block failover between them) page it identically.
    IntraBlock {
        /// The partially-consumed boundary block.
        height: u64,
        /// That block's hash: the cursor anchors here, so the standing
        /// frontier-hash reorg check re-verifies exactly the block being
        /// consumed.
        block_hash: [u8; 32],
        /// Transactions consumed this fetch that produced no record (observed
        /// non-carriage metadata). The caller adds them to the exclusion set
        /// alongside the returned records' hashes; leaving them out would
        /// re-fetch them forever and starve the window.
        consumed_no_record: Vec<[u8; 32]>,
    },
    /// The answering provider proved it has indexed every label-309 record up to
    /// its own metadata watermark `indexed_to`, with none above the highest
    /// returned record up to it. The cursor jumps to `min(tip, indexed_to)`,
    /// never past what THIS provider can actually see, so a provider lagging the
    /// other provider's tip can never drive the cursor over the gap.
    CaughtUpTo { indexed_to: u64 },
    /// No height is safe to advance to this fetch: the lowest record the fetch
    /// proved exists could not be hydrated (a hydration gap at or below the
    /// frontier), so there is nothing the cursor can pass without skipping it.
    /// The cursor is left unchanged and the next tick re-fetches the same window.
    Hold,
}

/// The result of one forward-scan fetch: the records discovered above the cursor
/// and the safe frontier the cursor may advance to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label309RecordsResult {
    /// The records discovered above the cursor, ascending by block height.
    pub records: Vec<Label309Record>,
    /// How far the cursor may safely advance after this fetch.
    pub frontier: ScanFrontier,
}

impl Default for Label309RecordsResult {
    /// An empty result that advances the cursor nowhere: no records and a held
    /// frontier. A real provider always reports a concrete watermark or anchor; the
    /// default is the safe no-op a non-scanning stub returns.
    fn default() -> Self {
        Self {
            records: Vec::new(),
            frontier: ScanFrontier::Hold,
        }
    }
}

/// How a forward-scan window is cut so the cursor never anchors in the MIDDLE of a
/// block.
enum WindowCut {
    /// Keep every record at or below `cutoff_height`. `None` keeps the whole window
    /// (the cap was not reached, so the provider had nothing more above it up to its
    /// own tip — the caught-up case the caller turns into a `CaughtUpTo` frontier);
    /// `Some` caps the window at a complete block boundary, so more records exist
    /// above it (the caller anchors there).
    Keep { cutoff_height: Option<u64> },
    /// The boundary block carries more label-309 records than one window holds, so
    /// the cursor cannot advance past it by height. The caller consumes part of the
    /// block and reports an [`ScanFrontier::IntraBlock`] frontier so the scan pages
    /// through it across ticks instead of stalling.
    SingleBlockOverflow { block_height: u64 },
}

/// Decide a block-aligned height cutoff for an ascending-by-height forward-scan
/// window so the cursor never anchors in the MIDDLE of a block.
///
/// The cursor advances by block height, and the next tick requests records STRICTLY
/// above the anchored height. So if a window were to end in the middle of a block
/// (more records share the highest kept height than were kept), anchoring at that
/// height would skip the same-block remainder forever.
///
/// `heights` are the block heights of EVERY label-309 transaction the scan knows
/// about above the cursor, sorted ascending, up to AT LEAST `max_records + 1` when
/// more exist — the one height past the cap is what reveals whether the
/// `max_records`-th block is complete or split. The heights come from the listed
/// transactions (including any whose metadata later fails to hydrate), so the cut
/// never lands inside a block that has an un-hydrated record either:
/// - `heights.len() <= max_records` — the scan saw everything available: keep it all
///   (`cutoff_height` None, the caught-up case).
/// - otherwise the window is capped at `max_records`. If the height just past the
///   cap is STRICTLY HIGHER, the boundary block ends exactly at the cap and the cut
///   is that boundary height. If it equals the boundary height, that block is split,
///   so the cut is the last height strictly below it. A cut below the first height
///   means a single block exceeds the cap (`SingleBlockOverflow`).
fn block_aligned_window(heights: &[u64], max_records: usize) -> WindowCut {
    if heights.len() <= max_records {
        return WindowCut::Keep {
            cutoff_height: None,
        };
    }
    // Capped: the scan has at least one height beyond `max_records`. The boundary
    // block is the one the cap falls in.
    let boundary_height = heights[max_records - 1];
    if heights[max_records] > boundary_height {
        // The next height is a higher block, so the boundary block ends exactly at the
        // cap: anchor at the boundary height (the whole boundary block is included).
        return WindowCut::Keep {
            cutoff_height: Some(boundary_height),
        };
    }
    // The boundary block continues past the cap (it is split): the cutoff is the last
    // height strictly below it, so the cursor anchors at the last fully-included block.
    match heights
        .iter()
        .copied()
        .filter(|&h| h < boundary_height)
        .max()
    {
        Some(cut) => WindowCut::Keep {
            cutoff_height: Some(cut),
        },
        None => WindowCut::SingleBlockOverflow {
            block_height: boundary_height,
        },
    }
}

/// Which provider answered a call, for tracing and the failover reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// The keyless Koios gateway.
    Koios,
    /// The Blockfrost gateway (project-id authenticated).
    Blockfrost,
}

impl ProviderKind {
    /// The stable string stored in `chain_provider_cooldown.provider`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Koios => "koios",
            ProviderKind::Blockfrost => "blockfrost",
        }
    }
}

/// The map type batched confirmation/CBOR lookups return: every requested hash
/// is a key, so a caller never has to handle a missing entry.
pub type TxConfirmationMap = std::collections::HashMap<[u8; 32], TxConfirmation>;

/// The map type [`ChainGateway::fetch_tx_cbor_by_hashes`] returns: a hash maps to
/// its full transaction CBOR, and a hash with no on-chain transaction is absent.
pub type TxCborMap = std::collections::HashMap<[u8; 32], Vec<u8>>;

/// The chain data provider seam the submit and confirm paths call.
///
/// All confirmation and CBOR lookups are batched and answer every requested
/// hash. Implementations classify their own transport/status failures so the
/// [`FailoverGateway`] can decide whether to fail over; a transient failure is
/// reported as [`Error::ChainProviderClassified`] carrying its
/// [`ChainErrorClass`] (see [`is_transient_chain_error`]).
pub trait ChainGateway: Send + Sync {
    /// Submit fully signed transaction CBOR, returning the accepted transaction
    /// id. The id the node echoes is cross-checked against the one the builder
    /// computed by the caller.
    fn submit_tx(
        &self,
        signed_tx: &[u8],
    ) -> impl std::future::Future<Output = Result<[u8; 32]>> + Send;

    /// Batch confirmation lookup. Every hash in `tx_hashes` appears in the
    /// returned map; a hash not on chain maps to [`TxConfirmation::not_on_chain`].
    /// The implementation chunks the request to the provider's per-tier body limit.
    fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> impl std::future::Future<Output = Result<TxConfirmationMap>> + Send;

    /// Read a block's coordinates by height, or `None` when no such block exists.
    fn get_block_info(
        &self,
        block_height: u64,
    ) -> impl std::future::Future<Output = Result<Option<BlockInfo>>> + Send;

    /// The current chain tip: the tip block height and the epoch the chain is in,
    /// read in one call. The forward scan is the single owner of this read and
    /// materialises both fields into `cw_core.cardano_tip`.
    fn get_tip(&self) -> impl std::future::Future<Output = Result<ChainTip>> + Send;

    /// Batch fetch full transaction CBOR by hash. A hash with no on-chain
    /// transaction is omitted from the returned map.
    fn fetch_tx_cbor_by_hashes(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> impl std::future::Future<Output = Result<TxCborMap>> + Send;

    /// Forward-scan fetch: the Label 309 records strictly above `after_block_height`
    /// up to `tip_block_height`, capped at `max_records`, ascending by block height.
    ///
    /// `exclude_tx_hashes` is the durable already-consumed set of a partially
    /// scanned boundary block (see [`ScanFrontier::IntraBlock`]): the fetch
    /// silently drops those transactions, and an implementation widens its list
    /// query by the exclusion count so exclusions can never crowd a full window
    /// out of the response. Empty on an ordinary (block-aligned) fetch.
    ///
    /// The records' confirmation counts are derived against `tip_block_height`, so
    /// the scan never makes a second tip read inside the fetch. The result's
    /// [`ScanFrontier`] reports how far the cursor may safely advance: the
    /// answering provider's own metadata watermark when caught up (clamped so a
    /// provider lagging the given tip cannot drive the cursor past what it has
    /// indexed), an anchor at the highest fully-hydrated complete block when
    /// capped or stopped below a hydration gap, or an intra-block page of a
    /// boundary block too full for one window. Per-block enumeration is forbidden:
    /// a provider returns records by count, not by walking every block.
    fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> impl std::future::Future<Output = Result<Label309RecordsResult>> + Send;

    /// The same forward-scan fetch, but biased to the ALTERNATE provider first.
    ///
    /// The forward scan uses this to recover a STUCK GAP: a height the usual
    /// (primary-first) fetch keeps failing to advance past because the primary
    /// cannot hydrate the transaction sitting there. A provider-specific hydration
    /// failure (a `/tx_metadata` replica lag on Koios, a mempool/partial `/txs`
    /// row on Blockfrost) does not surface as an error — it returns a non-advancing
    /// frontier — so the [`FailoverGateway`]'s error-driven failover never triggers
    /// for it, and the gap would stall the whole feed. Running the SECONDARY first
    /// (falling back to the primary) lets the other provider resolve the stuck
    /// height when it can, so one provider's blind spot never halts global delivery.
    ///
    /// For a single (non-failover) gateway this is identical to
    /// [`Self::fetch_label309_records_since`] — there is no alternate provider.
    fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> impl std::future::Future<Output = Result<Label309RecordsResult>> + Send;
}

/// The Cardano transaction-metadata label Proof-of-Existence records are
/// published under. Every forward-scan query filters on it.
pub const POE_METADATA_LABEL: u64 = 309;

/// The keyless Koios chunk size for `/tx_status`, `/tx_info`, `/tx_metadata`,
/// and `/tx_cbor` bodies. Koios caps the request BODY per tier — about 1 KiB on
/// the public (keyless) tier — so fourteen 64-character hex hashes plus the
/// JSON envelope is the most a keyless request may carry.
pub const KOIOS_KEYLESS_CHUNK: usize = 14;

/// The keyed Koios chunk size for the same bulk POST bodies. The registered
/// tiers raise the request-body cap to about 5 KiB (the Koios API description
/// states the body "limited to 1kb for public and 5kb for registered tiers"),
/// so an authenticated request carries seventy hashes — seventy 67-byte quoted
/// hex hashes plus the JSON envelope and the pinned `/tx_info` flags stays
/// conservatively under 5 KiB. The daily/burst limits are a separate axis,
/// governed by the local egress budget ([`EgressLimits`]), not by this size.
pub const KOIOS_REGISTERED_CHUNK: usize = 70;

// ---------------------------------------------------------------------------
// Error classification
//
// A transport/status failure carries its class in the error type itself
// (`Error::ChainProviderClassified`), so the failover wrapper decides whether to
// fail over and whether to arm the cooldown from a typed value rather than by
// re-parsing a message. Keeping the class in the error (not a separate channel)
// means a `ChainGateway`'s `Result` alone carries everything a caller needs, and
// the trait surface stays unchanged.
// ---------------------------------------------------------------------------

/// The transport/status class of a chain-provider failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainErrorClass {
    /// A transport-level failure with no HTTP status: a timeout or a failed
    /// connection. Always transient.
    Transport,
    /// A response carrying a non-success HTTP status that is NOT a proven ledger
    /// rejection of a submitted body: a 5xx, a 425/429, or a provider-side 4xx
    /// such as a 401/403 auth/routing misconfig or a 404 routing error. All of
    /// these are transient and failover-eligible — a second provider can still
    /// serve the request or accept the body. A genuine ledger reject of a submit
    /// is the distinct [`ChainErrorClass::NodeReject`], never this.
    Http {
        /// The HTTP status code the provider returned.
        status: u16,
    },
    /// A DETERMINISTIC, never-accepted-by-any-node ledger rejection of a submitted
    /// transaction body: a `submit_tx` that returned a 400/422 whose body carries
    /// a node/ledger validation error (the providers include one on a real
    /// tx-reject). No node can ever accept this body, so it never fails over and
    /// the recorded attempt can be abandoned immediately. Produced ONLY by the
    /// submit paths after inspecting the error body, so a provider misconfig
    /// (401/403/404) or a transient status can never masquerade as a ledger reject.
    NodeReject {
        /// The HTTP status the node returned with the ledger validation error.
        status: u16,
    },
    /// A deterministic ledger rejection ([`Self::NodeReject`]) answered by the
    /// SECONDARY provider after the PRIMARY arm of the same failover call was
    /// attempted and failed transiently — that is, after an AMBIGUOUS wire
    /// contact with the very bytes being submitted (a timeout after send, a 5xx
    /// after processing). The rejection is real, but it cannot stand as the
    /// CALL's deterministic verdict: the primary may have delivered the bytes,
    /// and the secondary's reject may be the transaction conflicting with its
    /// own in-flight or already-landed copy. Classified TRANSIENT so the
    /// immediate abandon-and-refund can never ride it — the recorded attempt
    /// stays in flight and the resume path re-evaluates it under the
    /// absence-corroboration gate. Produced ONLY by [`FailoverGateway`]'s
    /// submit failover; a single provider's reject is always the plain
    /// [`Self::NodeReject`].
    NodeRejectAfterAmbiguousBroadcast {
        /// The HTTP status the secondary's node returned with the ledger
        /// validation error.
        status: u16,
    },
    /// A successful response whose body did not match the expected shape (a
    /// malformed hash, a missing field, undecodable JSON). Deterministic: a
    /// second provider would not be expected to fare differently for the same
    /// request, so it is non-transient and propagates.
    BadResponse,
    /// A successful, well-shaped response carrying a value that cannot exist on
    /// chain (a transaction-metadata byte string above the ledger's 64-byte
    /// cap). The provider is not relaying chain data — the corruption is in its
    /// rendering, not in the transaction — so a second provider IS expected to
    /// serve the true bytes: transient, failover-worthy, and never a verdict on
    /// the transaction itself.
    CorruptProvider,
}

impl ChainErrorClass {
    /// Whether this class warrants a failover to the secondary provider.
    ///
    /// Transient classes: a transport timeout or connect failure, a corrupt
    /// provider response (on-chain-impossible data only this provider's rendering
    /// can explain), and ANY non-success HTTP status that is not a proven ledger
    /// reject — including a 5xx, a 425/429, and a provider-side 4xx such as a
    /// 401/403 auth/routing misconfig or a 404 routing error: a second provider
    /// can still serve the request or accept the body, so the failover wrapper
    /// tries it rather than failing a well-formed transaction on a provider's
    /// configuration error. The only non-transient classes are a malformed
    /// response body ([`ChainErrorClass::BadResponse`]) and a proven ledger reject
    /// ([`ChainErrorClass::NodeReject`]), neither of which a second provider would
    /// answer differently.
    #[must_use]
    pub fn is_transient(self) -> bool {
        match self {
            // NodeRejectAfterAmbiguousBroadcast is transient BY DESIGN: the
            // reject followed an ambiguous wire contact within the same failover
            // call, so the call's verdict is "unresolved", never "deterministic";
            // treating it as transient keeps the recorded attempt in flight for
            // the corroborated resume path instead of an immediate refund.
            ChainErrorClass::Transport
            | ChainErrorClass::CorruptProvider
            | ChainErrorClass::Http { .. }
            | ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { .. } => true,
            ChainErrorClass::NodeReject { .. } | ChainErrorClass::BadResponse => false,
        }
    }

    /// Whether this class is specifically an HTTP 429 (the only class that arms
    /// the per-provider cooldown).
    #[must_use]
    pub fn is_rate_limited(self) -> bool {
        matches!(self, ChainErrorClass::Http { status: 429 })
    }
}

/// Build a classified chain-provider error carrying `class` in the type.
///
/// The failover wrapper and [`is_transient_chain_error`] read the class straight
/// off [`Error::ChainProviderClassified`]; the `detail` is the human-readable
/// description an operator sees in a log line.
#[must_use]
pub fn chain_error(class: ChainErrorClass, detail: impl std::fmt::Display) -> Error {
    Error::ChainProviderClassified {
        class,
        detail: detail.to_string(),
    }
}

/// Recover the [`ChainErrorClass`] of an error built by [`chain_error`].
///
/// Returns `None` for an error that carries no provider class (a database error
/// raised mid-call, or a raw [`Error::ChainProvider`]); such an error is treated
/// as non-transient by the callers below so it surfaces rather than masquerading
/// as a provider blip.
#[must_use]
pub fn classify_chain_error(error: &Error) -> Option<ChainErrorClass> {
    match error {
        Error::ChainProviderClassified { class, .. } => Some(*class),
        _ => None,
    }
}

/// Whether a chain-provider error is transient and should trigger a failover.
///
/// Transient classes: a transport timeout or connect failure, a corrupt provider
/// response, and ANY non-success HTTP status that is not a proven ledger reject —
/// a 5xx, a 425/429, and a provider-side 4xx (401/403 auth/routing misconfig, 404
/// routing error). A provider's configuration error must fail over to the
/// secondary, not fail a well-formed request. The only non-transient classes are a
/// malformed response body and a proven [`ChainErrorClass::NodeReject`], which a
/// second provider would answer identically. An error this module did not classify
/// (a database error mid-call) is treated as non-transient so it surfaces rather
/// than masquerading as a provider blip.
#[must_use]
pub fn is_transient_chain_error(error: &Error) -> bool {
    classify_chain_error(error).is_some_and(ChainErrorClass::is_transient)
}

/// Whether a failed `submit_tx` is a DETERMINISTIC PERMANENT node rejection: the
/// node refused the transaction body and no node could ever accept it, so the
/// recorded attempt can be abandoned immediately and its inputs restored without
/// waiting for a settlement-deep conflicting spend.
///
/// This is deliberately the ONE abandon path not gated on a confirmed conflicting
/// spend, so it must be drawn conservatively: it fires ONLY for a typed,
/// never-accepted-by-any-node rejection. The submit paths (Koios `/submittx`,
/// Blockfrost `/tx/submit`) inspect the error body and raise
/// [`ChainErrorClass::NodeReject`] only for a 400/422 carrying a node/ledger
/// validation error — the providers include one on a real tx-reject (an
/// invalid/expired/already-spent transaction). That, and only that, is a
/// deterministic reject.
///
/// Everything else is treated as TRANSIENT / AMBIGUOUS and never abandons:
/// - [`ChainErrorClass::Transport`] (a timeout or connection failure) — the
///   submit may or may not have reached a node; the input may already be on the
///   wire.
/// - [`ChainErrorClass::Http`] with ANY status — a 5xx, a 425/429, or a
///   provider-side 4xx (a 401/403 auth/routing misconfig, a 404 routing error):
///   the PROVIDER, not the ledger, declined; a retry or the secondary can still
///   land the recorded bytes. A misconfigured provider must never permanently
///   fail (and auto-refund) a well-formed transaction the other provider would
///   accept.
/// - [`ChainErrorClass::BadResponse`] — the provider accepted the submit but its
///   response body did not decode (a malformed hash, a missing field); the
///   transaction may well be in the mempool, so this is ambiguous, never a reject.
/// - [`ChainErrorClass::CorruptProvider`] — the provider served data that cannot
///   exist on chain; that is a verdict on the provider, never on the
///   transaction.
/// - [`ChainErrorClass::NodeRejectAfterAmbiguousBroadcast`] — the secondary DID
///   reject the body, but only after the failover's primary arm was attempted
///   and failed transiently: the bytes may already be on the wire via the
///   primary, so the reject may be the transaction conflicting with its own
///   in-flight or landed copy. Never an immediate abandon; the resume path
///   re-evaluates under the absence-corroboration gate.
/// - Any error this module did not classify (a database error raised mid-call, a
///   raw [`Error::ChainProvider`], a rate-limit storm) — unknown, so transient.
///
/// So only the explicit, body-confirmed [`ChainErrorClass::NodeReject`] reaches
/// the deterministic-reject verdict; every other failure is transient by
/// construction. Because [`FailoverGateway`] downgrades a secondary reject that
/// followed an attempted-and-failed primary arm, a plain NodeReject surfacing
/// from a failover submit additionally PROVES the reject was the outcome of the
/// bytes' only wire contact in that call.
#[must_use]
pub fn is_deterministic_node_reject(error: &Error) -> bool {
    matches!(
        classify_chain_error(error),
        Some(ChainErrorClass::NodeReject { .. })
    )
}

/// Map a `reqwest` transport error to a classified [`Error`].
///
/// A timeout or a connect failure is [`ChainErrorClass::Transport`] (transient);
/// any other transport error is also treated as transport-transient, since a
/// second provider is the right next move for a request that never produced a
/// status.
fn transport_error(detail: impl std::fmt::Display, err: &reqwest::Error) -> Error {
    chain_error(ChainErrorClass::Transport, format!("{detail}: {err}"))
}

/// Turn an HTTP status that is not a success into a classified [`Error`].
fn http_status_error(status: reqwest::StatusCode, detail: impl std::fmt::Display) -> Error {
    chain_error(
        ChainErrorClass::Http {
            status: status.as_u16(),
        },
        format!("{detail}: HTTP {}", status.as_u16()),
    )
}

/// Classify a failed `submit_tx` response from its status AND its body.
///
/// A genuine ledger rejection of the body returns a 400 (commonly) or 422 AND
/// carries a node/ledger validation error in the response body — both Koios
/// (`/submittx`) and Blockfrost (`/tx/submit`) relay the node's error text on a
/// real tx-reject. Only that combination is a [`ChainErrorClass::NodeReject`]: no
/// node can ever accept the body, so the recorded attempt may be abandoned at
/// once. Every other non-success status — a 5xx, a 425/429, a 401/403 auth or
/// routing misconfig, a 404 routing error, or a 400/422 with NO ledger error body
/// (an empty body, an HTML/proxy error page) — is a transient
/// [`ChainErrorClass::Http`] the failover wrapper retries on the secondary, so a
/// provider's misconfiguration can never permanently fail a well-formed
/// transaction.
fn submit_status_error(
    status: reqwest::StatusCode,
    body: &str,
    detail: impl std::fmt::Display,
) -> Error {
    let code = status.as_u16();
    if (code == 400 || code == 422) && body_carries_ledger_reject(body) {
        return chain_error(
            ChainErrorClass::NodeReject { status: code },
            format!("{detail}: node rejected the transaction (HTTP {code}): {body}"),
        );
    }
    chain_error(
        ChainErrorClass::Http { status: code },
        format!("{detail}: HTTP {code}: {body}"),
    )
}

/// Whether a failed-submit response body PROVES a Cardano ledger rejection of the
/// transaction, as opposed to a provider-side routing/auth/proxy error that merely
/// happens to carry a 400/422.
///
/// This is the safety-critical boundary behind the one immediate
/// abandon-with-refund path, so it demands PROVIDER-SPECIFIC, ledger-only markers
/// that only the node's own validation failure produces — never a generic JSON
/// envelope. The two providers relay a real reject verbatim from the node:
///
/// - **Koios `/submittx`** proxies `cardano-submit-api`, which returns the node's
///   structured submit-validation error as JSON tagged
///   `{"tag":"TxSubmitFail","contents":{"tag":"TxCmdTxSubmitValidationError",...
///   "ShelleyTxValidationError" ... "ApplyTxError" ...}}`.
/// - **Blockfrost `/tx/submit`** returns a string beginning `transaction submit
///   error ShelleyTxValidationError ... (ApplyTxError [...])`.
///
/// Both therefore carry one of a small set of node-only tokens (`ApplyTxError`,
/// `ShelleyTxValidationError`, `TxValidationErrorInCardanoMode`,
/// `TxCmdTxSubmitValidationError`, `TxSubmitFail`, `transaction submit error`).
/// A routing/auth/proxy 400 — `{"error":"Bad Request","message":"route not
/// found"}`, a Blockfrost `{"status_code":403,"error":"Forbidden",...}`, an HTML
/// error page, a bare `Bad Request` — carries NONE of these. Generic JSON keys
/// like `error`/`message` are deliberately NOT accepted: a misconfigured provider
/// returns them with a 400, and treating that as a ledger reject would permanently
/// fail and auto-refund a valid, never-broadcast transaction (the GC-2 hazard).
///
/// A 400/422 WITHOUT one of these markers is therefore left transient → failover.
/// When unsure, default to transient: a wrongly-retried invalid tx is cheap; a
/// wrongly-refunded valid tx is a money/UX bug.
fn body_carries_ledger_reject(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    // Node-only ledger-validation tokens. Each is produced ONLY by the Cardano
    // ledger's transaction-validation path (relayed verbatim by cardano-submit-api
    // / Blockfrost). None appears in a provider routing/auth/proxy error body.
    const LEDGER_REJECT_MARKERS: &[&str] = &[
        // The ledger's apply-transaction error wrapper (every era).
        "applytxerror",
        // cardano-submit-api / cardano-cli validation-error tags.
        "shelleytxvalidationerror",
        "txvalidationerrorincardanomode",
        "txcmdtxsubmitvalidationerror",
        "txsubmitfail",
        // Blockfrost's verbatim node-reject string prefix.
        "transaction submit error",
    ];
    LEDGER_REJECT_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// A malformed-but-successful response body: deterministic, non-transient.
fn bad_response(detail: impl std::fmt::Display) -> Error {
    chain_error(ChainErrorClass::BadResponse, detail)
}

/// A response carrying on-chain-impossible data: the provider is corrupt, so the
/// failure is transient (the secondary serves the true bytes) and is never a
/// verdict on the transaction it was reported for.
fn corrupt_provider(detail: impl std::fmt::Display) -> Error {
    chain_error(ChainErrorClass::CorruptProvider, detail)
}

/// Validate a 64-character lowercase hex transaction id and decode it to bytes.
fn parse_tx_hash_hex(raw: &str, provider: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim().trim_matches('"');
    let bytes = hex::decode(trimmed)
        .map_err(|_| bad_response(format!("{provider} returned a non-hex transaction id")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        bad_response(format!(
            "{provider} returned a transaction id of wrong length"
        ))
    })
}

/// Decode a 64-character hex hash (transaction or block) into a key the maps use.
fn hash_from_hex(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Convert an epoch-seconds value (a JSON number or numeric string) to a UTC
/// instant, or `None` when the value is absent or not a non-negative integer.
fn epoch_seconds_to_date(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let secs = match value {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }?;
    Utc.timestamp_opt(secs, 0).single()
}

// ---------------------------------------------------------------------------
// Koios gateway
// ---------------------------------------------------------------------------

/// The Koios chain gateway.
///
/// Mirrors [`super::params::KoiosParamsSource`]: a rustls reqwest client, a
/// per-network base URL, lenient numeric parsing, and the non-deprecated
/// Koios field names (`block_height`, never the removed `block_no`). Submit posts
/// binary CBOR to `/submittx`; confirmations are a two-step `/tx_status` then
/// `/tx_info` lookup so only on-chain hashes incur the heavier info call.
///
/// Addressed per the carried [`KoiosConfig`]: the public per-network URL and
/// no authentication by default; an operator base-URL override (a self-hosted
/// instance, or a test's local fake) and/or an API key sent as
/// `Authorization: Bearer` on every request when configured.
pub struct KoiosGateway {
    client: reqwest::Client,
    network: Network,
    /// How Koios is addressed: the optional base-URL override and the optional
    /// API key every request authenticates with.
    config: KoiosConfig,
    /// The egress gate every HTTP request is admitted through. A bare
    /// constructor attaches a budgeted in-memory gate so even a standalone
    /// instance cannot stampede the provider; the failover assembly swaps in
    /// the shared, Postgres-accounted gate via [`Self::with_egress`].
    egress: Arc<ProviderEgress>,
}

impl KoiosGateway {
    /// The default per-instance egress gate: budgeted at the default limits,
    /// counting in memory only.
    fn default_egress(network: Network) -> Arc<ProviderEgress> {
        Arc::new(ProviderEgress::budgeted_in_memory(
            ProviderKind::Koios,
            network,
            EgressLimits::default(),
        ))
    }

    /// Build a Koios gateway for a network with a sensible request timeout,
    /// addressed per `config` (`KoiosConfig::default()` is the keyless public
    /// tier).
    ///
    /// Returns [`Error::ChainProvider`] if the TLS-backed client cannot be built.
    pub fn new(network: Network, config: KoiosConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::ChainProvider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            client,
            network,
            config,
            egress: Self::default_egress(network),
        })
    }

    /// Build a Koios gateway over a caller-provided client (shared pooling, a
    /// custom timeout, or a behavioural test pointing `config.base_url` at a
    /// local fake server with no TLS or live endpoint — the same seam
    /// Blockfrost's [`BlockfrostGateway::with_client`] exposes).
    #[must_use]
    pub fn with_client(client: reqwest::Client, network: Network, config: KoiosConfig) -> Self {
        Self {
            client,
            network,
            config,
            egress: Self::default_egress(network),
        }
    }

    /// Replace the egress gate (the failover assembly attaches the shared,
    /// Postgres-accounted gate; a test attaches a tight or unlimited one).
    #[must_use]
    pub fn with_egress(mut self, egress: Arc<ProviderEgress>) -> Self {
        self.egress = egress;
        self
    }

    /// The network this gateway answers for.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The base URL for a path on this gateway's network (the override when set,
    /// else the network's public URL).
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url_for(self.network))
    }

    /// Attach the configured API key as `Authorization: Bearer` (reqwest marks
    /// the header sensitive so it never reaches a debug log). A keyless config
    /// leaves the request untouched.
    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.config.api_key.as_deref() {
            Some(key) => request.bearer_auth(key),
            None => request,
        }
    }

    /// How many transaction hashes one bulk POST body may carry: the keyed
    /// chunk under an API key (the registered tiers' ~5 KiB body cap), the
    /// keyless chunk otherwise (the public tier's ~1 KiB cap). A base-URL
    /// override without a key keeps the keyless size — the gateway cannot know
    /// what body cap a self-hosted instance enforces, and the smaller chunk is
    /// always accepted.
    fn tx_hash_chunk(&self) -> usize {
        if self.config.api_key.is_some() {
            KOIOS_REGISTERED_CHUNK
        } else {
            KOIOS_KEYLESS_CHUNK
        }
    }

    /// POST a JSON body to a Koios path and return the decoded array, or `None`
    /// when the whole batch is not on chain (a 404 for the chunk). Classifies
    /// transport and status failures so the failover wrapper can act on them.
    async fn post_json_rows(
        &self,
        path: &str,
        body: serde_json::Value,
        label: &str,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        self.egress.admit().await?;
        let url = self.url(path);
        let resp = self
            .authorize(self.client.post(&url).json(&body))
            .send()
            .await
            .map_err(|e| transport_error(format!("POST {url}"), &e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(http_status_error(
                resp.status(),
                format!("{label} POST {url}"),
            ));
        }
        let rows: Vec<serde_json::Value> = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("{label} returned malformed JSON: {e}")))?;
        Ok(Some(rows))
    }

    /// GET a Koios path and return the decoded array, or `None` when the whole
    /// query is not on chain (a 404). Classifies transport and status failures so
    /// the failover wrapper can act on them. The companion of [`Self::post_json_rows`]
    /// for the GET-shaped forward-scan list query.
    async fn post_or_get_rows(
        &self,
        path: &str,
        label: &str,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        self.egress.admit().await?;
        let url = self.url(path);
        let resp = self
            .authorize(
                self.client
                    .get(&url)
                    .header(reqwest::header::ACCEPT, "application/json"),
            )
            .send()
            .await
            .map_err(|e| transport_error(format!("GET {url}"), &e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(http_status_error(
                resp.status(),
                format!("{label} GET {url}"),
            ));
        }
        let rows: Vec<serde_json::Value> = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("{label} returned malformed JSON: {e}")))?;
        Ok(Some(rows))
    }
}

impl ChainGateway for KoiosGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.egress.admit().await?;
        let url = self.url("/submittx");
        let resp = self
            .authorize(
                self.client
                    .post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/cbor")
                    .body(signed_tx.to_vec()),
            )
            .send()
            .await
            .map_err(|e| transport_error(format!("POST {url}"), &e))?;
        if !resp.status().is_success() {
            // Read the error body so a genuine ledger reject (a 400/422 carrying a
            // node validation error) is classified as a deterministic NodeReject,
            // while a provider misconfig (401/403/404) or a transient status stays
            // failover-eligible and never permanently fails a well-formed tx.
            let status = resp.status();
            let body = read_diagnostic_body(resp).await;
            return Err(submit_status_error(
                status,
                &body,
                format!("submit POST {url}"),
            ));
        }
        let text = read_capped_text(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("submit response body was not text: {e}")))?;
        parse_tx_hash_hex(&text, "Koios /submittx")
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        if tx_hashes.is_empty() {
            return Ok(HashMap::new());
        }

        // First pass: /tx_status carries num_confirmations directly. Collect the
        // on-chain subset (>= 1 confirmation); a mempool-only row is dropped here
        // and answered by the not-on-chain sentinel the merge seeds.
        let mut conf_by_hash: HashMap<[u8; 32], u64> = HashMap::new();
        for chunk in tx_hashes.chunks(self.tx_hash_chunk()) {
            let body = serde_json::json!({ "_tx_hashes": hashes_to_hex(chunk) });
            let Some(rows) = self
                .post_json_rows("/tx_status", body, "Koios /tx_status")
                .await?
            else {
                continue; // Whole chunk not on chain; the sentinel already stands.
            };
            for (hash, num) in parse_koios_tx_status(&rows)? {
                conf_by_hash.insert(hash, num);
            }
        }

        if conf_by_hash.is_empty() {
            return Ok(tx_hashes
                .iter()
                .map(|h| (*h, TxConfirmation::not_on_chain()))
                .collect());
        }

        // Second pass: /tx_info for the on-chain subset, pinning every optional
        // flag to false so a future default flip never pulls fields we discard.
        let needing_info: Vec<[u8; 32]> = conf_by_hash.keys().copied().collect();
        let mut info_rows: Vec<serde_json::Value> = Vec::new();
        for chunk in needing_info.chunks(self.tx_hash_chunk()) {
            let body = serde_json::json!({
                "_tx_hashes": hashes_to_hex(chunk),
                "_inputs": false,
                "_metadata": false,
                "_assets": false,
                "_certs": false,
                "_scripts": false,
                "_withdrawals": false,
                "_bytecode": false,
            });
            if let Some(rows) = self
                .post_json_rows("/tx_info", body, "Koios /tx_info")
                .await?
            {
                info_rows.extend(rows);
            }
        }

        Ok(merge_koios_confirmations(
            tx_hashes,
            &conf_by_hash,
            &info_rows,
        ))
    }

    async fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        self.egress.admit().await?;
        let path =
            format!("/blocks?block_height=eq.{block_height}&select=hash,block_time,block_height");
        let url = self.url(&path);
        let resp = self
            .authorize(
                self.client
                    .get(&url)
                    .header(reqwest::header::ACCEPT, "application/json"),
            )
            .send()
            .await
            .map_err(|e| transport_error(format!("GET {url}"), &e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(http_status_error(
                resp.status(),
                format!("blocks GET {url}"),
            ));
        }
        let rows: Vec<serde_json::Value> = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("Koios /blocks returned malformed JSON: {e}")))?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let hash = row
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
            .ok_or_else(|| bad_response("Koios /blocks returned a malformed hash"))?;
        let block_time = row
            .get("block_time")
            .and_then(epoch_seconds_to_date)
            .ok_or_else(|| bad_response("Koios /blocks returned a malformed block_time"))?;
        let height = row
            .get("block_height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(block_height);
        Ok(Some(BlockInfo {
            block_height: height,
            block_hash: hash,
            block_time,
        }))
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        self.egress.admit().await?;
        let url = self.url("/tip");
        let resp = self
            .authorize(
                self.client
                    .get(&url)
                    .header(reqwest::header::ACCEPT, "application/json"),
            )
            .send()
            .await
            .map_err(|e| transport_error(format!("GET {url}"), &e))?;
        if !resp.status().is_success() {
            return Err(http_status_error(resp.status(), format!("tip GET {url}")));
        }
        let rows: Vec<serde_json::Value> = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("Koios /tip returned malformed JSON: {e}")))?;
        parse_koios_chain_tip(&rows)
    }

    async fn fetch_tx_cbor_by_hashes(&self, tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        let mut out: TxCborMap = HashMap::new();
        if tx_hashes.is_empty() {
            return Ok(out);
        }
        for chunk in tx_hashes.chunks(self.tx_hash_chunk()) {
            let body = serde_json::json!({ "_tx_hashes": hashes_to_hex(chunk) });
            let Some(rows) = self
                .post_json_rows("/tx_cbor", body, "Koios /tx_cbor")
                .await?
            else {
                continue; // Whole chunk not on chain; absent from the map.
            };
            for row in &rows {
                let Some(hash) = row.get("tx_hash").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(hash) = hash_from_hex(hash) else {
                    continue;
                };
                let Some(cbor_hex) = row.get("cbor").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if let Ok(cbor) = hex::decode(cbor_hex) {
                    out.insert(hash, cbor);
                }
            }
        }
        Ok(out)
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // Bulk-select every label-309 transaction above the cursor in one call,
        // ordered ascending by block height. This is the O(records) path: the provider
        // returns records by count, never by walking every block. Fetch ONE more than
        // the per-tick cap (`max_records + 1`) so the cursor cut can tell whether the
        // `max_records`-th block is complete or split (the extra row reveals whether
        // the boundary block continues), and never anchor the cursor mid-block. The
        // limit is additionally widened by the exclusion count: the already-consumed
        // part of a partially-scanned boundary block sorts at the front of the
        // response (its block is the lowest above the cursor), so without the widening
        // it could crowd every new row out and starve the window.
        let max_records = max_records as usize;
        let fetch_limit = max_records
            .saturating_add(exclude_tx_hashes.len())
            .saturating_add(1);
        let path = format!(
            "/tx_by_metalabel?_label={POE_METADATA_LABEL}&_after_block_height={after_block_height}\
             &order=block_height.asc&limit={fetch_limit}"
        );
        let rows = match self
            .post_or_get_rows(&path, "Koios /tx_by_metalabel")
            .await?
        {
            Some(rows) if !rows.is_empty() => rows,
            // No transactions above the cursor: caught up to the chain head. Koios
            // serves its list and its tip from the same dbsync, so its metadata
            // watermark is the tip it was given; the caller clamps to the tip.
            _ => {
                return Ok(Label309RecordsResult {
                    records: Vec::new(),
                    frontier: ScanFrontier::CaughtUpTo {
                        indexed_to: tip_block_height,
                    },
                })
            }
        };

        let page = parse_koios_metalabel_rows(&rows);
        // A row the parser could not decode is malformed provider data, not a
        // safely-ignorable foreign row: every `/tx_by_metalabel` row IS a label-309
        // transaction. Dropping it and advancing the cursor would permanently skip a
        // real on-chain record, so fail the tick as a retryable bad response. The
        // cursor does not move; failover/retry re-fetches the page, and the next pass
        // re-attempts from the same frontier.
        if page.dropped > 0 {
            return Err(bad_response(format!(
                "Koios /tx_by_metalabel returned {} unparseable row(s) of {}",
                page.dropped,
                rows.len()
            )));
        }
        // Drop the already-consumed transactions of a partially-scanned boundary
        // block. If EVERY listed row was excluded, the response was necessarily
        // shorter than the widened fetch limit (the exclusion set is strictly
        // smaller than it), so the provider proved it has nothing new above the
        // cursor: caught up.
        let listed: Vec<ListedTx> = if exclude_tx_hashes.is_empty() {
            page.listed
        } else {
            let exclude: std::collections::HashSet<[u8; 32]> =
                exclude_tx_hashes.iter().copied().collect();
            page.listed
                .into_iter()
                .filter(|t| !exclude.contains(&t.tx_hash))
                .collect()
        };
        if listed.is_empty() {
            // No well-formed un-consumed rows at all: caught up to the chain head,
            // clamped to the tip by the caller.
            return Ok(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::CaughtUpTo {
                    indexed_to: tip_block_height,
                },
            });
        }

        // Decide the block-aligned cutoff from the LISTED heights (which include any
        // row whose metadata later fails to hydrate), against the per-tick cap. Using
        // the listed heights — not the post-hydration records — keeps the cut from
        // landing inside a block that has an un-hydrated record (re-discovered next
        // tick). The `max_records + 1`th listed height reveals whether the boundary
        // block is complete or split.
        let listed_heights: Vec<u64> = listed.iter().map(|t| t.block_height).collect();
        let cutoff_height = match block_aligned_window(&listed_heights, max_records) {
            WindowCut::Keep { cutoff_height, .. } => cutoff_height,
            WindowCut::SingleBlockOverflow { block_height } => {
                // The boundary block alone carries more un-consumed label-309
                // transactions than one window: consume a page of it and report an
                // intra-block frontier so the scan progresses THROUGH the block
                // across ticks instead of stalling on it.
                return self
                    .fetch_intra_block_page(listed, block_height, max_records, tip_block_height)
                    .await;
            }
        };

        // Only the listed transactions inside the kept window are hydrated, so a
        // trimmed (split or surplus) trailing block is not fetched this tick.
        let kept: Vec<ListedTx> = match cutoff_height {
            Some(cut) => listed
                .into_iter()
                .filter(|t| t.block_height <= cut)
                .collect(),
            None => listed,
        };

        let (metadata_by_hash, observed_hashes) = self.hydrate_label309_metadata(&kept).await?;

        // Resolve the records AND the safe frontier from the kept listed
        // transactions and what actually came back. A listed tx whose `/tx_metadata`
        // row was NOT returned (cross-endpoint replica lag) is a HYDRATION GAP: the
        // resolver caps the frontier strictly below the earliest such gap so the
        // next tick re-fetches it. A listed tx whose row WAS returned but is a
        // non-carriage is a clean skip, never a gap. The window was kept whole (the
        // provider had no more records above the kept set up to its own tip) only
        // when the cap was not reached.
        let window_caught_up = cutoff_height.is_none();
        Ok(resolve_scan_frontier(
            &kept,
            &metadata_by_hash,
            &observed_hashes,
            tip_block_height,
            window_caught_up,
        ))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // A single Koios gateway has no alternate provider, so the alternate fetch
        // is the same fetch.
        self.fetch_label309_records_since(
            after_block_height,
            exclude_tx_hashes,
            tip_block_height,
            max_records,
        )
        .await
    }
}

impl KoiosGateway {
    /// Fetch the chunked metadata for the kept listed transactions in tier-sized
    /// chunks, then unwrap each label-309 entry's bstr-chunk array into the bare
    /// canonical record bytes the validator expects. Returns BOTH the carriage
    /// records (`metadata_by_hash`) AND every hash `/tx_metadata` returned a row
    /// for at all (`observed_hashes`) — the two differ for a listed tx whose row
    /// was returned but is genuinely not a chunk-array carriage (a verdict on the
    /// TRANSACTION, a clean skip), versus a listed tx whose row was NOT returned
    /// (a true hydration gap the cursor must not pass).
    async fn hydrate_label309_metadata(
        &self,
        kept: &[ListedTx],
    ) -> Result<(
        HashMap<[u8; 32], Vec<u8>>,
        std::collections::HashSet<[u8; 32]>,
    )> {
        let mut metadata_by_hash: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut observed_hashes: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        let hashes: Vec<[u8; 32]> = kept.iter().map(|t| t.tx_hash).collect();
        for chunk in hashes.chunks(self.tx_hash_chunk()) {
            let body = serde_json::json!({ "_tx_hashes": hashes_to_hex(chunk) });
            let Some(meta_rows) = self
                .post_json_rows("/tx_metadata", body, "Koios /tx_metadata")
                .await?
            else {
                continue;
            };
            for row in &meta_rows {
                // Record every row's tx hash as observed (the metadata WAS returned),
                // independent of whether it is a label-309 carriage.
                if let Some(hash) = row
                    .get("tx_hash")
                    .and_then(serde_json::Value::as_str)
                    .and_then(hash_from_hex)
                {
                    observed_hashes.insert(hash);
                }
                // A provider-impossible chunk propagates (`?`) and fails the
                // whole fetch, so the scan tick aborts with the cursor where it
                // was and the failover/retry path re-reads the page — the
                // cursor must never advance past a transaction the provider
                // mis-rendered. A row that is genuinely not a label-309
                // carriage resolves to `None`: a verdict on the transaction,
                // skipped (but its row WAS observed, so it is not a gap).
                if let Some((hash, cbor)) = parse_koios_metadata_row(row)? {
                    metadata_by_hash.insert(hash, cbor);
                }
            }
        }
        Ok((metadata_by_hash, observed_hashes))
    }

    /// Consume one page of a boundary block whose un-consumed label-309
    /// transaction count exceeds the per-tick cap.
    ///
    /// Takes up to `max_records` of the block's listed (exclusion-filtered)
    /// transactions — WHICH subset is irrelevant, because the caller's durable
    /// exclusion set makes the paging order-free — hydrates their metadata, and
    /// reports an [`ScanFrontier::IntraBlock`] frontier carrying the block's own
    /// hash plus the observed-non-carriage hashes so every consumed transaction
    /// joins the exclusion set. A transaction whose metadata row did not come
    /// back is left un-consumed (not excluded), so the next tick retries it; if
    /// NOTHING in the page hydrated there is no progress to record and the
    /// frontier holds (the scan's stuck-gap machinery takes over).
    async fn fetch_intra_block_page(
        &self,
        listed: Vec<ListedTx>,
        block_height: u64,
        max_records: usize,
        tip_block_height: u64,
    ) -> Result<Label309RecordsResult> {
        let kept: Vec<ListedTx> = listed
            .into_iter()
            .filter(|t| t.block_height == block_height)
            .take(max_records)
            .collect();
        let Some(block_hash) = kept.first().map(|t| t.block_hash) else {
            // Unreachable: an overflow verdict proves the block has listed rows.
            return Ok(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::Hold,
            });
        };

        let (metadata_by_hash, observed_hashes) = self.hydrate_label309_metadata(&kept).await?;

        let mut records = Vec::new();
        let mut consumed_no_record = Vec::new();
        for t in &kept {
            if let Some(metadata_cbor) = metadata_by_hash.get(&t.tx_hash) {
                records.push(Label309Record {
                    tx_hash: t.tx_hash,
                    block_hash: t.block_hash,
                    block_height: t.block_height,
                    block_time: t.block_time,
                    num_confirmations: tip_block_height.saturating_sub(t.block_height) + 1,
                    metadata_cbor: metadata_cbor.clone(),
                });
            } else if observed_hashes.contains(&t.tx_hash) {
                // Observed but not a chunk-array carriage: a verdict on the
                // transaction, consumed with nothing to index.
                consumed_no_record.push(t.tx_hash);
            }
            // Not observed at all: a hydration gap; leave it un-consumed so the
            // next tick (which will not exclude it) retries it.
        }

        if records.is_empty() && consumed_no_record.is_empty() {
            // Nothing in the page hydrated: no consumed transaction to record, so
            // there is no safe progress marker this tick.
            return Ok(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::Hold,
            });
        }
        Ok(Label309RecordsResult {
            records,
            frontier: ScanFrontier::IntraBlock {
                height: block_height,
                block_hash,
                consumed_no_record,
            },
        })
    }
}

/// Hex-encode a slice of 32-byte hashes for a Koios request body.
fn hashes_to_hex(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(hex::encode).collect()
}

/// Read the tip height and epoch from a Koios `/tip` response body.
///
/// The tip height is required (a numeric or quoted-string `block_height`, never
/// the removed deprecated `block_no`); the epoch (`epoch_no`, numeric or quoted)
/// is optional, so a row that omits it still yields a usable tip and the populate
/// loop's cold-start fallback covers the missing epoch.
///
/// Split out from the transport so the parse is testable against a committed
/// fixture with no network.
pub fn parse_koios_chain_tip(rows: &[serde_json::Value]) -> Result<ChainTip> {
    let row = rows
        .first()
        .ok_or_else(|| bad_response("Koios /tip returned no rows"))?;
    let block_height = match row.get("block_height") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| bad_response("Koios /tip block_height is not a u64"))?,
        Some(serde_json::Value::String(s)) => s
            .parse::<u64>()
            .map_err(|_| bad_response("Koios /tip block_height string is not a u64"))?,
        _ => return Err(bad_response("Koios /tip is missing block_height")),
    };
    let epoch = parse_optional_u64(row.get("epoch_no"));
    Ok(ChainTip {
        block_height,
        epoch,
    })
}

/// Read an optional `u64` from a JSON value that a provider may encode as a
/// number or a quoted string, returning `None` for an absent, null, or
/// unparseable value (an optional field never fails the parse).
fn parse_optional_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.parse::<u64>().ok(),
        _ => None,
    }
}

/// Parse a Koios `/tx_status` response body into the `(hash, num_confirmations)`
/// pairs the confirmation lookup builds on, ignoring mempool-only rows.
///
/// Split out from the transport so the on-chain/in-mempool classification is
/// testable against a committed fixture with no network.
pub fn parse_koios_tx_status(rows: &[serde_json::Value]) -> Result<Vec<([u8; 32], u64)>> {
    let mut out = Vec::new();
    for row in rows {
        let Some(hash) = row
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
        else {
            continue;
        };
        let num = match row.get("num_confirmations") {
            None | Some(serde_json::Value::Null) => continue,
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            Some(serde_json::Value::String(s)) => s.parse::<u64>().ok(),
            Some(_) => {
                return Err(bad_response(
                    "Koios /tx_status num_confirmations is not numeric",
                ))
            }
        };
        let num =
            num.ok_or_else(|| bad_response("Koios /tx_status num_confirmations is not numeric"))?;
        if num >= 1 {
            out.push((hash, num));
        }
    }
    Ok(out)
}

/// Merge the two Koios confirmation passes into the answer map.
///
/// Seeds every requested hash with the not-on-chain sentinel and hydrates the
/// on-chain subset's coordinates from the `/tx_info` rows. The result answers
/// every requested hash, never omits one.
///
/// A confirmation is reported ONLY when `/tx_info` supplied a real block height:
/// a positive `num_confirmations` is meaningless without coordinates and must
/// never co-exist with a `None` height. A hash that `/tx_status` counted as
/// confirmed but `/tx_info` could not hydrate with complete coordinates
/// (cross-endpoint replica lag, a truncated response, or a rollback race
/// mid-poll) therefore keeps the not-on-chain NUMERIC shape — the confirm
/// authority waits for a complete lookup rather than settling a record at a
/// fabricated height 0 — but is marked [`TxConfirmation::inconclusive`], not
/// absent: `/tx_status` positively saw it, so a money decision (the submit
/// path's abandon-and-refund gate) must not read the lag window as proof the
/// transaction does not exist.
///
/// Split out from the transport so the full two-step behaviour, including the
/// incomplete-`/tx_info` case, is testable against committed fixtures with no
/// HTTP.
#[must_use]
pub fn merge_koios_confirmations(
    requested: &[[u8; 32]],
    conf_by_hash: &HashMap<[u8; 32], u64>,
    info_rows: &[serde_json::Value],
) -> TxConfirmationMap {
    let mut out: TxConfirmationMap = requested
        .iter()
        .map(|h| (*h, TxConfirmation::not_on_chain()))
        .collect();

    for row in info_rows {
        let Some(hash) = row
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
        else {
            continue;
        };
        let Some(&num) = conf_by_hash.get(&hash) else {
            continue;
        };
        // A confirmation must carry BOTH real coordinates: a row missing either the
        // block height or the block time is an incomplete observation, not an on-chain
        // one, and stays the not-on-chain sentinel (the seed) so a partially-hydrated
        // response can never manufacture a fabricated coordinate downstream. The
        // height is read leniently (a number OR a quoted-string integer) because some
        // Koios deployments quote even numeric fields; reading it strictly would skip a
        // legitimately confirmed tx on such a deployment. The time goes through the
        // same lenient epoch parse.
        let Some(block_height) = parse_optional_u64(row.get("block_height")) else {
            continue;
        };
        let Some(block_time) = row.get("tx_timestamp").and_then(epoch_seconds_to_date) else {
            continue;
        };
        out.insert(
            hash,
            TxConfirmation::on_chain(num, block_height, block_time),
        );
    }

    // Every hash `/tx_status` counted that the loop above could not hydrate with
    // complete coordinates (no `/tx_info` row, or a row missing the height or
    // the time) is a positive-but-incomplete observation, NOT affirmative
    // absence. Mark it inconclusive: the numeric shape stays the not-on-chain
    // sentinel (the confirm authority's behaviour is unchanged), but the
    // presence verdict stops a refund from riding a provider-lag window.
    for hash in conf_by_hash.keys() {
        if let Some(entry) = out.get_mut(hash) {
            if entry.block_height.is_none() {
                *entry = TxConfirmation::inconclusive();
            }
        }
    }

    out
}

/// One transaction the forward-scan list query returned, before its metadata is
/// hydrated: the coordinates, kept separate so the metadata fetch and the final
/// assembly stay testable against committed fixtures with no HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedTx {
    /// 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// 32-byte block hash.
    pub block_hash: [u8; 32],
    /// The block height the transaction landed in.
    pub block_height: u64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
}

/// The outcome of parsing a Koios `/tx_by_metalabel` page: the well-formed
/// transactions plus a count of rows that could not be parsed.
///
/// Every row a metalabel query returns IS a label-309 transaction by
/// construction (the query filters on the label), so a row whose coordinates do
/// not parse is malformed provider data, not a safely-ignorable foreign row. The
/// scan must not silently drop it and advance the cursor past a real on-chain
/// record, so the count is surfaced to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetalabelPage {
    /// The well-formed transactions, in the order the provider returned them.
    pub listed: Vec<ListedTx>,
    /// How many rows could not be parsed (a malformed hash, block hash, height,
    /// or timestamp). A non-zero count fails the scan tick rather than skipping.
    pub dropped: usize,
}

/// Parse a Koios `/tx_by_metalabel` response body into the listed transactions
/// the forward scan hydrates, counting any row whose hash, block hash, height,
/// or timestamp does not parse.
///
/// `block_height` is read leniently as a number OR a quoted-string integer,
/// because some Koios deployments render even numeric fields as quoted strings;
/// reading it strictly would drop every row on such a deployment.
///
/// Split out from the transport so the list parse is testable against a committed
/// fixture with no network.
#[must_use]
pub fn parse_koios_metalabel_rows(rows: &[serde_json::Value]) -> MetalabelPage {
    let mut listed = Vec::new();
    let mut dropped = 0usize;
    for row in rows {
        let Some(tx_hash) = row
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
        else {
            dropped += 1;
            continue;
        };
        let Some(block_hash) = row
            .get("block_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
        else {
            dropped += 1;
            continue;
        };
        let Some(block_height) = parse_optional_u64(row.get("block_height")) else {
            dropped += 1;
            continue;
        };
        let Some(block_time) = row.get("tx_timestamp").and_then(epoch_seconds_to_date) else {
            dropped += 1;
            continue;
        };
        listed.push(ListedTx {
            tx_hash,
            block_hash,
            block_height,
            block_time,
        });
    }
    MetalabelPage { listed, dropped }
}

/// Parse one Koios `/tx_metadata` row into a `(tx_hash, unwrapped_record_bytes)`
/// pair.
///
/// The on-chain label-309 metadatum is a CBOR array of byte-string chunks (each
/// <= 64 bytes); Koios renders it as a JSON array of `"0x<hex>"` strings.
/// Concatenating the decoded chunks recovers the bare canonical record bytes the
/// validator expects.
///
/// `Ok(None)` is a verdict on the TRANSACTION: the row carries no label-309
/// entry, or the entry is genuinely not the chunk-array carriage (shapes that
/// can exist on chain), so the caller skips it. An error is a verdict on the
/// PROVIDER: a chunk no chain could carry (see `label309_chunks_from_json`),
/// which must fail the fetch — never skip the transaction — so the scan
/// cursor cannot advance past a mis-rendered record.
pub fn parse_koios_metadata_row(row: &serde_json::Value) -> Result<Option<([u8; 32], Vec<u8>)>> {
    let Some(tx_hash) = row
        .get("tx_hash")
        .and_then(serde_json::Value::as_str)
        .and_then(hash_from_hex)
    else {
        return Ok(None);
    };
    let Some(label_entry) = row
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(&POE_METADATA_LABEL.to_string()))
    else {
        return Ok(None);
    };
    Ok(label309_chunks_from_json(label_entry)?.map(|cbor| (tx_hash, cbor)))
}

/// Concatenate a Koios-rendered label-309 chunk array (`["0x<hex>", ...]`) into
/// the bare record bytes.
///
/// `Ok(None)` when the value is not an array of hex-string chunks. Such a value
/// (a map, a number, a text chunk) can genuinely exist on chain under label
/// 309, so it is a verdict on the transaction and the caller skips it. An error
/// when a chunk decodes past the ledger's 64-byte metadata-string cap: no
/// rendering of legitimate chain data can exceed it (on-chain text values cap
/// at 64 characters and byte values at 64 bytes), so an oversized chunk means
/// the provider response is corrupt — a provider-level failure, never a verdict
/// on the transaction.
fn label309_chunks_from_json(value: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    let Some(chunks) = value.as_array() else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for chunk in chunks {
        let Some(hex_str) = chunk.as_str() else {
            return Ok(None);
        };
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let Ok(bytes) = hex::decode(hex_str) else {
            return Ok(None);
        };
        if bytes.len() > METADATA_CHUNK_CAP {
            return Err(corrupt_provider(format!(
                "Koios rendered a {}-byte label-309 metadata chunk; the ledger caps \
                 metadata strings at {METADATA_CHUNK_CAP} bytes, so this response is \
                 not chain data",
                bytes.len()
            )));
        }
        out.extend_from_slice(&bytes);
    }
    Ok(Some(out))
}

/// Unwrap the on-chain label-309 metadatum CBOR into the bare canonical record
/// bytes.
///
/// Blockfrost's `/metadata/txs/labels/{label}/cbor` endpoint returns the whole
/// transaction-metadata map for the label as hex, i.e. `{309: [chunk, ...]}`, not
/// the bare chunk array Koios's JSON `/tx_metadata` already digs out from under
/// the `309` key. So this accepts either shape: a top-level map keyed by 309 (the
/// live Blockfrost form, whose `309` value is the chunk array) or the bare chunk
/// array itself. Either way it concatenates the byte-string chunks into the
/// canonical record bytes the validator expects, so both providers feed the
/// validator byte-identical input.
///
/// The transport rules are enforced here, with the two failure directions kept
/// apart. `Ok(None)` is a verdict on the TRANSACTION: the value is not a
/// chunk-array carriage (not an array, a non-byte-string element) — shapes that
/// can genuinely exist on chain under label 309 — so the caller skips it. An
/// error is a verdict on the PROVIDER: a byte-string chunk above the ledger's
/// 64-byte metadata-string cap cannot exist on chain, so a response carrying
/// one is corrupt and must fail the fetch rather than skip the transaction.
/// Zero-length chunks are tolerated (chunk boundaries are semantics-free).
/// Definiteness of the provider's re-serialised length encodings is not
/// distinguished by the permissive decode; the reassembled body is then
/// strictly validated before anything is indexed, so a non-canonical body never
/// enters the index.
pub fn unwrap_label309_chunked_metadatum(metadatum_cbor: &[u8]) -> Result<Option<Vec<u8>>> {
    use cardanowall::cbor::PermissiveValue;
    let Ok(value) = cardanowall::cbor::decode_cbor_permissive(metadatum_cbor) else {
        return Ok(None);
    };
    // Peel a `{309: <chunks>}` metadata-map wrapper when present, otherwise take
    // the value as the chunk array directly.
    let chunks = match value {
        PermissiveValue::Map(pairs) => {
            let Some(label) = pairs.into_iter().find_map(|(key, val)| match key {
                PermissiveValue::Unsigned(label) if label == POE_METADATA_LABEL => Some(val),
                _ => None,
            }) else {
                return Ok(None);
            };
            match label {
                PermissiveValue::Array(chunks) => chunks,
                _ => return Ok(None),
            }
        }
        PermissiveValue::Array(chunks) => chunks,
        _ => return Ok(None),
    };
    let mut out = Vec::new();
    for chunk in chunks {
        let PermissiveValue::Bytes(bytes) = chunk else {
            return Ok(None);
        };
        if bytes.len() > METADATA_CHUNK_CAP {
            return Err(corrupt_provider(format!(
                "label-309 metadatum carries a {}-byte chunk; the ledger caps \
                 metadata strings at {METADATA_CHUNK_CAP} bytes, so this response \
                 is not chain data",
                bytes.len()
            )));
        }
        out.extend_from_slice(&bytes);
    }
    Ok(Some(out))
}

/// The ledger's cap on a single transaction-metadata byte string. A label-309
/// transport chunk above it cannot appear on chain, so the unwrap rejects it.
const METADATA_CHUNK_CAP: usize = 64;

/// Resolve the forward-scan records AND the safe frontier the cursor may advance
/// to, given the kept listed transactions (block-aligned, ascending by height),
/// the carriage records that hydrated (`metadata_by_hash`), every hash the
/// metadata fetch returned a row for AT ALL (`observed_hashes`), the tip the call
/// was given, and whether the window was kept whole (the provider had no more
/// records above it up to its own tip).
///
/// A listed transaction whose metadata row was NOT returned is a HYDRATION GAP:
/// the list query proved a label-309 record exists at that height, but its bytes
/// are not yet readable (cross-endpoint replica lag, a truncated metadata
/// response). The cursor must never advance past such a gap, because the next tick
/// fetches strictly above the cursor and would never re-discover it. So the
/// frontier is capped strictly below the EARLIEST gap: the cursor anchors at the
/// highest fully-resolved block below the gap, or HOLDS when the gap is at or below
/// the lowest kept block. Records at or above the earliest gap are NOT emitted this
/// fetch — they are re-discovered (and emitted) once they hydrate.
///
/// A listed transaction whose row WAS returned but is genuinely not a chunk-array
/// carriage (a non-carriage metadatum, valid on chain) is NOT a gap: it is a clean
/// skip (a verdict on the transaction). It produces no record but its block is
/// fully resolved, so the frontier may safely advance past it.
///
/// With no gap the frontier is:
/// - `Anchor` at the highest resolved block when the window was capped (more
///   records exist above it), so the next tick resumes strictly above it; or
/// - `CaughtUpTo` the provider's own tip when the window was kept whole, so the
///   caller jumps the cursor to `min(tip, indexed_to)` and a provider lagging the
///   other provider's tip can never drive the cursor past its own watermark.
///
/// Split out from the transport so the gap/cap/caught-up frontier decision is
/// testable against committed fixtures with no HTTP.
#[must_use]
pub fn resolve_scan_frontier(
    listed: &[ListedTx],
    metadata_by_hash: &HashMap<[u8; 32], Vec<u8>>,
    observed_hashes: &std::collections::HashSet<[u8; 32]>,
    tip_block_height: u64,
    window_caught_up: bool,
) -> Label309RecordsResult {
    // The earliest listed block height whose metadata row was NOT returned. A row
    // that WAS returned but is a non-carriage is observed (not a gap). The list is
    // ascending by block height, so the first un-observed tx is the earliest gap.
    let earliest_gap = listed
        .iter()
        .find(|t| !observed_hashes.contains(&t.tx_hash))
        .map(|t| t.block_height);

    // Emit the carriage records strictly below the earliest gap (or all, with no
    // gap), each with a tip-derived confirmation count. Track the highest
    // fully-resolved block — carriage OR non-carriage — so a capped or gap-clamped
    // window can anchor on a real hash even when the boundary block carried only a
    // non-carriage transaction.
    let mut records = Vec::new();
    let mut highest_complete: Option<(u64, [u8; 32])> = None;
    for t in listed {
        if earliest_gap.is_some_and(|gap| t.block_height >= gap) {
            // At or above the earliest gap: not safe to cross, so neither emitted
            // nor allowed to anchor the frontier. The list is ascending, so every
            // later transaction is also at or above the gap.
            break;
        }
        // This transaction's block is fully resolved (its row was observed), so the
        // frontier may anchor at it whether or not it is a carriage record.
        highest_complete = Some((t.block_height, t.block_hash));
        let Some(metadata_cbor) = metadata_by_hash.get(&t.tx_hash) else {
            // Observed but a non-carriage: a clean skip, no record, but safe to pass.
            continue;
        };
        records.push(Label309Record {
            tx_hash: t.tx_hash,
            block_hash: t.block_hash,
            block_height: t.block_height,
            block_time: t.block_time,
            num_confirmations: tip_block_height.saturating_sub(t.block_height) + 1,
            metadata_cbor: metadata_cbor.clone(),
        });
    }

    let frontier = match earliest_gap {
        // A hydration gap (whether the window was capped or whole): anchor strictly
        // below it so the gap is re-fetched next tick. With nothing below the gap
        // hydrated there is no safe height, so the cursor HOLDS where it was.
        Some(_) => match highest_complete {
            Some((height, block_hash)) => ScanFrontier::Anchor { height, block_hash },
            None => ScanFrontier::Hold,
        },
        None => match highest_complete {
            // No gap, window capped: anchor at the highest kept block (more records
            // exist above it), so the next tick resumes strictly above it.
            Some((height, block_hash)) if !window_caught_up => {
                ScanFrontier::Anchor { height, block_hash }
            }
            // No gap, window kept whole (or a degenerate empty capped window): the
            // provider is caught up to its own tip; the caller clamps to the tip.
            _ => ScanFrontier::CaughtUpTo {
                indexed_to: tip_block_height,
            },
        },
    };

    Label309RecordsResult { records, frontier }
}

// ---------------------------------------------------------------------------
// Blockfrost gateway
// ---------------------------------------------------------------------------

/// The Blockfrost label-metadata page size. Blockfrost paginates this endpoint at
/// 100 rows per page; a short page is the last page.
pub const BLOCKFROST_SCAN_PAGE_SIZE: usize = 100;

/// The ceiling on pages a single forward-scan fetch walks on Blockfrost, so one
/// tick cannot page through unbounded history; the caller re-enqueues to resume.
pub const BLOCKFROST_MAX_SCAN_PAGES: usize = 50;

/// A transaction's block coordinates hydrated from a Blockfrost `/txs/{hash}` row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockfrostTxCoords {
    block_height: u64,
    block_hash: [u8; 32],
    block_time: DateTime<Utc>,
}

/// Parse one Blockfrost `/metadata/txs/labels/{label}/cbor` row into a
/// `(tx_hash, metadatum_cbor)` pair, or `None` when the row carries no usable
/// hash or metadata.
///
/// Prefers the non-deprecated `metadata` field (plain hex); falls back to the
/// deprecated `cbor_metadata` (which may carry a `\x` Postgres-bytea prefix) only
/// when the new field is absent. Split out from the transport so the row parse is
/// testable against a committed fixture with no HTTP.
#[must_use]
pub fn parse_blockfrost_label_row(row: &serde_json::Value) -> Option<([u8; 32], Vec<u8>)> {
    let tx_hash = row
        .get("tx_hash")
        .and_then(serde_json::Value::as_str)
        .and_then(hash_from_hex)?;
    let metadata_hex = match row.get("metadata").and_then(serde_json::Value::as_str) {
        Some(hex_str) => hex_str.to_string(),
        None => {
            let deprecated = row
                .get("cbor_metadata")
                .and_then(serde_json::Value::as_str)?;
            deprecated
                .strip_prefix("\\x")
                .unwrap_or(deprecated)
                .to_string()
        }
    };
    if metadata_hex.is_empty() {
        return None;
    }
    let metadatum_cbor = hex::decode(&metadata_hex).ok()?;
    Some((tx_hash, metadatum_cbor))
}

/// The Blockfrost base URL for a network, used when a project id is configured so
/// the secondary actually answers rather than being a second Koios instance.
#[must_use]
pub fn blockfrost_base_url(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "https://cardano-mainnet.blockfrost.io/api/v0",
        Network::Preprod => "https://cardano-preprod.blockfrost.io/api/v0",
        Network::Preview => "https://cardano-preview.blockfrost.io/api/v0",
    }
}

/// The project-id-authenticated Blockfrost gateway, the configured secondary.
///
/// Blockfrost has no batch confirmation endpoint, so [`Self::get_tx_confirmations`]
/// fetches per hash and reads the tip once per batch (every confirmation count
/// derives from the same tip). The project id is held as decrypted-at-rest
/// material the constructor was handed from a configured file path; it is never
/// hardcoded and never logged.
pub struct BlockfrostGateway {
    client: reqwest::Client,
    network: Network,
    base_url: String,
    /// The project id, a deploy-time secret wiped on drop.
    project_id: Zeroizing<String>,
    /// The egress gate every HTTP request is admitted through. A bare
    /// constructor attaches a budgeted in-memory gate; the failover assembly
    /// swaps in the shared, Postgres-accounted gate via [`Self::with_egress`].
    egress: Arc<ProviderEgress>,
}

impl BlockfrostGateway {
    /// The default per-instance egress gate: budgeted at the default limits,
    /// counting in memory only.
    fn default_egress(network: Network) -> Arc<ProviderEgress> {
        Arc::new(ProviderEgress::budgeted_in_memory(
            ProviderKind::Blockfrost,
            network,
            EgressLimits::default(),
        ))
    }

    /// Build a Blockfrost gateway for a network from a project id, with a
    /// sensible request timeout.
    ///
    /// Returns [`Error::ChainProvider`] if the TLS-backed client cannot be built.
    /// The project id is supplied by the caller (read from a configured file
    /// path), never embedded here.
    pub fn new(network: Network, project_id: Zeroizing<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::ChainProvider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            client,
            network,
            base_url: blockfrost_base_url(network).to_string(),
            project_id,
            egress: Self::default_egress(network),
        })
    }

    /// Build a Blockfrost gateway over a caller-provided client and base URL (the
    /// test seam for pointing at a local fake without TLS or a real endpoint).
    #[must_use]
    pub fn with_client(
        client: reqwest::Client,
        network: Network,
        base_url: String,
        project_id: Zeroizing<String>,
    ) -> Self {
        Self {
            client,
            network,
            base_url,
            project_id,
            egress: Self::default_egress(network),
        }
    }

    /// Replace the egress gate (the failover assembly attaches the shared,
    /// Postgres-accounted gate; a test attaches a tight or unlimited one).
    #[must_use]
    pub fn with_egress(mut self, egress: Arc<ProviderEgress>) -> Self {
        self.egress = egress;
        self
    }

    /// The network this gateway answers for.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// GET a Blockfrost path, returning the decoded JSON body or `None` on a 404.
    async fn get_json(&self, path: &str, label: &str) -> Result<Option<serde_json::Value>> {
        self.egress.admit().await?;
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("project_id", self.project_id.as_str())
            .send()
            .await
            .map_err(|e| transport_error(format!("GET {url}"), &e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(http_status_error(
                resp.status(),
                format!("{label} GET {url}"),
            ));
        }
        let body: serde_json::Value = read_capped_json(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("{label} returned malformed JSON: {e}")))?;
        Ok(Some(body))
    }
}

impl ChainGateway for BlockfrostGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.egress.admit().await?;
        let url = format!("{}/tx/submit", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .header("project_id", self.project_id.as_str())
            .body(signed_tx.to_vec())
            .send()
            .await
            .map_err(|e| transport_error(format!("POST {url}"), &e))?;
        if !resp.status().is_success() {
            // Read the error body so a genuine ledger reject (a 400/422 carrying a
            // node validation error) is classified as a deterministic NodeReject,
            // while a provider misconfig (401/403/404) or a transient status stays
            // failover-eligible and never permanently fails a well-formed tx.
            let status = resp.status();
            let body = read_diagnostic_body(resp).await;
            return Err(submit_status_error(
                status,
                &body,
                format!("submit POST {url}"),
            ));
        }
        let text = read_capped_text(resp, JSON_BODY_CEILING)
            .await
            .map_err(|e| bad_response(format!("submit response body was not text: {e}")))?;
        parse_tx_hash_hex(&text, "Blockfrost /tx/submit")
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        let mut out: TxConfirmationMap = tx_hashes
            .iter()
            .map(|h| (*h, TxConfirmation::not_on_chain()))
            .collect();
        if tx_hashes.is_empty() {
            return Ok(out);
        }
        // Every confirmation count is (tip observed now) - block_height + 1, so
        // the tip is fetched at most once per batch, lazily, only when at least
        // one hash is on chain.
        let mut tip: Option<u64> = None;
        for hash in tx_hashes {
            let hex = hex::encode(hash);
            let Some(body) = self
                .get_json(&format!("/txs/{hex}"), "Blockfrost /txs")
                .await?
            else {
                // A 404 is Blockfrost's AFFIRMATIVE "no such transaction": the
                // absent sentinel stands.
                continue;
            };
            // A confirmation requires BOTH a real height AND a real block time: a
            // found row missing either is an incomplete observation (the tx is not
            // yet in a block, or the row is partially hydrated). It must not
            // confirm — confirming on a height with no time would synthesize a
            // now() block time downstream and write a fabricated on-chain
            // coordinate — but the transaction row EXISTS, so it is marked
            // inconclusive, never affirmatively absent.
            let block_height = body.get("block_height").and_then(serde_json::Value::as_u64);
            let block_time = body.get("block_time").and_then(epoch_seconds_to_date);
            let (Some(block_height), Some(block_time)) = (block_height, block_time) else {
                out.insert(*hash, TxConfirmation::inconclusive());
                continue;
            };
            let tip_height = match tip {
                Some(t) => t,
                None => {
                    let t = self.fetch_tip().await?;
                    tip = Some(t);
                    t
                }
            };
            let num = tip_height.saturating_sub(block_height) + 1;
            out.insert(
                *hash,
                TxConfirmation::on_chain(num, block_height, block_time),
            );
        }
        Ok(out)
    }

    async fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        let Some(body) = self
            .get_json(&format!("/blocks/{block_height}"), "Blockfrost /blocks")
            .await?
        else {
            return Ok(None);
        };
        let hash = body
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex)
            .ok_or_else(|| bad_response("Blockfrost /blocks returned a malformed hash"))?;
        let block_time = body
            .get("time")
            .and_then(epoch_seconds_to_date)
            .ok_or_else(|| bad_response("Blockfrost /blocks is missing time"))?;
        let height = body
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(block_height);
        Ok(Some(BlockInfo {
            block_height: height,
            block_hash: hash,
            block_time,
        }))
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        self.fetch_chain_tip().await
    }

    async fn fetch_tx_cbor_by_hashes(&self, tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        let mut out: TxCborMap = HashMap::new();
        for hash in tx_hashes {
            let hex = hex::encode(hash);
            let Some(body) = self
                .get_json(&format!("/txs/{hex}/cbor"), "Blockfrost /txs/cbor")
                .await?
            else {
                continue;
            };
            if let Some(cbor_hex) = body.get("cbor").and_then(serde_json::Value::as_str) {
                if let Ok(cbor) = hex::decode(cbor_hex) {
                    out.insert(*hash, cbor);
                }
            }
        }
        Ok(out)
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // Blockfrost paginates label metadata newest-first and has no
        // block-height filter. The cursor advances by ascending block height, so a
        // capped tick must leave the cursor at the BOTTOM of the consumed window
        // (the oldest record above the cursor), never the top. Page descending all
        // the way down to the cursor boundary, accumulate every record above it,
        // then sort ascending and keep only the oldest `max_records` so the cursor
        // anchors at that window's top and the next tick resumes immediately above
        // it. This mirrors the Koios ascending-window semantics and guarantees no
        // record between the cursor and the window bottom is ever skipped.
        //
        // Two hazards a naive "jump to the given tip when paged out" path gets
        // wrong, both fixed here:
        //
        // - Blockfrost's metadata index can LAG the tip the caller observed from
        //   the other provider. The given `tip_block_height` is NOT Blockfrost's
        //   own watermark, so the caught-up frontier clamps to the highest block
        //   Blockfrost actually rendered a hydrated record for — never the given
        //   tip — or the cursor leaps over the lag gap and never re-reads it.
        // - A listed row whose coordinates do not hydrate (`Ok(None)`: still in
        //   mempool, or a partial row) or whose label row does not parse is a
        //   hydration gap at an unknown height, bounded below by the NEXT
        //   fully-hydrated row in the descending stream (which may share the
        //   gap's block, so that row itself is not safe either). The frontier
        //   stays strictly below every such bound — and no caught-up form ever
        //   fires while a gap exists — so the next tick re-reads the gap instead
        //   of the cursor skipping past it.
        let exclude: std::collections::HashSet<[u8; 32]> =
            exclude_tx_hashes.iter().copied().collect();
        let mut records: Vec<Label309Record> = Vec::new();
        // Transactions that hydrated fully but carry no chunk-array record (a
        // verdict on the transaction, nothing to index), as `(block_height,
        // tx_hash, block_hash)`. They are RESOLVED points the frontier may pass —
        // an intra-block page reports the boundary block's share of them as
        // consumed, and a window whose only label-309 transactions are
        // non-carriage still advances past them (never holds forever) exactly as
        // the Koios path does.
        let mut non_carriage: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
        // Whether the walk saw any already-consumed (excluded) row: proof the
        // provider's index covers the partially-scanned boundary block, which lets
        // an otherwise-empty, GAP-FREE walk report caught-up-to-that-block instead
        // of a hold.
        let mut saw_excluded = false;
        // Whether ANY hydration gap was observed this fetch (a label row that did
        // not parse, or whose coordinates did not hydrate). Authoritative for the
        // frontier decision: no caught-up form — neither the watermark jump nor
        // the boundary-block completion — may ever fire while a gap exists,
        // because completing past an un-hydrated transaction skips it forever.
        // Deliberately a standalone flag, NEVER derived from the height bound
        // below: a gap seen while nothing has hydrated yet leaves the bound
        // untouched, and deriving "has a gap" from it would silently drop
        // exactly that case.
        let mut saw_gap = false;
        // A gap whose lower bound is not yet known. A gap's height is unknown but
        // is AT LEAST the next fully-hydrated row's height (the descending walk
        // means every later row is at or below it), so the NEXT hydrated row —
        // not the previous one, which can share the gap's block — closes the gap
        // by capping the safe frontier below itself.
        let mut gap_open = false;
        // The height at or above which nothing is safe to index or anchor on this
        // fetch (the tightest bound over every observed gap). `u64::MAX` = no
        // bound yet.
        let mut lowest_gap_bound = u64::MAX;
        let mut reached_cursor_or_head = false;
        let mut page = 0u32;
        let max_records = max_records as usize;

        while (page as usize) < BLOCKFROST_MAX_SCAN_PAGES {
            page += 1;
            let path = format!(
                "/metadata/txs/labels/{POE_METADATA_LABEL}/cbor?order=desc&count={BLOCKFROST_SCAN_PAGE_SIZE}&page={page}"
            );
            let Some(rows) = self
                .get_json(&path, "Blockfrost /metadata/txs/labels")
                .await?
            else {
                // 404: no more pages, the chain head is reached.
                reached_cursor_or_head = true;
                break;
            };
            let Some(rows) = rows.as_array() else {
                return Err(bad_response(
                    "Blockfrost /metadata/txs/labels did not return an array",
                ));
            };
            if rows.is_empty() {
                reached_cursor_or_head = true;
                break;
            }

            let mut dipped_below_cursor = false;
            for row in rows {
                // The label-metadata endpoint lists ONLY label-309 transactions, so
                // a row that does not parse is a listed-but-unhydrated record at an
                // unknown height: a hydration gap, not a foreign row. Its height is
                // bounded below by the NEXT hydrated row (which closes it), so the
                // gap is recorded as open here and bounded when that row arrives.
                let Some((tx_hash, metadatum_cbor)) = parse_blockfrost_label_row(row) else {
                    saw_gap = true;
                    gap_open = true;
                    continue;
                };
                if exclude.contains(&tx_hash) {
                    // Already consumed by an earlier pass over the partially-scanned
                    // boundary block: skip it before the coordinate hydration so the
                    // re-walk costs no per-transaction call. An excluded row's height
                    // is unknown (never hydrated), so it neither opens nor closes a
                    // gap.
                    saw_excluded = true;
                    continue;
                }
                let Some(coords) = self.fetch_blockfrost_tx_coords(&tx_hash).await? else {
                    // Coordinates did not hydrate (mempool, or a partial row): a
                    // hydration gap at the same unknown position in the descending
                    // stream, bounded by the next hydrated row like a parse gap.
                    saw_gap = true;
                    gap_open = true;
                    continue;
                };
                if gap_open {
                    // The first fully-hydrated row after a gap: the gap sits at or
                    // ABOVE this row's height (it could share this very block), so
                    // nothing at or above this height is safe this fetch. Bounding
                    // on the next row — never the previous one — is what keeps a
                    // same-block record from anchoring the cursor over the gap.
                    lowest_gap_bound = lowest_gap_bound.min(coords.block_height);
                    gap_open = false;
                }
                if coords.block_height <= after_block_height {
                    // The descending stream just dipped to or below the cursor;
                    // every later row is also at or below it, so the whole range
                    // above the cursor has now been paged.
                    dipped_below_cursor = true;
                    break;
                }
                // A provider-impossible chunk propagates (`?`) and fails the
                // whole fetch so the cursor never advances past this
                // transaction; a genuinely non-chunk-array metadatum is a
                // verdict on the transaction and skips it (tracked as a
                // RESOLVED no-record point the frontier may pass).
                let Some(metadata_cbor) = unwrap_label309_chunked_metadatum(&metadatum_cbor)?
                else {
                    non_carriage.push((coords.block_height, tx_hash, coords.block_hash));
                    continue;
                };
                records.push(Label309Record {
                    tx_hash,
                    block_hash: coords.block_hash,
                    block_height: coords.block_height,
                    block_time: coords.block_time,
                    num_confirmations: tip_block_height.saturating_sub(coords.block_height) + 1,
                    metadata_cbor,
                });
            }

            if dipped_below_cursor || rows.len() < BLOCKFROST_SCAN_PAGE_SIZE {
                // Reached the cursor boundary, or a short page is the last page
                // Blockfrost has to offer: the entire range above the cursor is read.
                reached_cursor_or_head = true;
                break;
            }
        }

        if gap_open {
            // A gap with NO hydrated row after it: nothing below the gap was
            // proven this fetch, so no height above the cursor is safe to index
            // or anchor on.
            lowest_gap_bound = 0;
        }

        // Re-sort ascending so cursor advancement and the oldest-window selection
        // both see monotone block heights, matching the Koios ascending semantics.
        records.sort_by_key(|r| r.block_height);

        if !reached_cursor_or_head {
            // The page ceiling was hit before the descending walk reached the cursor
            // boundary: the records below the oldest one fetched are still unread, so
            // there is NO height at which the cursor can advance without skipping
            // them. Fail the tick rather than advance past unindexed records (the
            // cursor does not move and the next pass retries). A backlog this deep on
            // Blockfrost needs a higher page ceiling, never a silent skip.
            return Err(bad_response(format!(
                "Blockfrost label scan exhausted {BLOCKFROST_MAX_SCAN_PAGES} pages without reaching \
                 the cursor at block {after_block_height}; backlog too deep for one tick"
            )));
        }

        // Drop every record AND resolved no-record point at or above the lowest
        // hydration-gap bound: only heights strictly below every gap are safe to
        // index and anchor on this tick. The dropped ones are re-discovered (and
        // emitted) once the gap hydrates.
        records.retain(|r| r.block_height < lowest_gap_bound);
        non_carriage.retain(|(height, _, _)| *height < lowest_gap_bound);

        // The scan has read every record above the cursor up to its watermark, so
        // the safe ascending set is known. Cut a block-aligned window of at most
        // `max_records`: when more than the cap exist, keep the OLDEST records up to
        // the last FULLY-included block so the cursor anchors at that block's top
        // and the next tick walks the gap upward, never anchoring mid-block. A block
        // that alone exceeds the cap cannot be paged by a height cursor, so it is
        // consumed piecemeal behind the caller's exclusion set instead.
        let heights: Vec<u64> = records.iter().map(|r| r.block_height).collect();
        let cutoff_height = match block_aligned_window(&heights, max_records) {
            WindowCut::Keep { cutoff_height, .. } => cutoff_height,
            WindowCut::SingleBlockOverflow { block_height } => {
                // The boundary block alone carries more un-consumed records than one
                // window: consume a page of it (which subset is irrelevant — the
                // caller's durable exclusion set makes the paging order-free) and
                // report an intra-block frontier so the scan pages through the block
                // across ticks instead of stalling. The gap-retain above guarantees
                // everything at this height hydrated fully.
                records.retain(|r| r.block_height == block_height);
                records.truncate(max_records);
                let Some(block_hash) = records.first().map(|r| r.block_hash) else {
                    // Unreachable: an overflow verdict proves the block has records.
                    return Ok(Label309RecordsResult {
                        records: Vec::new(),
                        frontier: ScanFrontier::Hold,
                    });
                };
                let consumed_no_record: Vec<[u8; 32]> = non_carriage
                    .iter()
                    .filter(|(height, _, _)| *height == block_height)
                    .map(|(_, tx_hash, _)| *tx_hash)
                    .collect();
                return Ok(Label309RecordsResult {
                    records,
                    frontier: ScanFrontier::IntraBlock {
                        height: block_height,
                        block_hash,
                        consumed_no_record,
                    },
                });
            }
        };

        let frontier = match cutoff_height {
            // Capped window: anchor at the highest fully-included block; more
            // records exist above it, so the next tick resumes there.
            Some(cut) => {
                records.retain(|r| r.block_height <= cut);
                match records.last() {
                    Some(last) => ScanFrontier::Anchor {
                        height: last.block_height,
                        block_hash: last.block_hash,
                    },
                    None => ScanFrontier::Hold,
                }
            }
            // Whole window kept. The frontier is decided from the highest RESOLVED
            // point — a hydrated record OR a hydrated no-record (non-carriage)
            // transaction — so a window whose only label-309 transactions carry
            // nothing to index still advances (the Koios highest-complete
            // semantics), never holds forever.
            //
            // `saw_gap` is the sole authority on whether a caught-up form may
            // fire. With a gap, the frontier ANCHORS at the highest resolved
            // point strictly below it (all retained points are, by the gap
            // trim above) or HOLDS when nothing safe resolved: a `CaughtUpTo`
            // would let the cursor jump the gap and permanently skip the
            // un-hydrated transaction. With no gap, Blockfrost is caught up to
            // its OWN watermark — the highest resolved block, never the given
            // tip — and the caller clamps the cursor to `min(tip, indexed_to)`.
            // An empty gap-free window leaves the cursor unchanged rather than
            // jumping the given tip — an empty page does not prove Blockfrost's
            // watermark reached that tip — UNLESS the walk saw the
            // already-consumed rows of a partially-scanned boundary block: with
            // NO gap outstanding, those prove the index covers that block and
            // nothing new exists beyond the exclusions, so the provider is
            // caught up to exactly that block and the caller may close it out.
            // (With a gap, that completion must not fire: the gap may be the
            // block's own remainder.)
            None => {
                let record_anchor = records
                    .last()
                    .map(|last| (last.block_height, last.block_hash));
                let no_record_anchor = non_carriage
                    .iter()
                    .max_by_key(|(height, _, _)| *height)
                    .map(|(height, _, block_hash)| (*height, *block_hash));
                let highest_resolved = match (record_anchor, no_record_anchor) {
                    (Some(rec), Some(skip)) => Some(if skip.0 > rec.0 { skip } else { rec }),
                    (rec, skip) => rec.or(skip),
                };
                match (highest_resolved, saw_gap) {
                    (Some((height, block_hash)), true) => {
                        ScanFrontier::Anchor { height, block_hash }
                    }
                    (Some((height, _)), false) => ScanFrontier::CaughtUpTo { indexed_to: height },
                    (None, false) if saw_excluded => ScanFrontier::CaughtUpTo {
                        indexed_to: after_block_height.saturating_add(1),
                    },
                    (None, _) => ScanFrontier::Hold,
                }
            }
        };
        Ok(Label309RecordsResult { records, frontier })
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // A single Blockfrost gateway has no alternate provider, so the alternate
        // fetch is the same fetch.
        self.fetch_label309_records_since(
            after_block_height,
            exclude_tx_hashes,
            tip_block_height,
            max_records,
        )
        .await
    }
}

impl BlockfrostGateway {
    /// Hydrate a transaction's block coordinates from `GET /txs/{hash}`, or
    /// `None` when the transaction is absent or not yet in a block.
    async fn fetch_blockfrost_tx_coords(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<BlockfrostTxCoords>> {
        let hex = hex::encode(tx_hash);
        let Some(body) = self
            .get_json(&format!("/txs/{hex}"), "Blockfrost /txs")
            .await?
        else {
            return Ok(None);
        };
        let block_height = body.get("block_height").and_then(serde_json::Value::as_u64);
        let block_hash = body
            .get("block")
            .and_then(serde_json::Value::as_str)
            .and_then(hash_from_hex);
        let block_time = body.get("block_time").and_then(epoch_seconds_to_date);
        match (block_height, block_hash, block_time) {
            (Some(block_height), Some(block_hash), Some(block_time)) => {
                Ok(Some(BlockfrostTxCoords {
                    block_height,
                    block_hash,
                    block_time,
                }))
            }
            // Missing any coordinate (still in mempool, or a partial row): skip it
            // this tick; the next scan re-discovers it once it lands.
            _ => Ok(None),
        }
    }

    /// Read the current tip height from `/blocks/latest` (the confirmation path's
    /// lazy per-batch tip read, which needs only the height).
    async fn fetch_tip(&self) -> Result<u64> {
        Ok(self.fetch_chain_tip().await?.block_height)
    }

    /// Read the current tip height and epoch from `/blocks/latest` (the scan's tip
    /// read, which materialises both). The `/blocks/latest` row carries `epoch`
    /// next to `height`; the epoch is optional so a row that omits it still yields
    /// a usable tip.
    async fn fetch_chain_tip(&self) -> Result<ChainTip> {
        let body = self
            .get_json("/blocks/latest", "Blockfrost /blocks/latest")
            .await?
            .ok_or_else(|| bad_response("Blockfrost /blocks/latest returned no body"))?;
        let block_height = body
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| bad_response("Blockfrost /blocks/latest is missing height"))?;
        let epoch = parse_optional_u64(body.get("epoch"));
        Ok(ChainTip {
            block_height,
            epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// Failover wrapper
// ---------------------------------------------------------------------------

/// A primary/secondary failover wrapper over two [`ChainGateway`]s.
///
/// A transient failure on the primary (timeout/connect, 5xx, 425, 429) fails over
/// to the secondary and records which provider answered; a non-transient error
/// (a 4xx other than 425/429, or a malformed body) propagates straight to the
/// caller without a failover attempt. The cooldown store is consulted before the
/// primary call and written through on a 429: a primary already in cooldown is
/// skipped straight to the secondary, and a fresh 429 from the primary engages
/// the cooldown so a sustained storm parks the loop and survives a restart. When
/// BOTH providers return 429 (the primary parked or 429'd, then the secondary
/// 429'd too) the wrapper engages each provider's cooldown and raises
/// [`Error::ChainRateLimitStorm`], which the submit/confirm/scan loops defer on.
///
/// One submit-specific honesty rule: a deterministic
/// [`ChainErrorClass::NodeReject`] from the SECONDARY after the primary arm was
/// attempted and failed transiently is downgraded to the transient
/// [`ChainErrorClass::NodeRejectAfterAmbiguousBroadcast`] — the failed primary
/// attempt is an ambiguous wire contact with the submitted bytes, so the call's
/// verdict is unresolved, never deterministic. A skipped (parked) primary does
/// not downgrade: it never touched the payload.
pub struct FailoverGateway<P: ChainGateway, S: ChainGateway> {
    primary: P,
    secondary: S,
    primary_kind: ProviderKind,
    secondary_kind: ProviderKind,
    cooldown: ProviderCooldown,
    network: Network,
}

impl<P: ChainGateway, S: ChainGateway> FailoverGateway<P, S> {
    /// Wrap a primary and secondary gateway, naming each provider for the
    /// cooldown store and the failover reason, against a cooldown store and the
    /// network the pair serves.
    pub fn new(
        primary: P,
        secondary: S,
        primary_kind: ProviderKind,
        secondary_kind: ProviderKind,
        cooldown: ProviderCooldown,
        network: Network,
    ) -> Self {
        Self {
            primary,
            secondary,
            primary_kind,
            secondary_kind,
            cooldown,
            network,
        }
    }

    /// The network this failover pair serves.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Borrow the primary/secondary provider kinds (for tracing).
    #[must_use]
    pub fn provider_kinds(&self) -> (ProviderKind, ProviderKind) {
        (self.primary_kind, self.secondary_kind)
    }

    /// Borrow the cooldown store (for tests and tracing of the per-provider gate).
    #[must_use]
    pub fn cooldown(&self) -> &ProviderCooldown {
        &self.cooldown
    }

    /// Run one call through the failover policy.
    ///
    /// If the primary is in cooldown (a recent 429), the secondary answers
    /// directly; the primary is already known to be rate-limiting us, so a
    /// secondary 429 then means BOTH providers are rate-limited and the call
    /// raises a [`Error::ChainRateLimitStorm`]. Otherwise the primary runs first;
    /// a transient failure fails over to the secondary (engaging the primary's
    /// cooldown first when the failure was a 429), and a non-transient failure
    /// propagates without a failover attempt.
    async fn run<T, PF, SF>(&self, primary_call: PF, secondary_call: SF) -> Result<T>
    where
        PF: std::future::Future<Output = Result<T>>,
        SF: std::future::Future<Output = Result<T>>,
    {
        // Skip a primary already known to be rate-limiting us. Because the primary
        // is parked behind a 429, a secondary 429 is the second arm of an
        // all-provider storm.
        if self
            .cooldown
            .active_until(self.primary_kind, self.network)
            .await?
            .is_some()
        {
            // A parked primary is SKIPPED: this call never put the payload on
            // the wire through it, so a secondary verdict stands on its own.
            return self.run_secondary(secondary_call, true, false).await;
        }

        match primary_call.await {
            Ok(value) => Ok(value),
            Err(err) => {
                let Some(class) = classify_chain_error(&err) else {
                    return Err(err); // unclassified (e.g. a database error): surface it
                };
                if !class.is_transient() {
                    return Err(err); // deterministic: a second provider repeats it
                }
                let primary_rate_limited = class.is_rate_limited();
                if primary_rate_limited {
                    let until = Utc::now() + DEFAULT_COOLDOWN;
                    self.cooldown
                        .engage(self.primary_kind, self.network, until)
                        .await?;
                }
                // A secondary 429 after the primary was itself rate-limited is the
                // all-provider storm; after any other primary failure it is just a
                // failed failover that propagates. The primary WAS attempted and
                // failed transiently, so any payload this call carried may already
                // be on the wire through it — the secondary's verdict must not be
                // read as the payload's first contact.
                self.run_secondary(secondary_call, primary_rate_limited, true)
                    .await
            }
        }
    }

    /// Run the secondary, turning a secondary 429 into the typed all-provider
    /// storm when the primary was already rate-limiting us.
    ///
    /// `primary_rate_limited` is true when the primary is parked behind a cooldown
    /// or just returned a 429. In that case a secondary 429 means every provider
    /// is rate-limited: the secondary's cooldown is engaged too and the call
    /// raises [`Error::ChainRateLimitStorm`] carrying the soonest cooldown instant,
    /// which the submit/confirm/scan loops defer on. A secondary 429 when the
    /// primary failed for some other reason is a plain failed failover that
    /// propagates with the secondary's classified error.
    ///
    /// `primary_contact_ambiguous` is true when the primary arm was ATTEMPTED in
    /// this call and failed transiently — for a submit, an ambiguous wire contact
    /// with the very bytes being broadcast (a timeout after send, a 5xx after
    /// processing). A parked-and-skipped primary passes false: it never touched
    /// this call's payload.
    async fn run_secondary<T, SF>(
        &self,
        secondary_call: SF,
        primary_rate_limited: bool,
        primary_contact_ambiguous: bool,
    ) -> Result<T>
    where
        SF: std::future::Future<Output = Result<T>>,
    {
        match secondary_call.await {
            Ok(value) => Ok(value),
            Err(err) => {
                let secondary_rate_limited =
                    classify_chain_error(&err).is_some_and(ChainErrorClass::is_rate_limited);
                if primary_rate_limited && secondary_rate_limited {
                    let until = Utc::now() + DEFAULT_COOLDOWN;
                    self.cooldown
                        .engage(self.secondary_kind, self.network, until)
                        .await?;
                    return Err(Error::ChainRateLimitStorm {
                        cooldown_until: until,
                    });
                }
                // A deterministic NodeReject from the secondary cannot stand as
                // the CALL's verdict when a failed transient primary attempt
                // preceded it. Only the submit arms ever produce a NodeReject, so
                // this fires exactly for a broadcast whose bytes MAY already be
                // on the wire via the primary — and the secondary's reject may be
                // the transaction conflicting with its own in-flight or landed
                // copy. Letting the clean reject surface would license the submit
                // path's immediate abandon-and-refund against bytes that can
                // still land (the self-landed refund). Downgrade it to the
                // transient ambiguous-broadcast class: the recorded attempt stays
                // in flight and the resume path re-evaluates it under the
                // absence-corroboration gate.
                if primary_contact_ambiguous {
                    if let Some(ChainErrorClass::NodeReject { status }) = classify_chain_error(&err)
                    {
                        return Err(chain_error(
                            ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status },
                            format!(
                                "the secondary rejected the body after the primary failed \
                                 transiently; the bytes may already be on the wire via the \
                                 primary: {err}"
                            ),
                        ));
                    }
                }
                Err(err)
            }
        }
    }

    /// Run the failover pair with the SECONDARY as the leading provider and the
    /// primary as its fallback — the mirror of [`Self::run`] with the two arms (and
    /// their cooldown identities) swapped.
    ///
    /// The forward scan uses this to recover a stuck gap: one provider keeps
    /// failing to advance past a height (returning a non-advancing frontier, never
    /// an error, so ordinary error-driven failover never fires), so the scan asks
    /// the OTHER provider first. Cooldown is engaged against the correct provider
    /// kind for whichever arm is rate-limited, so a secondary-first attempt never
    /// mis-attributes a 429.
    async fn run_alternate<T, LF, FF>(&self, leading_call: LF, fallback_call: FF) -> Result<T>
    where
        LF: std::future::Future<Output = Result<T>>,
        FF: std::future::Future<Output = Result<T>>,
    {
        // Skip a secondary already known to be rate-limiting us, straight to the
        // primary fallback.
        if self
            .cooldown
            .active_until(self.secondary_kind, self.network)
            .await?
            .is_some()
        {
            return self.run_alternate_fallback(fallback_call, true).await;
        }

        match leading_call.await {
            Ok(value) => Ok(value),
            Err(err) => {
                let Some(class) = classify_chain_error(&err) else {
                    return Err(err);
                };
                if !class.is_transient() {
                    return Err(err);
                }
                let leading_rate_limited = class.is_rate_limited();
                if leading_rate_limited {
                    let until = Utc::now() + DEFAULT_COOLDOWN;
                    self.cooldown
                        .engage(self.secondary_kind, self.network, until)
                        .await?;
                }
                self.run_alternate_fallback(fallback_call, leading_rate_limited)
                    .await
            }
        }
    }

    /// Run the primary as the alternate path's fallback, turning a primary 429 into
    /// the typed all-provider storm when the secondary was already rate-limiting us.
    async fn run_alternate_fallback<T, FF>(
        &self,
        fallback_call: FF,
        leading_rate_limited: bool,
    ) -> Result<T>
    where
        FF: std::future::Future<Output = Result<T>>,
    {
        match fallback_call.await {
            Ok(value) => Ok(value),
            Err(err) => {
                let fallback_rate_limited =
                    classify_chain_error(&err).is_some_and(ChainErrorClass::is_rate_limited);
                if leading_rate_limited && fallback_rate_limited {
                    let until = Utc::now() + DEFAULT_COOLDOWN;
                    self.cooldown
                        .engage(self.primary_kind, self.network, until)
                        .await?;
                    return Err(Error::ChainRateLimitStorm {
                        cooldown_until: until,
                    });
                }
                Err(err)
            }
        }
    }
}

/// How long a 429 from a provider parks it. An all-provider storm raises
/// [`Error::ChainRateLimitStorm`] carrying an instant this far out, so the loops
/// defer for the same span the cooldown holds every provider out.
pub const DEFAULT_COOLDOWN: chrono::Duration = chrono::Duration::seconds(300);

impl<P: ChainGateway, S: ChainGateway> ChainGateway for FailoverGateway<P, S> {
    async fn submit_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.run(
            self.primary.submit_tx(signed_tx),
            self.secondary.submit_tx(signed_tx),
        )
        .await
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        self.run(
            self.primary.get_tx_confirmations(tx_hashes),
            self.secondary.get_tx_confirmations(tx_hashes),
        )
        .await
    }

    async fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        self.run(
            self.primary.get_block_info(block_height),
            self.secondary.get_block_info(block_height),
        )
        .await
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        self.run(self.primary.get_tip(), self.secondary.get_tip())
            .await
    }

    async fn fetch_tx_cbor_by_hashes(&self, tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        self.run(
            self.primary.fetch_tx_cbor_by_hashes(tx_hashes),
            self.secondary.fetch_tx_cbor_by_hashes(tx_hashes),
        )
        .await
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        self.run(
            self.primary.fetch_label309_records_since(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            ),
            self.secondary.fetch_label309_records_since(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            ),
        )
        .await
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // Secondary first, primary as the fallback: the mirror of the usual fetch.
        // The scan calls this to recover a stuck gap the primary keeps failing to
        // advance past.
        self.run_alternate(
            self.secondary.fetch_label309_records_since(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            ),
            self.primary.fetch_label309_records_since(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            ),
        )
        .await
    }
}

/// Build the production failover gateway for a network: Koios primary, and a
/// secondary that is a Blockfrost gateway when a project id is supplied, else a
/// second Koios instance.
///
/// Both Koios arms (the primary, and the secondary when no Blockfrost project
/// id is configured) are addressed per the same [`KoiosConfig`]: an operator
/// API key authenticates every arm's requests, and a base-URL override points
/// every arm at the same self-hosted instance.
///
/// The project id (`Some` when the deployment configured a Blockfrost secret,
/// `None` otherwise) and the Koios config are resolved by the caller from the
/// environment or a config path; this builder never reads the filesystem and
/// never logs a secret. With no project id the secondary degrades to a second
/// Koios instance, so the wrapper's shape is the same on every deployment.
///
/// Every provider call is admitted through the caller-supplied [`ChainEgress`]
/// gates. The caller builds that pair ONCE per process and passes the same one
/// to every `build_failover_gateway` call, so however many handler-owned pairs
/// exist they all draw from one budget per provider. A no-Blockfrost secondary
/// (a second Koios instance) shares the primary's Koios gate: both arms consume
/// the same Koios quota.
pub fn build_failover_gateway(
    network: Network,
    koios: &KoiosConfig,
    blockfrost_project_id: Option<Zeroizing<String>>,
    cooldown: ProviderCooldown,
    egress: &ChainEgress,
) -> Result<FailoverGateway<KoiosGateway, EitherGateway>> {
    let primary = KoiosGateway::new(network, koios.clone())?
        .with_egress(egress.provider(ProviderKind::Koios));
    let secondary = match blockfrost_project_id {
        Some(project_id) => EitherGateway::Blockfrost(
            BlockfrostGateway::new(network, project_id)?
                .with_egress(egress.provider(ProviderKind::Blockfrost)),
        ),
        None => EitherGateway::Koios(
            KoiosGateway::new(network, koios.clone())?
                .with_egress(egress.provider(ProviderKind::Koios)),
        ),
    };
    let secondary_kind = match &secondary {
        EitherGateway::Blockfrost(_) => ProviderKind::Blockfrost,
        EitherGateway::Koios(_) => ProviderKind::Koios,
    };
    Ok(FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        secondary_kind,
        cooldown,
        network,
    ))
}

/// The concrete secondary the failover builder produces: a Blockfrost gateway
/// when a project id is configured, else a second Koios instance. A single enum
/// keeps [`build_failover_gateway`]'s return type concrete (one
/// [`FailoverGateway`] type) regardless of which secondary the deployment got.
pub enum EitherGateway {
    /// The Blockfrost secondary (a project id was configured).
    Blockfrost(BlockfrostGateway),
    /// A second Koios instance (no Blockfrost project id configured).
    Koios(KoiosGateway),
}

impl ChainGateway for EitherGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]> {
        match self {
            EitherGateway::Blockfrost(g) => g.submit_tx(signed_tx).await,
            EitherGateway::Koios(g) => g.submit_tx(signed_tx).await,
        }
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        match self {
            EitherGateway::Blockfrost(g) => g.get_tx_confirmations(tx_hashes).await,
            EitherGateway::Koios(g) => g.get_tx_confirmations(tx_hashes).await,
        }
    }

    async fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        match self {
            EitherGateway::Blockfrost(g) => g.get_block_info(block_height).await,
            EitherGateway::Koios(g) => g.get_block_info(block_height).await,
        }
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        match self {
            EitherGateway::Blockfrost(g) => g.get_tip().await,
            EitherGateway::Koios(g) => g.get_tip().await,
        }
    }

    async fn fetch_tx_cbor_by_hashes(&self, tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        match self {
            EitherGateway::Blockfrost(g) => g.fetch_tx_cbor_by_hashes(tx_hashes).await,
            EitherGateway::Koios(g) => g.fetch_tx_cbor_by_hashes(tx_hashes).await,
        }
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        match self {
            EitherGateway::Blockfrost(g) => {
                g.fetch_label309_records_since(
                    after_block_height,
                    exclude_tx_hashes,
                    tip_block_height,
                    max_records,
                )
                .await
            }
            EitherGateway::Koios(g) => {
                g.fetch_label309_records_since(
                    after_block_height,
                    exclude_tx_hashes,
                    tip_block_height,
                    max_records,
                )
                .await
            }
        }
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // The concrete secondary is itself a single provider, so its alternate
        // fetch is the same fetch (the failover wrapper owns the cross-provider
        // alternation; this arm has no second provider of its own).
        match self {
            EitherGateway::Blockfrost(g) => {
                g.fetch_label309_records_since_alternate(
                    after_block_height,
                    exclude_tx_hashes,
                    tip_block_height,
                    max_records,
                )
                .await
            }
            EitherGateway::Koios(g) => {
                g.fetch_label309_records_since_alternate(
                    after_block_height,
                    exclude_tx_hashes,
                    tip_block_height,
                    max_records,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Provider cooldown
// ---------------------------------------------------------------------------

/// The restart-survivable per-provider rate-limit gate.
///
/// Backed by `cw_core.chain_provider_cooldown`. The failover wrapper consults
/// [`Self::active_until`] before a primary call and calls [`Self::engage`] on a
/// 429 so the gate persists across a restart and a fresh replica does not
/// immediately re-hammer a provider that was already rate-limiting us.
#[derive(Clone)]
pub struct ProviderCooldown {
    pool: sqlx::PgPool,
}

impl ProviderCooldown {
    /// Build a cooldown store over a pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// The instant a provider+network is in cooldown until, or `None` when it is
    /// free to call. Read before every primary call. A row whose `cooldown_until`
    /// is already in the past is treated as free.
    pub async fn active_until(
        &self,
        provider: ProviderKind,
        network: Network,
    ) -> Result<Option<DateTime<Utc>>> {
        let until: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT cooldown_until FROM cw_core.chain_provider_cooldown \
             WHERE provider = $1 AND network = $2 AND cooldown_until > now()",
        )
        .bind(provider.as_str())
        .bind(network.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(until)
    }

    /// Engage (or extend) the cooldown for a provider+network until `until`,
    /// taking the later of any existing cooldown and the new one so a concurrent
    /// writer can never shorten the gate.
    pub async fn engage(
        &self,
        provider: ProviderKind,
        network: Network,
        until: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO cw_core.chain_provider_cooldown (provider, network, cooldown_until, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (provider, network) DO UPDATE SET \
               cooldown_until = GREATEST(cw_core.chain_provider_cooldown.cooldown_until, EXCLUDED.cooldown_until), \
               updated_at = now()",
        )
        .bind(provider.as_str())
        .bind(network.as_str())
        .bind(until)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Borrow the pool (for tests and the cooldown smoke).
    #[must_use]
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

// ---------------------------------------------------------------------------
// Stub gateway
// ---------------------------------------------------------------------------

/// Seeded state a [`StubChainGateway`] answers reads from.
#[derive(Debug, Default)]
struct StubState {
    /// Per-hash confirmation answers; an unseeded hash answers not-on-chain.
    confirmations: HashMap<[u8; 32], TxConfirmation>,
    /// Per-height block answers.
    blocks: HashMap<u64, BlockInfo>,
    /// The seeded tip height.
    tip: u64,
    /// The seeded tip epoch (the epoch a `/tip` read would report). `None` until
    /// a test seeds it, matching a provider response that omitted the epoch.
    tip_epoch: Option<u64>,
    /// Per-hash full-transaction CBOR.
    cbor: HashMap<[u8; 32], Vec<u8>>,
    /// The hash the next submit echoes.
    next_submit_hash: Option<[u8; 32]>,
    /// Hashes submitted so far (for assertions).
    submitted: Vec<[u8; 32]>,
    /// Scripted forward-scan responses, consumed in order so a test can drive a
    /// multi-tick scan (tick 1 returns this, tick 2 returns the next, ...). When
    /// the script is empty the stub answers an empty caught-up result.
    label309_script: std::collections::VecDeque<Label309RecordsResult>,
    /// The `(after_block_height, exclude_tx_hashes, tip_block_height,
    /// max_records)` arguments each forward-scan call was made with, in order
    /// (for assertions).
    label309_calls: Vec<(u64, Vec<[u8; 32]>, u64, u32)>,
}

/// An offline [`ChainGateway`] for tests, refusing construction on production.
///
/// Mirrors the wallet's [`crate::wallet::submitter::StubSubmitter`] production
/// guard: a stub can never answer for a real mainnet submit. It accepts every
/// submit (echoing a caller-seeded hash) and answers confirmation/tip/block reads
/// from caller-seeded state so the submit and confirm paths run end to end with
/// no network.
#[derive(Debug)]
pub struct StubChainGateway {
    network: Network,
    state: Mutex<StubState>,
}

impl StubChainGateway {
    /// Construct a stub gateway, refusing under the production network.
    ///
    /// Returns [`Error::Config`] when `network` is mainnet so a stub can never be
    /// wired into a deployment that submits real transactions.
    pub fn new(network: Network) -> Result<Self> {
        if matches!(network, Network::Mainnet) {
            return Err(Error::Config(
                "the stub chain gateway cannot be constructed on the production network"
                    .to_string(),
            ));
        }
        Ok(Self {
            network,
            state: Mutex::new(StubState::default()),
        })
    }

    /// The network this stub is pinned to (always a test network).
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Seed the hash the next submit echoes.
    pub fn seed_submit_hash(&self, hash: [u8; 32]) {
        self.lock().next_submit_hash = Some(hash);
    }

    /// Seed a confirmation answer for a hash.
    pub fn seed_confirmation(&self, hash: [u8; 32], confirmation: TxConfirmation) {
        self.lock().confirmations.insert(hash, confirmation);
    }

    /// Seed a block answer for a height, and advance the tip to at least that
    /// height so a confirmation derived from the tip is consistent.
    pub fn seed_block(&self, block: BlockInfo) {
        let mut state = self.lock();
        state.tip = state.tip.max(block.block_height);
        state.blocks.insert(block.block_height, block);
    }

    /// Seed the tip height directly.
    pub fn seed_tip(&self, tip: u64) {
        self.lock().tip = tip;
    }

    /// Seed the tip epoch the next `/tip` read reports, so a scan tick
    /// materialises it into `cw_core.cardano_tip`.
    pub fn seed_tip_epoch(&self, epoch: u64) {
        self.lock().tip_epoch = Some(epoch);
    }

    /// Seed full-transaction CBOR for a hash.
    pub fn seed_cbor(&self, hash: [u8; 32], cbor: Vec<u8>) {
        self.lock().cbor.insert(hash, cbor);
    }

    /// Push one scripted forward-scan response. Calls consume the script in order,
    /// so seeding several lets a test drive a multi-tick scan; once the script is
    /// drained the stub answers an empty, caught-up result.
    pub fn seed_label309_response(&self, response: Label309RecordsResult) {
        self.lock().label309_script.push_back(response);
    }

    /// The `(after_block_height, exclude_tx_hashes, tip_block_height,
    /// max_records)` arguments each forward-scan call was made with, in order
    /// (for assertions).
    #[must_use]
    pub fn label309_calls(&self) -> Vec<(u64, Vec<[u8; 32]>, u64, u32)> {
        self.lock().label309_calls.clone()
    }

    /// The hashes submitted through this stub so far (for assertions).
    #[must_use]
    pub fn submitted(&self) -> Vec<[u8; 32]> {
        self.lock().submitted.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StubState> {
        self.state.lock().expect("stub state lock poisoned")
    }
}

impl ChainGateway for StubChainGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]> {
        debug_assert!(
            !signed_tx.is_empty(),
            "a submit must carry the signed transaction bytes"
        );
        let mut state = self.lock();
        let hash = state.next_submit_hash.ok_or_else(|| {
            Error::Config("stub submit was not seeded with an accepted hash".to_string())
        })?;
        state.submitted.push(hash);
        Ok(hash)
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        let state = self.lock();
        Ok(tx_hashes
            .iter()
            .map(|h| {
                (
                    *h,
                    state
                        .confirmations
                        .get(h)
                        .copied()
                        .unwrap_or_else(TxConfirmation::not_on_chain),
                )
            })
            .collect())
    }

    async fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        Ok(self.lock().blocks.get(&block_height).cloned())
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        let state = self.lock();
        Ok(ChainTip {
            block_height: state.tip,
            epoch: state.tip_epoch,
        })
    }

    async fn fetch_tx_cbor_by_hashes(&self, tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        let state = self.lock();
        Ok(tx_hashes
            .iter()
            .filter_map(|h| state.cbor.get(h).map(|c| (*h, c.clone())))
            .collect())
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        let mut state = self.lock();
        state.label309_calls.push((
            after_block_height,
            exclude_tx_hashes.to_vec(),
            tip_block_height,
            max_records,
        ));
        // Consume the next scripted response, defaulting to an empty caught-up
        // result (to the given tip) so an unscripted tick is a clean no-op.
        Ok(state
            .label309_script
            .pop_front()
            .unwrap_or(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::CaughtUpTo {
                    indexed_to: tip_block_height,
                },
            }))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        // The single-provider stub has no alternate; delegate to the normal fetch.
        self.fetch_label309_records_since(
            after_block_height,
            exclude_tx_hashes,
            tip_block_height,
            max_records,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_refuses_construction_on_mainnet() {
        let err = StubChainGateway::new(Network::Mainnet)
            .expect_err("a stub must never be constructible on the production network");
        assert!(
            matches!(err, Error::Config(_)),
            "the production guard is a configuration error, got {err:?}"
        );
    }

    #[test]
    fn stub_constructs_on_a_test_network() {
        let stub = StubChainGateway::new(Network::Preprod).expect("preprod stub constructs");
        assert_eq!(stub.network(), Network::Preprod);
    }

    #[test]
    fn not_on_chain_sentinel_has_zero_confirmations_and_no_coordinates() {
        let c = TxConfirmation::not_on_chain();
        assert_eq!(c.num_confirmations, 0);
        assert!(c.block_height.is_none());
        assert!(c.block_time.is_none());
    }

    #[test]
    fn presence_distinguishes_absent_inconclusive_and_on_chain() {
        assert_eq!(
            TxConfirmation::not_on_chain().presence(),
            TxPresence::Absent,
            "affirmative absence"
        );
        // The inconclusive sentinel shares the absent NUMERIC shape (the confirm
        // authority treats both as not-yet-observed) but a money decision must
        // be able to tell them apart.
        let inconclusive = TxConfirmation::inconclusive();
        assert_eq!(inconclusive.num_confirmations, 0);
        assert!(inconclusive.block_height.is_none());
        assert!(inconclusive.block_time.is_none());
        assert_eq!(inconclusive.presence(), TxPresence::Inconclusive);
        assert_eq!(
            TxConfirmation::on_chain(3, 100, Utc.timestamp_opt(1_700_000_000, 0).unwrap())
                .presence(),
            TxPresence::OnChain
        );
        // Defensive: a count without coordinates can never read as affirmative
        // absence, no matter how the value was constructed.
        let partial = TxConfirmation {
            num_confirmations: 5,
            block_height: None,
            block_time: None,
            positively_seen: false,
        };
        assert_eq!(partial.presence(), TxPresence::Inconclusive);
        // Complete coordinates without a positively_seen flag still read on
        // chain: the coordinates ARE the positive observation.
        let coords_only = TxConfirmation {
            num_confirmations: 1,
            block_height: Some(7),
            block_time: Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap()),
            positively_seen: false,
        };
        assert_eq!(coords_only.presence(), TxPresence::OnChain);
    }

    #[test]
    fn provider_kind_strings_are_stable() {
        assert_eq!(ProviderKind::Koios.as_str(), "koios");
        assert_eq!(ProviderKind::Blockfrost.as_str(), "blockfrost");
    }

    #[test]
    fn transient_classification_covers_the_failover_set() {
        // Transient: a transport blip and EVERY non-success HTTP status that is not
        // a proven ledger reject — the failover statuses (425/429/5xx) AND the
        // provider-side 4xx (401/403 auth/routing misconfig, 404 routing error, a
        // bare 400). A provider's configuration error must fail over, not fail a
        // well-formed request, so it stays transient.
        assert!(ChainErrorClass::Transport.is_transient());
        assert!(ChainErrorClass::CorruptProvider.is_transient());
        for status in [400u16, 401, 403, 404, 425, 429, 500, 503] {
            assert!(
                ChainErrorClass::Http { status }.is_transient(),
                "HTTP {status} must fail over to the secondary"
            );
        }
        // A secondary reject that followed an ambiguous primary attempt is
        // transient BY DESIGN: the call's verdict is unresolved, never an
        // immediate abandon.
        assert!(ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 400 }.is_transient());
        // Non-transient: a malformed body and a proven ledger reject.
        assert!(!ChainErrorClass::BadResponse.is_transient());
        assert!(!ChainErrorClass::NodeReject { status: 400 }.is_transient());
        assert!(!ChainErrorClass::NodeReject { status: 422 }.is_transient());
        // Only a 429 arms the cooldown.
        assert!(ChainErrorClass::Http { status: 429 }.is_rate_limited());
        assert!(!ChainErrorClass::Http { status: 503 }.is_rate_limited());
        assert!(!ChainErrorClass::Transport.is_rate_limited());
        assert!(!ChainErrorClass::NodeReject { status: 400 }.is_rate_limited());
        assert!(
            !ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 400 }.is_rate_limited()
        );
    }

    #[test]
    fn classified_errors_round_trip_through_the_message() {
        for class in [
            ChainErrorClass::Transport,
            ChainErrorClass::BadResponse,
            ChainErrorClass::CorruptProvider,
            ChainErrorClass::Http { status: 429 },
            ChainErrorClass::Http { status: 500 },
            ChainErrorClass::Http { status: 404 },
            ChainErrorClass::NodeReject { status: 400 },
            ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 422 },
        ] {
            let err = chain_error(class, "a detail line for the operator");
            assert_eq!(
                classify_chain_error(&err),
                Some(class),
                "the class encoded into the message must be recoverable"
            );
        }
    }

    #[test]
    fn an_unclassified_chain_provider_error_is_not_transient() {
        // A raw ChainProvider error (no carried class, e.g. the params source's
        // plain message) is treated as non-transient so it surfaces rather than
        // masquerading as a provider blip the failover wrapper would retry.
        let err = Error::ChainProvider("building HTTP client: broken".to_string());
        assert!(classify_chain_error(&err).is_none());
        assert!(!is_transient_chain_error(&err));
    }

    #[test]
    fn a_non_chain_error_is_not_transient() {
        let err = Error::Config("not a provider error".to_string());
        assert!(classify_chain_error(&err).is_none());
        assert!(!is_transient_chain_error(&err));
    }

    #[test]
    fn is_transient_helper_agrees_with_the_class() {
        // A rate limit and a provider-side 404 both fail over; a malformed body and
        // a proven ledger reject do not.
        assert!(is_transient_chain_error(&chain_error(
            ChainErrorClass::Http { status: 429 },
            "rate limited"
        )));
        assert!(is_transient_chain_error(&chain_error(
            ChainErrorClass::Http { status: 404 },
            "routing misconfig"
        )));
        assert!(!is_transient_chain_error(&chain_error(
            ChainErrorClass::NodeReject { status: 400 },
            "ledger rejected the body"
        )));
        assert!(!is_transient_chain_error(&chain_error(
            ChainErrorClass::BadResponse,
            "undecodable body"
        )));
    }

    #[test]
    fn deterministic_node_reject_is_only_a_proven_ledger_reject() {
        // The ONLY deterministic-reject verdict is a typed NodeReject: a submit body
        // the ledger refused (a 400/422 carrying a node validation error). No node
        // can ever accept it, so the recorded attempt can be abandoned immediately.
        for status in [400u16, 422] {
            assert!(
                is_deterministic_node_reject(&chain_error(
                    ChainErrorClass::NodeReject { status },
                    "node rejected the body"
                )),
                "a proven HTTP {status} ledger reject is a deterministic reject"
            );
        }

        // Every transient/ambiguous failure is NEVER a deterministic reject: the
        // transaction may have reached (or already be in) the mempool, so abandoning
        // its inputs would risk a refund-plus-later-landing. Critically, a provider
        // misconfig (401/403/404) and a bare 400/422 with no ledger body are now
        // transient HTTP, so they fail over instead of permanently failing a
        // well-formed tx.
        for transient in [
            chain_error(ChainErrorClass::Transport, "connection reset"),
            chain_error(ChainErrorClass::Http { status: 400 }, "bare bad request"),
            chain_error(ChainErrorClass::Http { status: 401 }, "auth misconfig"),
            chain_error(ChainErrorClass::Http { status: 403 }, "forbidden"),
            chain_error(ChainErrorClass::Http { status: 404 }, "routing misconfig"),
            chain_error(ChainErrorClass::Http { status: 500 }, "node 5xx"),
            chain_error(ChainErrorClass::Http { status: 425 }, "mempool full"),
            chain_error(ChainErrorClass::Http { status: 429 }, "rate limited"),
            chain_error(ChainErrorClass::BadResponse, "undecodable submit response"),
            chain_error(ChainErrorClass::CorruptProvider, "on-chain-impossible data"),
            chain_error(
                ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 400 },
                "secondary reject after an ambiguous primary attempt",
            ),
        ] {
            assert!(
                !is_deterministic_node_reject(&transient),
                "a transient/ambiguous failure must never be a deterministic reject: {transient:?}"
            );
        }

        // An error this module never classified (a database error, a raw
        // ChainProvider message, a rate-limit storm) is conservatively transient.
        assert!(!is_deterministic_node_reject(&Error::ChainProvider(
            "no class carried".to_string()
        )));
        assert!(!is_deterministic_node_reject(&Error::Config(
            "not a provider error".to_string()
        )));
    }

    #[test]
    fn submit_status_error_distinguishes_a_ledger_reject_from_a_provider_misconfig() {
        use reqwest::StatusCode;

        // REAL ledger-reject bodies the two providers relay verbatim from the node
        // are deterministic NodeRejects. These carry node-only validation tokens.
        let koios_reject = "{\"tag\":\"TxSubmitFail\",\"contents\":{\"tag\":\
            \"TxCmdTxSubmitValidationError\",\"contents\":{\"tag\":\
            \"TxValidationErrorInCardanoMode\",\"contents\":{\"kind\":\
            \"ShelleyTxValidationError\",\"error\":[\"ApplyTxError [...]\"]}}}}";
        let blockfrost_reject = "transaction submit error ShelleyTxValidationError \
            ShelleyBasedEraBabbage (ApplyTxError [UtxoFailure (FeeTooSmallUTxO ...)])";
        for (status, body) in [
            (StatusCode::BAD_REQUEST, koios_reject),
            (StatusCode::BAD_REQUEST, blockfrost_reject),
            (StatusCode::UNPROCESSABLE_ENTITY, koios_reject),
        ] {
            let err = submit_status_error(status, body, "submit");
            assert_eq!(
                classify_chain_error(&err),
                Some(ChainErrorClass::NodeReject {
                    status: status.as_u16()
                }),
                "a verbatim node ledger-reject body is a deterministic node reject"
            );
            assert!(is_deterministic_node_reject(&err));
        }

        // GC-2 GUARD: a GENERIC JSON error envelope (the shape a misconfigured
        // provider/proxy returns on a routing/auth 400) must NOT be a NodeReject —
        // generic `error`/`message` keys are no proof of a ledger reject. Treating
        // it as one would permanently fail and auto-refund a valid, never-broadcast
        // tx. It stays transient → failover.
        let generic_envelopes = [
            "{\"error\":\"Bad Request\",\"message\":\"route not found\"}",
            "{\"status_code\":403,\"error\":\"Forbidden\",\"message\":\"invalid project token\"}",
            "{\"error\":\"Invalid or malformed request\"}",
            "{\"message\":\"Internal proxy error\"}",
        ];
        for body in generic_envelopes {
            for status in [StatusCode::BAD_REQUEST, StatusCode::UNPROCESSABLE_ENTITY] {
                let err = submit_status_error(status, body, "submit");
                assert_eq!(
                    classify_chain_error(&err),
                    Some(ChainErrorClass::Http {
                        status: status.as_u16()
                    }),
                    "a generic JSON envelope {body:?} must stay transient, never a node reject"
                );
                assert!(is_transient_chain_error(&err));
                assert!(
                    !is_deterministic_node_reject(&err),
                    "a generic envelope must never permanently-fail a valid tx"
                );
            }
        }

        // A 400/422 with NO body (empty / whitespace / an HTML proxy page) is a
        // provider/proxy error, not a ledger verdict: transient, fails over.
        for (status, body) in [
            (StatusCode::BAD_REQUEST, ""),
            (StatusCode::BAD_REQUEST, "<html>Bad Request</html>"),
            (StatusCode::UNPROCESSABLE_ENTITY, "   "),
        ] {
            let err = submit_status_error(status, body, "submit");
            assert_eq!(
                classify_chain_error(&err),
                Some(ChainErrorClass::Http {
                    status: status.as_u16()
                }),
                "a {} with body {body:?} must stay transient, not a node reject",
                status.as_u16()
            );
            assert!(is_transient_chain_error(&err));
            assert!(!is_deterministic_node_reject(&err));
        }

        // A provider misconfig (401/403/404) and a transient 5xx are transient Http
        // regardless of body — even a body that LOOKS like a ledger reject — because
        // only a 400/422 can carry a real ledger verdict.
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let err = submit_status_error(status, blockfrost_reject, "submit");
            assert_eq!(
                classify_chain_error(&err),
                Some(ChainErrorClass::Http {
                    status: status.as_u16()
                }),
                "HTTP {} is a provider-side failure, never a ledger reject",
                status.as_u16()
            );
            assert!(is_transient_chain_error(&err));
            assert!(!is_deterministic_node_reject(&err));
        }
    }

    #[test]
    fn parses_a_tip_height_and_epoch_from_a_numeric_and_a_string_form() {
        // A numeric row carries both the height and the epoch.
        let numeric = serde_json::json!([{ "block_height": 1234567, "epoch_no": 213 }]);
        let rows: Vec<serde_json::Value> = serde_json::from_value(numeric).unwrap();
        let tip = parse_koios_chain_tip(&rows).unwrap();
        assert_eq!(tip.block_height, 1_234_567);
        assert_eq!(tip.epoch, Some(213));

        // Both fields may be quoted strings.
        let stringy = serde_json::json!([{ "block_height": "1234567", "epoch_no": "508" }]);
        let rows: Vec<serde_json::Value> = serde_json::from_value(stringy).unwrap();
        let tip = parse_koios_chain_tip(&rows).unwrap();
        assert_eq!(tip.block_height, 1_234_567);
        assert_eq!(tip.epoch, Some(508));
    }

    #[test]
    fn tip_epoch_is_optional_when_the_row_omits_it() {
        // A height-only row still yields a usable tip; the epoch is None and the
        // populate loop's cold-start fallback covers it.
        let rows: Vec<serde_json::Value> =
            serde_json::from_value(serde_json::json!([{ "block_height": 1234567 }])).unwrap();
        let tip = parse_koios_chain_tip(&rows).unwrap();
        assert_eq!(tip.block_height, 1_234_567);
        assert_eq!(tip.epoch, None);
    }

    #[test]
    fn rejects_a_tip_with_no_rows_or_no_height() {
        // A malformed response body is a deterministic, non-transient BadResponse
        // (it must not fail over or arm a cooldown).
        let empty: Vec<serde_json::Value> = vec![];
        assert_eq!(
            classify_chain_error(&parse_koios_chain_tip(&empty).unwrap_err()),
            Some(ChainErrorClass::BadResponse)
        );
        let no_height = serde_json::json!([{ "epoch_no": 1 }]);
        let rows: Vec<serde_json::Value> = serde_json::from_value(no_height).unwrap();
        assert_eq!(
            classify_chain_error(&parse_koios_chain_tip(&rows).unwrap_err()),
            Some(ChainErrorClass::BadResponse)
        );
    }

    #[test]
    fn parse_tx_status_keeps_on_chain_and_drops_mempool_rows() {
        let body = serde_json::json!([
            { "tx_hash": "11".repeat(32), "num_confirmations": 5 },
            { "tx_hash": "22".repeat(32), "num_confirmations": null },
            { "tx_hash": "33".repeat(32), "num_confirmations": "12" },
        ]);
        let rows: Vec<serde_json::Value> = serde_json::from_value(body).unwrap();
        let parsed = parse_koios_tx_status(&rows).unwrap();
        let by_hash: HashMap<[u8; 32], u64> = parsed.into_iter().collect();
        assert_eq!(by_hash.get(&[0x11; 32]).copied(), Some(5));
        assert_eq!(by_hash.get(&[0x33; 32]).copied(), Some(12));
        assert!(
            !by_hash.contains_key(&[0x22; 32]),
            "a mempool-only (null) row is not on chain"
        );
    }

    #[test]
    fn parse_tx_status_rejects_a_non_numeric_confirmation() {
        let body = serde_json::json!([
            { "tx_hash": "11".repeat(32), "num_confirmations": true },
        ]);
        let rows: Vec<serde_json::Value> = serde_json::from_value(body).unwrap();
        // A non-numeric confirmation is a malformed body: a deterministic
        // BadResponse, not a transient failure.
        assert_eq!(
            classify_chain_error(&parse_koios_tx_status(&rows).unwrap_err()),
            Some(ChainErrorClass::BadResponse)
        );
    }

    #[test]
    fn blockfrost_base_urls_are_per_network_and_keyless_in_path() {
        assert!(blockfrost_base_url(Network::Mainnet).contains("cardano-mainnet"));
        assert!(blockfrost_base_url(Network::Preprod).contains("cardano-preprod"));
        // The project id rides a header, never the URL.
        assert!(!blockfrost_base_url(Network::Mainnet).contains("project_id"));
    }

    #[tokio::test]
    async fn stub_submit_echoes_the_seeded_hash() {
        let stub = StubChainGateway::new(Network::Preprod).unwrap();
        let hash = [0x5a_u8; 32];
        stub.seed_submit_hash(hash);
        let got = stub.submit_tx(&[0x84, 0xa0]).await.unwrap();
        assert_eq!(got, hash);
        assert_eq!(stub.submitted(), vec![hash]);
    }

    #[tokio::test]
    async fn stub_submit_without_a_seed_is_a_config_error() {
        let stub = StubChainGateway::new(Network::Preprod).unwrap();
        let err = stub.submit_tx(&[0x84]).await.expect_err("unseeded submit");
        assert!(matches!(err, Error::Config(_)));
    }

    #[tokio::test]
    async fn stub_answers_every_requested_hash_in_confirmations() {
        let stub = StubChainGateway::new(Network::Preprod).unwrap();
        let on_chain = [0x01_u8; 32];
        let off_chain = [0x02_u8; 32];
        stub.seed_confirmation(
            on_chain,
            TxConfirmation {
                num_confirmations: 7,
                block_height: Some(100),
                block_time: None,
                positively_seen: true,
            },
        );
        let map = stub
            .get_tx_confirmations(&[on_chain, off_chain])
            .await
            .unwrap();
        assert_eq!(map.get(&on_chain).unwrap().num_confirmations, 7);
        assert_eq!(
            map.get(&off_chain).copied(),
            Some(TxConfirmation::not_on_chain()),
            "an unseeded hash answers not-on-chain, never absent"
        );
    }

    #[tokio::test]
    async fn stub_serves_seeded_blocks_tip_and_cbor() {
        let stub = StubChainGateway::new(Network::Preprod).unwrap();
        let block = BlockInfo {
            block_height: 500,
            block_hash: [0xab; 32],
            block_time: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
        };
        stub.seed_block(block.clone());
        assert_eq!(stub.get_block_info(500).await.unwrap(), Some(block));
        assert_eq!(
            stub.get_tip().await.unwrap().block_height,
            500,
            "seeding a block advances the tip to at least its height"
        );
        // A tip read carries the seeded epoch (None until a test seeds one).
        assert_eq!(stub.get_tip().await.unwrap().epoch, None);
        stub.seed_tip_epoch(213);
        assert_eq!(stub.get_tip().await.unwrap().epoch, Some(213));
        assert!(stub.get_block_info(999).await.unwrap().is_none());

        let hash = [0x07; 32];
        stub.seed_cbor(hash, vec![0xde, 0xad]);
        let map = stub
            .fetch_tx_cbor_by_hashes(&[hash, [0x08; 32]])
            .await
            .unwrap();
        assert_eq!(map.get(&hash).cloned(), Some(vec![0xde, 0xad]));
        assert!(
            !map.contains_key(&[0x08; 32]),
            "a hash with no on-chain transaction is absent from the cbor map"
        );
    }
}
