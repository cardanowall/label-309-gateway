//! Operator root credentials and short-lived access tokens.
//!
//! The control plane authenticates two new credential types alongside the
//! data-plane api key:
//!
//!   - an OPERATOR ROOT credential ([`mint_root_credential`]), created once out of
//!     band by the binary's bootstrap subcommand and the single bearer that may
//!     mint operator tokens;
//!   - short-lived ACCESS TOKENS ([`mint_operator_token`], [`mint_account_token`])
//!     the control plane issues, an operator token authorizing the operator
//!     surface and an account-scoped token authorizing the data plane AS an
//!     account (the dogfood bridge).
//!
//! All three credential classes (api key, root credential, access token) share
//! one hashing discipline: the secret is never stored, only SHA-256(secret) split
//! into an 8-byte lookup prefix and the full 32-byte hash, with the full hash
//! compared in constant time after the prefix narrows the candidates. The shared
//! [`crate::api::middleware::auth::hash_secret`] computes the stored pair.
//!
//! # Revocation and lineage
//!
//! Every credential class revokes by stamping `revoked_at` (never a row delete),
//! and every minted token records the ROW ID of the credential that minted it in
//! `minted_by` — a root credential, another access token, or an api key acting
//! self-service. A token authenticates only while its own row AND every ancestor
//! in that mint lineage are un-revoked ([`resolve_access_token`] walks the chain
//! on each resolve), so revoking a credential is a real kill switch for
//! everything derived from it: revoking a root instantly invalidates the
//! operator tokens it minted and the account tokens minted beneath them.
//! Expiry is deliberately NOT part of the chain check — an ancestor lapsing
//! naturally says nothing about its authority having been compromised, so a
//! still-live child outliving an expired parent keeps working.
//!
//! Root replacement is [`rotate_root_credential`]: one transaction revokes the
//! presented root and mints its successor, so the operator is never left
//! rootless and a revoked root can never mint its own replacement.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::hash_secret;
use crate::ledger::account::ScopedChange;
use crate::{Error, Result};

/// The number of random bytes in a minted secret's entropy tail (256 bits).
const SECRET_ENTROPY_BYTES: usize = 32;

/// The default time-to-live of a minted operator token (24 hours).
pub const DEFAULT_OPERATOR_TOKEN_TTL: Duration = Duration::hours(24);

/// The default time-to-live of a minted account-scoped token (1 hour).
pub const DEFAULT_ACCOUNT_TOKEN_TTL: Duration = Duration::hours(1);

/// A freshly minted secret and the row id it was stored under.
///
/// The plaintext `secret` is returned exactly once, at mint time; it is never
/// recoverable afterwards (only its hash is stored). A caller surfaces it to the
/// operator once and then drops it.
#[derive(Clone)]
pub struct MintedSecret {
    /// The row id the credential / token was stored under.
    pub id: Uuid,
    /// The plaintext secret, shown exactly once. Never logged.
    pub secret: String,
}

/// Redact the plaintext on `{:?}` so a stray debug-format of a containing struct
/// (a log line, a panic, a test assertion) cannot leak the shown-once secret.
/// The id is safe to surface.
impl std::fmt::Debug for MintedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedSecret")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// A token mint that also reports when the token expires. Its `Debug` redacts the
/// secret through [`MintedSecret`]'s.
#[derive(Debug, Clone)]
pub struct MintedToken {
    /// The minted secret (id + plaintext, shown once).
    pub minted: MintedSecret,
    /// When the token stops authenticating.
    pub expires_at: DateTime<Utc>,
}

/// Generate a fresh secret string with a human-readable prefix and a 256-bit
/// random tail rendered in lowercase hex.
///
/// The prefix is operator-meaningful (a deployment chooses it for its control
/// credentials and tokens); the tail is the entropy a guesser must defeat. The
/// engine ships no hardcoded brand prefix, so the caller supplies it.
#[must_use]
pub fn generate_secret(prefix: &str) -> String {
    let mut tail = [0u8; SECRET_ENTROPY_BYTES];
    fill_random(&mut tail);
    format!("{prefix}{}", hex::encode(tail))
}

/// Fill a buffer with cryptographically strong random bytes.
///
/// Uses the process getrandom source through `Uuid::new_v4`'s RNG path by drawing
/// successive random UUIDs; each contributes 16 bytes of entropy. This keeps the
/// control plane free of an extra RNG dependency while still sourcing OS entropy
/// (the `uuid` v4 generator reads `getrandom`).
fn fill_random(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        let chunk = *Uuid::new_v4().as_bytes();
        let take = (buf.len() - filled).min(chunk.len());
        buf[filled..filled + take].copy_from_slice(&chunk[..take]);
        filled += take;
    }
}

/// Mint an operator root credential: generate a secret, store its hash, and
/// return the plaintext exactly once.
///
/// The single bearer that may mint operator tokens. The bootstrap subcommand
/// calls this once for a fresh operator; replacing a live root afterwards is
/// [`rotate_root_credential`], which mints the successor and revokes the
/// presented root in one transaction. The plaintext is returned only here and
/// never stored. The executor is generic so bootstrap can mint the root inside
/// the same transaction that creates the operator — a failure between the two
/// then rolls both back instead of stranding a rootless operator.
pub async fn mint_root_credential<'a, A>(
    executor: A,
    operator_id: Uuid,
    prefix: &str,
    label: Option<&str>,
) -> Result<MintedSecret>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let secret = generate_secret(prefix);
    let (lookup, full_hash) = hash_secret(&secret);
    let id = Uuid::now_v7();
    insert_root_credential(executor, id, operator_id, &lookup, &full_hash, label).await?;
    Ok(MintedSecret { id, secret })
}

/// The single INSERT both root-mint paths share (fresh mint and rotation), so
/// the rotation transaction stores its successor through exactly the code the
/// bootstrap mint uses.
async fn insert_root_credential<'a, A>(
    executor: A,
    id: Uuid,
    operator_id: Uuid,
    lookup: &[u8],
    full_hash: &[u8],
    label: Option<&str>,
) -> Result<()>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO cw_core.control_credential \
           (id, operator_id, kind, secret_lookup, secret_hash, label) \
         VALUES ($1, $2, 'operator_root', $3, $4, $5)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(lookup)
    .bind(full_hash)
    .bind(label)
    .execute(executor)
    .await?;
    Ok(())
}

/// Serialize every credential-lifecycle mutation for one operator by locking its
/// operator row for the transaction.
///
/// Revocation and rotation both enforce "an operator never loses its last live
/// root through the API"; under READ COMMITTED, two concurrent mutations could
/// each see the other's target as still live and together revoke every root
/// (write skew). Taking the operator row lock first makes the mutations run one
/// at a time per operator, so the guard's count is always current. These are
/// rare administrative writes, so the serialization costs nothing in practice.
async fn lock_operator_row(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operator_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT id FROM cw_core.operator WHERE id = $1 FOR UPDATE")
        .bind(operator_id)
        .execute(&mut **txn)
        .await?;
    Ok(())
}

/// The outcome of revoking a control credential under an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRevocation {
    /// The credential is absent or belongs to another operator (an oracle-safe
    /// 404: a cross-tenant id is shaped exactly like a missing one).
    NotFound,
    /// This call stamped `revoked_at`. Every token minted under the credential
    /// stops resolving with it (the auth path walks the mint lineage).
    Revoked,
    /// The credential was already revoked; its original timestamp is preserved.
    AlreadyRevoked,
    /// Refused: the target is the operator's only live root credential. Revoking
    /// it would leave the operator unable to mint tokens or rotate — a state
    /// recoverable only by database surgery, which this API exists to eliminate.
    /// Rotation covers the "kill my last root NOW" incident: it revokes the old
    /// root just as immediately while minting the successor atomically.
    LastLiveRoot,
}

/// Revoke a control credential of `operator_id` by stamping `revoked_at`.
///
/// Tenancy-scoped: a credential of another operator reports
/// [`CredentialRevocation::NotFound`]. Refuses to revoke the operator's last
/// live root ([`CredentialRevocation::LastLiveRoot`]); the check and the stamp
/// run under the per-operator lock so concurrent revocations cannot together
/// take the last root. Idempotent: an already-revoked credential keeps its
/// original timestamp and reports [`CredentialRevocation::AlreadyRevoked`].
///
/// The executor is generic over [`sqlx::Acquire`] so the revocation can ride the
/// route's transaction (committing atomically with its audit row — the internal
/// begin becomes a savepoint there) or run standalone against a pool.
pub async fn revoke_credential<'a, A>(
    executor: A,
    operator_id: Uuid,
    credential_id: Uuid,
) -> Result<CredentialRevocation>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let mut txn = executor.begin().await?;
    lock_operator_row(&mut txn, operator_id).await?;

    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT kind, revoked_at FROM cw_core.control_credential \
         WHERE id = $1 AND operator_id = $2",
    )
    .bind(credential_id)
    .bind(operator_id)
    .fetch_optional(&mut *txn)
    .await?;
    let Some((kind, revoked_at)) = row else {
        return Ok(CredentialRevocation::NotFound);
    };
    if revoked_at.is_some() {
        return Ok(CredentialRevocation::AlreadyRevoked);
    }

    // The last-live-root guard applies to root credentials: at least one other
    // live root must remain so the operator keeps a path to mint and rotate.
    if kind == "operator_root" {
        let other_live_roots: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.control_credential \
             WHERE operator_id = $1 AND id <> $2 \
               AND kind = 'operator_root' AND revoked_at IS NULL",
        )
        .bind(operator_id)
        .bind(credential_id)
        .fetch_one(&mut *txn)
        .await?;
        if other_live_roots == 0 {
            return Ok(CredentialRevocation::LastLiveRoot);
        }
    }

    sqlx::query("UPDATE cw_core.control_credential SET revoked_at = now() WHERE id = $1")
        .bind(credential_id)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;
    Ok(CredentialRevocation::Revoked)
}

/// A completed root rotation: the successor's shown-once secret and the id of
/// the root it replaced.
#[derive(Debug, Clone)]
pub struct RotatedRoot {
    /// The successor root credential (id + plaintext, shown once).
    pub minted: MintedSecret,
    /// The old root this rotation revoked.
    pub revoked_credential_id: Uuid,
}

/// The outcome of rotating an operator's root credential.
#[derive(Debug, Clone)]
pub enum RootRotation {
    /// The presented root was revoked and its successor minted, atomically.
    Rotated(RotatedRoot),
    /// The presented root lost its liveness between authentication and the
    /// rotation transaction (a concurrent revocation or rotation). Nothing was
    /// minted: a root that is no longer live may never mint its successor.
    PresentedRootRevoked,
}

/// Rotate the operator's root credential: revoke the PRESENTED root and mint its
/// successor in one transaction.
///
/// The incident-response flow for a leaked root. Revocation cascades through the
/// mint lineage at resolve time, so the moment this commits, every operator
/// token minted from the old root — and every account token minted beneath those
/// — stops authenticating. The operator's data-plane api keys are untouched:
/// they are account-owned resources, not derivations of control-plane authority.
///
/// Revoke-then-mint inside the transaction gives two guarantees at once: the
/// operator is never observable with zero live roots (the swap is atomic), and a
/// root revoked concurrently cannot mint a replacement (the conditional revoke
/// affecting no row aborts the rotation). `label` names the successor; omitted,
/// the old root's label carries over.
///
/// The executor is generic over [`sqlx::Acquire`] so the rotation can ride the
/// route's transaction (committing atomically with its audit row — the internal
/// begin becomes a savepoint there) or run standalone against a pool.
pub async fn rotate_root_credential<'a, A>(
    executor: A,
    operator_id: Uuid,
    presented_credential_id: Uuid,
    prefix: &str,
    label: Option<&str>,
) -> Result<RootRotation>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let secret = generate_secret(prefix);
    let (lookup, full_hash) = hash_secret(&secret);
    let new_id = Uuid::now_v7();

    let mut txn = executor.begin().await?;
    lock_operator_row(&mut txn, operator_id).await?;

    let revoked = sqlx::query(
        "UPDATE cw_core.control_credential SET revoked_at = now() \
         WHERE id = $1 AND operator_id = $2 AND kind = 'operator_root' \
           AND revoked_at IS NULL",
    )
    .bind(presented_credential_id)
    .bind(operator_id)
    .execute(&mut *txn)
    .await?
    .rows_affected();
    if revoked != 1 {
        // The guard resolved this root as live moments ago, so the only way the
        // conditional update misses is a concurrent revocation. Abort without
        // minting; the transaction rolls back the nothing it changed.
        return Ok(RootRotation::PresentedRootRevoked);
    }

    let carried_label: Option<String> = match label {
        Some(l) => Some(l.to_string()),
        None => {
            sqlx::query_scalar("SELECT label FROM cw_core.control_credential WHERE id = $1")
                .bind(presented_credential_id)
                .fetch_one(&mut *txn)
                .await?
        }
    };
    insert_root_credential(
        &mut *txn,
        new_id,
        operator_id,
        &lookup,
        &full_hash,
        carried_label.as_deref(),
    )
    .await?;
    txn.commit().await?;

    Ok(RootRotation::Rotated(RotatedRoot {
        minted: MintedSecret { id: new_id, secret },
        revoked_credential_id: presented_credential_id,
    }))
}

/// Revoke an access token of `operator_id` by stamping `revoked_at` — the
/// targeted kill switch for one leaked token without a full rotation.
///
/// Tenancy-scoped: a token of another operator reports
/// [`ScopedChange::NotFound`]. Revoking a token also invalidates any token
/// minted UNDER it (the auth path walks the mint lineage), so killing a leaked
/// operator token takes the account tokens an attacker minted with it down too.
/// Idempotent: an already-revoked token reports [`ScopedChange::Unchanged`].
///
/// The executor is generic so the revocation can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn revoke_access_token<'a, A>(
    executor: A,
    operator_id: Uuid,
    token_id: Uuid,
) -> Result<ScopedChange>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let row: Option<(bool,)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT id, revoked_at FROM cw_core.access_token \
             WHERE id = $1 AND operator_id = $2 \
         ), \
         updated AS ( \
             UPDATE cw_core.access_token t SET revoked_at = now() \
             FROM owned \
             WHERE t.id = owned.id AND owned.revoked_at IS NULL \
             RETURNING t.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed FROM owned",
    )
    .bind(token_id)
    .bind(operator_id)
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => ScopedChange::NotFound,
        Some((true,)) => ScopedChange::Changed,
        Some((false,)) => ScopedChange::Unchanged,
    })
}

/// The operator a live root credential resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRoot {
    /// The credential row id (the audit handle).
    pub credential_id: Uuid,
    /// The operator the credential belongs to.
    pub operator_id: Uuid,
}

/// Resolve a presented secret to a live root credential, or `None`.
///
/// Hashes the secret, narrows to live (un-revoked) candidates by the 8-byte
/// lookup prefix, and constant-time-compares the full hash. A revoked or unknown
/// credential resolves to `None`, collapsing both into one outcome so a scanner
/// cannot distinguish them.
pub async fn resolve_root_credential(
    pool: &sqlx::PgPool,
    secret: &str,
) -> Result<Option<ResolvedRoot>> {
    if secret.is_empty() {
        return Ok(None);
    }
    let full_hash = Sha256::digest(secret.as_bytes());
    let lookup = &full_hash[..8];

    let candidates: Vec<RootRow> = sqlx::query_as(
        "SELECT id, operator_id, secret_hash FROM cw_core.control_credential \
         WHERE secret_lookup = $1 AND revoked_at IS NULL AND kind = 'operator_root'",
    )
    .bind(lookup)
    .fetch_all(pool)
    .await?;

    for row in candidates {
        if full_hash.as_slice().ct_eq(&row.secret_hash).into() {
            return Ok(Some(ResolvedRoot {
                credential_id: row.id,
                operator_id: row.operator_id,
            }));
        }
    }
    Ok(None)
}

/// The minimum and maximum per-minute request budget a minted credential (api
/// key or account token) may carry.
///
/// A custom budget must be positive (a zero or negative budget would lock the
/// credential out) and is capped so a single mint cannot hand out an unbounded
/// budget. The ceiling is generous: credentials are minted under operator
/// control, so the cap guards against a fat-finger value, not abuse.
pub const MIN_RATE_LIMIT_PER_MIN: i32 = 1;
/// The maximum per-minute request budget a minted credential may carry.
pub const MAX_RATE_LIMIT_PER_MIN: i32 = 1_000_000;

/// Validate an optional per-minute budget for a minted credential.
///
/// The single bounds check both issuing paths (api-key create and account-token
/// mint) share. `None` is legal — the credential carries no custom budget and
/// the data plane meters it against its fixed default; a custom budget must be
/// in `[MIN_RATE_LIMIT_PER_MIN, MAX_RATE_LIMIT_PER_MIN]`.
pub(crate) fn validate_rate_limit(rate_limit_per_min: Option<i32>) -> Result<()> {
    if let Some(budget) = rate_limit_per_min {
        if !(MIN_RATE_LIMIT_PER_MIN..=MAX_RATE_LIMIT_PER_MIN).contains(&budget) {
            return Err(Error::Config(format!(
                "a rate limit must be between {MIN_RATE_LIMIT_PER_MIN} and \
                 {MAX_RATE_LIMIT_PER_MIN} requests per minute"
            )));
        }
    }
    Ok(())
}

/// Mint an operator access token under a root credential.
///
/// The token carries no account_id, so it authorizes the operator control
/// surface. `ttl` bounds its lifetime; `minted_by` records the root credential's
/// row id — the lineage revocation cascades through (revoking the root kills
/// this token) and the audit trail's handle. The plaintext secret is returned
/// exactly once. An operator token carries no per-request budget (it does not
/// exercise the data-plane limiter), so its budget is always NULL.
///
/// The executor is generic over [`sqlx::Acquire`] so the mint can ride the
/// route's transaction (committing atomically with its audit row) or run
/// standalone against a pool.
pub async fn mint_operator_token<'a, A>(
    executor: A,
    operator_id: Uuid,
    prefix: &str,
    ttl: Duration,
    minted_by: Uuid,
) -> Result<MintedToken>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let mut txn = executor.begin().await?;
    let minted = mint_token(
        &mut txn,
        operator_id,
        None,
        &[],
        None,
        prefix,
        ttl,
        minted_by,
    )
    .await?;
    txn.commit().await?;
    Ok(minted)
}

/// The outcome of minting an account-scoped token.
///
/// A target account the operator does not own resolves to
/// [`AccountTokenMint::AccountNotFound`] (the route renders a 404, no cross-tenant
/// existence oracle); an owned account carries the [`MintedToken`].
#[derive(Debug, Clone)]
pub enum AccountTokenMint {
    /// The target account is absent or owned by another operator.
    AccountNotFound,
    /// The account is owned; the token was minted.
    Minted(MintedToken),
}

/// Mint an account-scoped access token, pinned to the operator owning the account.
///
/// Confirms the account belongs to `operator_id` before minting (an account of
/// another operator yields [`AccountTokenMint::AccountNotFound`] and no token is
/// written). The token carries an account_id and the data-plane scopes it may
/// exercise, so it authenticates the data plane AS that account (no privileged
/// backdoor). The plaintext secret is returned exactly once.
///
/// Every requested scope must exist in the `cw_core.api_scope` registry (an
/// unknown scope is a caller error, never silently dropped); an empty scope set
/// remains legal for a token. `rate_limit_per_min` is an OPTIONAL per-minute
/// request budget the data-plane limiter meters this token against. `None`
/// leaves the token with no custom budget, so the limiter applies its fixed
/// default; a custom budget must be in
/// `[MIN_RATE_LIMIT_PER_MIN, MAX_RATE_LIMIT_PER_MIN]`. `minted_by` is the row id
/// of the minting credential (a root, an operator token, or the account's own
/// token / api key acting self-service) — the lineage revocation cascades
/// through, so it is required: a token with no lineage would sit outside every
/// kill switch short of its own targeted revoke.
///
/// The executor is generic over [`sqlx::Acquire`] so the mint can ride the
/// route's transaction (committing atomically with its audit row) or run
/// standalone against a pool.
#[allow(clippy::too_many_arguments)]
pub async fn mint_account_token<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    scopes: &[String],
    rate_limit_per_min: Option<i32>,
    prefix: &str,
    ttl: Duration,
    minted_by: Uuid,
) -> Result<AccountTokenMint>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    validate_rate_limit(rate_limit_per_min)?;
    let mut txn = executor.begin().await?;
    crate::api::middleware::scope::validate_registered(&mut *txn, scopes).await?;
    if !crate::ledger::account::account_belongs_to_operator(&mut *txn, operator_id, account_id)
        .await?
    {
        return Ok(AccountTokenMint::AccountNotFound);
    }
    let minted = mint_token(
        &mut txn,
        operator_id,
        Some(account_id),
        scopes,
        rate_limit_per_min,
        prefix,
        ttl,
        minted_by,
    )
    .await?;
    txn.commit().await?;
    Ok(AccountTokenMint::Minted(minted))
}

/// The shared token-mint primitive: store the hash with an expiry and the mint
/// lineage, and return the plaintext once.
///
/// Takes a concrete connection (the public mint fns acquire it from their
/// generic executor), so the lineage check and the insert run on the caller's
/// connection — and therefore inside the caller's transaction when one is open.
#[allow(clippy::too_many_arguments)]
async fn mint_token(
    conn: &mut sqlx::PgConnection,
    operator_id: Uuid,
    account_id: Option<Uuid>,
    scopes: &[String],
    rate_limit_per_min: Option<i32>,
    prefix: &str,
    ttl: Duration,
    minted_by: Uuid,
) -> Result<MintedToken> {
    if ttl <= Duration::zero() {
        return Err(Error::Config("token TTL must be positive".into()));
    }

    // Defense in depth on the mint lineage. `minted_by` is stored as the
    // revocation-cascade anchor, so it must reference a REAL, un-revoked
    // credential of THIS operator: a root credential, another access token, or
    // an api key on one of the operator's accounts. Every route already passes
    // the authenticated credential's row id, but nothing else pins that — a
    // future caller passing an arbitrary id would mint a token whose lineage
    // walk dead-ends at a phantom row, leaving it outside every kill switch
    // short of its own targeted revoke. Expiry is deliberately NOT checked,
    // matching the lineage walk's semantics (natural expiry of the minter says
    // nothing about its authority being compromised; the request that reaches
    // here authenticated moments ago).
    let minter_is_live: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM cw_core.control_credential \
             WHERE id = $1 AND operator_id = $2 AND revoked_at IS NULL) \
            OR EXISTS ( \
             SELECT 1 FROM cw_core.access_token \
             WHERE id = $1 AND operator_id = $2 AND revoked_at IS NULL) \
            OR EXISTS ( \
             SELECT 1 FROM cw_core.api_key k \
             JOIN cw_core.account_detail d ON d.account_id = k.account_id \
             WHERE k.id = $1 AND d.operator_id = $2 AND k.revoked_at IS NULL)",
    )
    .bind(minted_by)
    .bind(operator_id)
    .fetch_one(&mut *conn)
    .await?;
    if !minter_is_live {
        return Err(Error::Config(
            "minted_by does not reference a live credential of this operator".into(),
        ));
    }

    let secret = generate_secret(prefix);
    let (lookup, full_hash) = hash_secret(&secret);
    let id = Uuid::now_v7();
    let ttl_secs = ttl.num_seconds();

    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO cw_core.access_token \
           (id, operator_id, account_id, scopes, token_lookup, token_hash, expires_at, \
            minted_by, rate_limit_per_min) \
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7), $8, $9) \
         RETURNING expires_at",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(scopes)
    .bind(&lookup)
    .bind(&full_hash)
    .bind(ttl_secs as f64)
    .bind(minted_by)
    .bind(rate_limit_per_min)
    .fetch_one(&mut *conn)
    .await?;

    Ok(MintedToken {
        minted: MintedSecret { id, secret },
        expires_at,
    })
}

/// A live access token resolved from a presented secret.
#[derive(Debug, Clone)]
pub struct ResolvedToken {
    /// The token row id (the audit handle).
    pub token_id: Uuid,
    /// The operator that owns the token.
    pub operator_id: Uuid,
    /// The account the token is scoped to, or `None` for an operator token.
    pub account_id: Option<Uuid>,
    /// The data-plane scopes an account-scoped token carries.
    pub scopes: Vec<String>,
    /// The token's custom per-minute request budget, or `None` to fall back to
    /// the fixed default budget the data-plane limiter applies.
    pub rate_limit_per_min: Option<i32>,
}

/// Resolve a presented secret to a live access token, or `None`.
///
/// Hashes the secret, narrows to unexpired, un-revoked candidates by the 8-byte
/// lookup prefix, and constant-time-compares the full hash. The matched token
/// then authenticates only if its whole mint lineage is un-revoked
/// (`mint_lineage_is_live`), so revoking a root credential or an intermediate
/// token instantly invalidates everything minted beneath it. An expired,
/// revoked, lineage-revoked, or unknown token all collapse to `None`, so a
/// scanner cannot distinguish them.
pub async fn resolve_access_token(
    pool: &sqlx::PgPool,
    secret: &str,
) -> Result<Option<ResolvedToken>> {
    if secret.is_empty() {
        return Ok(None);
    }
    let full_hash = Sha256::digest(secret.as_bytes());
    let lookup = &full_hash[..8];

    let candidates: Vec<TokenRow> = sqlx::query_as(
        "SELECT id, operator_id, account_id, scopes, token_hash, rate_limit_per_min \
         FROM cw_core.access_token \
         WHERE token_lookup = $1 AND expires_at > now() AND revoked_at IS NULL",
    )
    .bind(lookup)
    .fetch_all(pool)
    .await?;

    for row in candidates {
        if full_hash.as_slice().ct_eq(&row.token_hash).into() {
            if !mint_lineage_is_live(pool, row.id).await? {
                return Ok(None);
            }
            return Ok(Some(ResolvedToken {
                token_id: row.id,
                operator_id: row.operator_id,
                account_id: row.account_id,
                scopes: row.scopes,
                rate_limit_per_min: row.rate_limit_per_min,
            }));
        }
    }
    Ok(None)
}

/// The maximum mint-chain depth the lineage walk follows.
///
/// A real chain is at most a few links (root -> operator token -> account token,
/// plus a self-service hop or two); `minted_by` is written once at INSERT from a
/// row that already exists and is never updated, so a cycle is unrepresentable
/// through the API. The cap is pure defense against pathological data sending
/// the recursive query into an unbounded loop; a walk that hits it fails CLOSED
/// (see [`mint_lineage_is_live`]).
const MAX_MINT_CHAIN_DEPTH: i32 = 32;

/// Whether a token's entire mint lineage is un-revoked.
///
/// Walks `minted_by` upward through `cw_core.access_token` (an account token
/// minted by an operator token, a self-service token minted by another token)
/// and checks every ancestor id against the two terminal credential stores
/// (`cw_core.control_credential` for a root, `cw_core.api_key` for a
/// self-service key). Any revoked link anywhere in the chain kills the token.
/// Only `revoked_at` participates: an ancestor merely EXPIRING does not
/// invalidate a still-live child, because natural expiry says nothing about the
/// ancestor's authority having been compromised. A `minted_by` that references
/// no surviving row ends the walk (pre-lineage rows nulled by migration).
///
/// A walk truncated at [`MAX_MINT_CHAIN_DEPTH`] fails CLOSED: if the deepest
/// visited row still points at an unvisited token, the unvisited ancestors
/// could carry a revocation this resolve would otherwise miss, so the token is
/// treated as not live rather than silently escaping the kill switch.
async fn mint_lineage_is_live(pool: &sqlx::PgPool, token_id: Uuid) -> Result<bool> {
    let live: bool = sqlx::query_scalar(
        "WITH RECURSIVE lineage AS ( \
             SELECT id, minted_by, revoked_at, 1 AS depth \
             FROM cw_core.access_token WHERE id = $1 \
           UNION ALL \
             SELECT t.id, t.minted_by, t.revoked_at, l.depth + 1 \
             FROM cw_core.access_token t \
             JOIN lineage l ON t.id = l.minted_by \
             WHERE l.depth < $2 \
         ) \
         SELECT NOT EXISTS (SELECT 1 FROM lineage WHERE revoked_at IS NOT NULL) \
            AND NOT EXISTS ( \
                  SELECT 1 FROM cw_core.control_credential c \
                  WHERE c.revoked_at IS NOT NULL \
                    AND c.id IN (SELECT minted_by FROM lineage)) \
            AND NOT EXISTS ( \
                  SELECT 1 FROM cw_core.api_key k \
                  WHERE k.revoked_at IS NOT NULL \
                    AND k.id IN (SELECT minted_by FROM lineage)) \
            AND NOT EXISTS ( \
                  SELECT 1 FROM lineage l \
                  WHERE l.depth = $2 AND l.minted_by IS NOT NULL \
                    AND EXISTS (SELECT 1 FROM cw_core.access_token t \
                                WHERE t.id = l.minted_by))",
    )
    .bind(token_id)
    .bind(MAX_MINT_CHAIN_DEPTH)
    .fetch_one(pool)
    .await?;
    Ok(live)
}

/// The columns the root-credential resolve query reads back.
#[derive(sqlx::FromRow)]
struct RootRow {
    id: Uuid,
    operator_id: Uuid,
    secret_hash: Vec<u8>,
}

/// The columns the access-token resolve query reads back.
#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    operator_id: Uuid,
    account_id: Option<Uuid>,
    scopes: Vec<String>,
    token_hash: Vec<u8>,
    rate_limit_per_min: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_carries_the_prefix_and_a_full_entropy_tail() {
        let secret = generate_secret("ctl_root_");
        assert!(secret.starts_with("ctl_root_"));
        // 32 bytes of entropy render to 64 lowercase hex characters.
        assert_eq!(secret.len(), "ctl_root_".len() + SECRET_ENTROPY_BYTES * 2);
        assert!(secret
            .trim_start_matches("ctl_root_")
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_secret_is_unique_across_calls() {
        let a = generate_secret("p_");
        let b = generate_secret("p_");
        assert_ne!(a, b, "two minted secrets must not collide");
    }

    #[test]
    fn fill_random_fills_the_whole_buffer_for_non_multiple_lengths() {
        // A length that is not a multiple of 16 exercises the final partial chunk.
        let mut buf = [0u8; 20];
        fill_random(&mut buf);
        // Astronomically unlikely to be all-zero from a real entropy source.
        assert!(buf.iter().any(|&b| b != 0));
    }
}
