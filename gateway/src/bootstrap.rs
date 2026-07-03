//! The `gateway operator bootstrap` subcommand.
//!
//! Provisions a fresh deployment's control plane from an empty database: it
//! creates one operator row, mints its operator root credential, and registers
//! the reference manual-adjustment ledger kind. It creates NO account (accounts
//! are provisioned through the control API after bootstrap).
//!
//! The root credential's plaintext secret is printed EXACTLY ONCE, here, to
//! stdout. It is never stored (only its hash is) and never logged: the operator
//! copies it from this single print and keeps it safe. Rotation is
//! `POST /control/v1/operator/root/rotate` (CLI: `gateway admin credential
//! rotate-root`): one transaction revokes the presented root and mints its
//! successor, and every token minted under the old root stops authenticating.
//!
//! Bootstrap is not silently idempotent: a re-run against a database that already
//! has an operator refuses by default rather than minting a fresh root credential
//! an attacker (or a careless re-deploy) might use. Provisioning a second operator
//! is a deliberate act that the caller opts into with an explicit flag; the typed
//! [`Provisioning`] mode makes that choice un-ambiguous.

use anyhow::{Context, Result};
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::ledger_adjust::register_manual_adjustment_kind;
use gateway_core::wallet::operator::create_operator;

use crate::config::GatewayConfig;

/// How a bootstrap run treats an already-provisioned database.
///
/// The default ([`Provisioning::FreshOnly`]) refuses to run a second time, so a
/// re-deploy that accidentally re-runs bootstrap cannot mint an unexpected root
/// credential. [`Provisioning::AllowAdditional`] is the explicit opt-in for the
/// rare, intentional act of standing up a second operator (a second tenant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provisioning {
    /// Provision only when the database has no operator yet; refuse otherwise.
    FreshOnly,
    /// Provision an additional operator even when one already exists.
    AllowAdditional,
}

/// Run the bootstrap: create the operator, register the manual-adjustment kind,
/// and mint + print the root credential exactly once.
///
/// `label` is the operator's display name. `mode` decides what happens when the
/// database already carries an operator: [`Provisioning::FreshOnly`] refuses (the
/// safe default), [`Provisioning::AllowAdditional`] explicitly provisions another.
/// The function prints the root secret to stdout and returns; the caller exits.
/// The secret is the only sensitive value that ever leaves this process, and it
/// leaves only on stdout, never through the tracing subscriber.
pub async fn run(
    pool: &sqlx::PgPool,
    config: &GatewayConfig,
    label: &str,
    mode: Provisioning,
) -> Result<()> {
    // ONE transaction for the whole provisioning: the fresh-only guard, the
    // operator row, the manual-adjustment kind, and the root credential commit
    // together or not at all. Without this, a failure between the operator
    // insert and the root mint would strand an operator with no credential —
    // and the fresh-only guard (keyed on operator existence) would then refuse
    // the retry, bricking the deployment. With it, a failed run rolls back
    // cleanly and a re-run starts from an empty table again.
    let mut txn = pool
        .begin()
        .await
        .context("opening the bootstrap transaction")?;

    // Guard idempotence before mutating anything. A re-run against a provisioned
    // database is refused unless the caller explicitly asked for an additional
    // operator, so an accidental re-deploy cannot quietly mint a second root.
    if mode == Provisioning::FreshOnly {
        let existing = existing_operator_count(&mut txn)
            .await
            .context("checking for an existing operator")?;
        if existing > 0 {
            anyhow::bail!(
                "this database already has {existing} operator(s); bootstrap refuses to mint \
                 another root credential by default. Re-run with --allow-additional to provision \
                 a second operator on purpose."
            );
        }
    }

    let operator_id = create_operator(&mut *txn, label)
        .await
        .context("creating the operator row")?;

    // Register the reference manual-adjustment ledger kind so an operator balance
    // adjustment is possible. This is the reference adapter registering it, not a
    // core-seeded kind. Idempotent across re-runs (a second operator does not
    // re-register a kind that already exists).
    register_manual_adjustment_kind(&mut *txn)
        .await
        .context("registering the manual-adjustment ledger kind")?;

    let minted = mint_root_credential(
        &mut *txn,
        operator_id,
        &config.control.secret_prefix,
        Some(label),
    )
    .await
    .context("minting the operator root credential")?;

    txn.commit()
        .await
        .context("committing the bootstrap transaction")?;

    // The single print of the secret, only after the commit made the credential
    // real. Deliberately on stdout (not the tracing subscriber), framed so an
    // operator cannot miss that it is shown only once.
    print_root_secret(operator_id, &minted.id.to_string(), &minted.secret);

    Ok(())
}

/// Count the operator rows already present, so the fresh-only guard can refuse a
/// re-run before minting anything. Runs on the provisioning transaction so the
/// guard and the mutations read one snapshot.
///
/// Bootstrap legitimately touches the database directly (it is the out-of-band
/// provisioning path, not an API client), so a small count query here is the
/// right place for the idempotence check.
async fn existing_operator_count(txn: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<i64> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.operator")
        .fetch_one(&mut **txn)
        .await?;
    Ok(count)
}

/// Print the bootstrap result to stdout, framing the once-only root secret.
///
/// Kept as its own function with no `tracing` call so the secret cannot leak into
/// a structured log line: it is written to stdout and nowhere else.
fn print_root_secret(operator_id: uuid::Uuid, credential_id: &str, secret: &str) {
    println!("operator bootstrap complete");
    println!("  operator_id    {operator_id}");
    println!("  credential_id  {credential_id}");
    println!();
    println!("  operator root secret (shown once, store it now):");
    println!();
    println!("    {secret}");
    println!();
    println!("  This secret is not stored and cannot be recovered. Use it to mint");
    println!("  short-lived operator tokens through POST /control/v1/operator/token.");
    println!("  If it ever leaks, rotate it: `gateway admin credential rotate-root`");
    println!("  revokes it and every token minted under it, and prints a successor.");
}
