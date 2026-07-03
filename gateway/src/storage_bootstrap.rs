//! The `gateway storage bootstrap` subcommand.
//!
//! Gets a single-key deployment from "the keyring holds one Arweave funding key"
//! to "uploads work" in one step, with no per-operator or per-account grant
//! choreography. It unlocks the operator keyring, resolves the one Arweave funding
//! key and the one bootstrapped operator, and registers a `service`-scoped funding
//! source for the chosen backend, so every account on the instance can draw it.
//!
//! It does NOT call the storage provider: registering a source and granting it does
//! not need a network round trip. The source's winc balance is stamped by the
//! serving runtime's reconcile loop on its first pass (which reads the provider's
//! authoritative balance); until that lands, the source reads as unfunded and an
//! upload is refused, exactly as a never-reconciled source should. So the sequence
//! a self-host operator follows is: run `operator bootstrap` once, fund the Arweave
//! address out of band through the provider's rails, run `storage bootstrap` once,
//! then start the serving binary, whose reconcile loop stamps the balance and opens
//! uploads.
//!
//! Re-running is safe: a same-owner re-run renames the source row in place and
//! converges on its existing live service grant rather than minting a second one.

use anyhow::{bail, Context, Result};
use gateway_core::storage::{bootstrap_service_source, BootstrapOutcome};
use gateway_core::wallet::keyring::VerifiedArweaveKey;
use uuid::Uuid;

use crate::assembly::unlock_keyring;
use crate::config::GatewayConfig;

/// The persisted backend identifiers a funding source may target. The hyphen form
/// is canonical (it matches the backends' own `name()`); the underscore form is a
/// config alias the operator may type, normalized here so the row never carries the
/// underscore spelling.
const KNOWN_BACKENDS: [&str; 3] = ["turbo", "direct-arweave", "arlocal"];

/// Normalize a backend token to its canonical persisted form, or reject an unknown
/// one. `direct_arweave` (underscore) maps to the canonical `direct-arweave`, the
/// same normalization the config and control plane apply, so a bootstrap and a
/// later config can never disagree on the spelling of one backend.
fn normalize_backend(raw: &str) -> Option<&'static str> {
    match raw {
        "turbo" => Some("turbo"),
        "direct-arweave" | "direct_arweave" => Some("direct-arweave"),
        "arlocal" => Some("arlocal"),
        _ => None,
    }
}

/// Run the storage bootstrap: unlock the keyring, resolve the funding key and the
/// owning operator, and register a service-scoped funding source for `backend`.
///
/// `backend` is the storage backend the source draws from (required: a deployment
/// chooses Turbo, direct Arweave, or ArLocal). `label` names the source row.
/// `key_address` optionally selects which Arweave key to register when the keyring
/// holds more than one; with a single key it is inferred. `operator_id` optionally
/// selects the owning operator when more than one exists; with a single operator it
/// is inferred (the common single-tenant case). The resolved source + grant ids are
/// printed to stdout.
pub async fn run(
    pool: &sqlx::PgPool,
    config: &GatewayConfig,
    backend: &str,
    label: &str,
    key_address: Option<&str>,
    operator_id: Option<Uuid>,
) -> Result<()> {
    let backend = normalize_backend(backend).with_context(|| {
        format!(
            "unknown storage backend {backend:?}; expected one of {}",
            KNOWN_BACKENDS.join(", ")
        )
    })?;

    // Unlock the keyring and resolve the one Arweave funding key whose address the
    // source registers under. The keyring already derived and verified the address
    // from the JWK at unlock, so a key resolved here is one the instance provably
    // holds a signer for. The address doubles as the source's key_ref, since an
    // Arweave signer is resolved by address.
    let keyring = unlock_keyring(config).context("unlocking the operator keyring")?;
    let funding_keys = keyring.arweave_funding_keys();
    let key = resolve_funding_key(&funding_keys, key_address)?;

    // Resolve the owning operator. A fresh self-host deployment has exactly one
    // operator (minted by `operator bootstrap`), so it is inferred; an explicit id
    // is required only on a multi-operator instance, where "the" operator is
    // ambiguous.
    let owner = resolve_owner_operator(pool, operator_id).await?;

    let outcome = bootstrap_service_source(
        pool,
        owner,
        label,
        backend,
        &key.address,
        // key_ref = the address: the keyring resolves an Arweave signer by address.
        &key.address,
    )
    .await
    .context("registering the service funding source")?;

    print_outcome(backend, &key.address, owner, &outcome);
    Ok(())
}

/// Pick the Arweave funding key to register from the keyring's verified set.
///
/// With one key in the keyring it is used directly (the single-key self-host case).
/// With several, `key_address` must name which one, so a multi-key keyring never
/// silently registers an arbitrary key. An empty keyring (no Arweave entry) is a
/// hard error: there is nothing to back a funding source, so a hash-only or
/// wallet-only deployment cannot bootstrap storage.
fn resolve_funding_key<'a>(
    keys: &'a [VerifiedArweaveKey],
    key_address: Option<&str>,
) -> Result<&'a VerifiedArweaveKey> {
    match key_address {
        Some(addr) => keys.iter().find(|k| k.address == addr).with_context(|| {
            format!("the keyring holds no Arweave funding key for address {addr}")
        }),
        None => match keys {
            [] => bail!(
                "the operator keyring holds no Arweave funding key, so there is no key to back a \
                 storage funding source; add an arweave-rsa entry to the keyring first"
            ),
            [only] => Ok(only),
            many => bail!(
                "the keyring holds {} Arweave funding keys; pass --key-address to choose which one \
                 backs the funding source",
                many.len()
            ),
        },
    }
}

/// Resolve the operator that owns the funding source.
///
/// An explicit id is used as-is (and verified to exist). With none, the single
/// bootstrapped operator is inferred — the self-host case after `operator
/// bootstrap`. Zero operators is a hard error (run `operator bootstrap` first); more
/// than one requires an explicit id, since "the" owner is then ambiguous.
async fn resolve_owner_operator(pool: &sqlx::PgPool, operator_id: Option<Uuid>) -> Result<Uuid> {
    if let Some(id) = operator_id {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cw_core.operator WHERE id = $1)")
                .bind(id)
                .fetch_one(pool)
                .await
                .context("checking the named operator exists")?;
        if !exists {
            bail!("no operator with id {id} exists; run `operator bootstrap` first");
        }
        return Ok(id);
    }

    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.operator ORDER BY id")
        .fetch_all(pool)
        .await
        .context("listing operators")?;
    match ids.as_slice() {
        [] => bail!(
            "this database has no operator; run `operator bootstrap` before `storage bootstrap`"
        ),
        [only] => Ok(*only),
        many => bail!(
            "this database has {} operators; pass --operator-id to choose which one owns the \
             funding source",
            many.len()
        ),
    }
}

/// Print the bootstrap result to stdout, framing what was provisioned and the next
/// step (the reconcile loop stamps the balance once the serving binary starts).
fn print_outcome(backend: &str, arweave_address: &str, owner: Uuid, outcome: &BootstrapOutcome) {
    println!("storage bootstrap complete");
    println!("  operator_id    {owner}");
    println!("  backend        {backend}");
    println!("  arweave_addr   {arweave_address}");
    println!(
        "  source_id      {} ({})",
        outcome.source_id,
        if outcome.source_created {
            "created"
        } else {
            "renamed in place (already registered)"
        }
    );
    println!(
        "  grant          service ({})",
        if outcome.grant_issued {
            "issued"
        } else {
            "already granted"
        }
    );
    println!();
    println!("  The source is drawable service-wide. Its winc balance is stamped by the");
    println!("  reconcile loop on the serving binary's first pass; fund the Arweave address");
    println!("  through the provider, then start the gateway and uploads will work.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(address: &str) -> VerifiedArweaveKey {
        VerifiedArweaveKey {
            label: "storage".to_string(),
            address: address.to_string(),
        }
    }

    #[test]
    fn normalizes_the_underscore_backend_alias_to_the_hyphen_form() {
        assert_eq!(normalize_backend("turbo"), Some("turbo"));
        assert_eq!(normalize_backend("direct-arweave"), Some("direct-arweave"));
        // The config/control alias maps to the one canonical persisted spelling, so
        // a bootstrap row and a later config never split a backend's credit pool.
        assert_eq!(normalize_backend("direct_arweave"), Some("direct-arweave"));
        assert_eq!(normalize_backend("arlocal"), Some("arlocal"));
        assert_eq!(normalize_backend("ipfs"), None);
    }

    #[test]
    fn a_single_keyring_key_is_inferred_without_an_explicit_address() {
        let keys = vec![key("addr-one")];
        let resolved = resolve_funding_key(&keys, None).expect("the single key is inferred");
        assert_eq!(resolved.address, "addr-one");
    }

    #[test]
    fn an_empty_keyring_cannot_bootstrap_storage() {
        let keys: Vec<VerifiedArweaveKey> = Vec::new();
        let err = resolve_funding_key(&keys, None)
            .expect_err("no Arweave key means nothing backs a funding source");
        assert!(
            err.to_string().contains("no Arweave funding key"),
            "the error explains there is no key to back a source, got: {err}"
        );
    }

    #[test]
    fn a_multi_key_keyring_requires_an_explicit_address() {
        let keys = vec![key("addr-one"), key("addr-two")];
        // Ambiguous without a selector: the bootstrap must not pick a key silently.
        let err = resolve_funding_key(&keys, None)
            .expect_err("two keys is ambiguous without --key-address");
        assert!(err.to_string().contains("--key-address"), "got: {err}");

        // The selector picks exactly the named key.
        let resolved = resolve_funding_key(&keys, Some("addr-two")).expect("named key resolves");
        assert_eq!(resolved.address, "addr-two");

        // A selector that names no held key is rejected, not silently ignored.
        let err = resolve_funding_key(&keys, Some("addr-missing"))
            .expect_err("an unheld address is rejected");
        assert!(err.to_string().contains("addr-missing"), "got: {err}");
    }
}
