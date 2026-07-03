//! Self-host bootstrap: stand up one drawable funding source in a single step.
//!
//! A single-key deployment should reach a working upload without any grant
//! choreography: register the Arweave funding source, make it drawable, and let
//! the reconcile loop stamp its balance. This module is the one orchestration that
//! ties the two row-level engine operations together for that common case.
//!
//! Two engine operations already exist as separate primitives: [`register_source`]
//! writes the source row, and [`issue_grant`] writes the draw grant. The control
//! plane's register route calls them in sequence; this module names that same pair
//! as a single, idempotent operation so the self-host path (and its end-to-end
//! test) has one entry point rather than re-deriving the sequence. It always issues
//! a `service`-scoped grant: a single-key, single-tenant deployment wants every
//! account on the instance drawable from its one source, with no per-operator or
//! per-account step. An operator that needs a tighter scope issues a narrower grant
//! through the control plane afterwards.
//!
//! Idempotency is end to end. A re-run against an already-bootstrapped source
//! renames the row in place (the same owner re-registering) and converges on the
//! existing live service grant rather than minting a second one (the per-backend
//! single-service-grant rule), so re-running bootstrap is always safe.

use uuid::Uuid;

use crate::storage::funding::{issue_grant, IssueOutcome, StorageGrantScope};
use crate::storage::source::{register_source, RegisterSourceOutcome};
use crate::{Error, Result};

/// The result of a self-host bootstrap.
///
/// Carries the ids the caller reports and re-runs against (the source and its live
/// service grant) plus the two idempotency flags, so a re-run is observably a
/// rename + converge rather than a fresh provision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapOutcome {
    /// The funding source that backs uploads on this backend.
    pub source_id: Uuid,
    /// The live `service` grant that makes the source drawable instance-wide.
    pub grant_id: Uuid,
    /// True when this call inserted a fresh source row (false on a re-run that
    /// renamed an existing one).
    pub source_created: bool,
    /// True when this call inserted a fresh service grant (false on a re-run that
    /// converged on the existing one).
    pub grant_issued: bool,
}

/// Register a `service`-scoped funding source under `owner_operator_id` and make it
/// drawable in one step, so a single-key deployment reaches a working upload with
/// no further grant choreography.
///
/// The address must be one the unlocked keyring physically holds a signer for; the
/// caller verifies that before calling (the keyring already derived the address
/// from the JWK at unlock), so a row is never written for an address no signer can
/// back. `key_ref` names the keyring entry; the existing convention is to store the
/// address itself, since the keyring resolves an Arweave signer by address.
///
/// Returns [`Error::Config`] only when the address is already a funding source owned
/// by a DIFFERENT operator: a global credit pool cannot be re-registered by a second
/// tenant, and the right expression of a shared key is the owner issuing a grant,
/// not a parallel bootstrap. Every other outcome (fresh provision, same-owner
/// re-run) succeeds idempotently.
///
/// This always grants the `service` scope: the self-host default is that the one
/// source funds every account on the instance. A deployment that wants a narrower
/// scope registers through the control plane (which honors `default_storage_scope`)
/// instead, then issues the tighter grant.
pub async fn bootstrap_service_source(
    pool: &sqlx::PgPool,
    owner_operator_id: Uuid,
    label: &str,
    backend: &str,
    arweave_address: &str,
    key_ref: &str,
) -> Result<BootstrapOutcome> {
    // Step one: write (or rename in place) the source row. A foreign-owned address
    // is the only hard failure: it is a genuine conflict the operator must resolve
    // out of band (the owner grants on the shared source), not something a retry
    // fixes, so it surfaces as an error rather than a silent no-op.
    let registered = match register_source(
        pool,
        owner_operator_id,
        label,
        backend,
        arweave_address,
        key_ref,
    )
    .await?
    {
        RegisterSourceOutcome::Registered(r) => r,
        RegisterSourceOutcome::AddressTaken { source_id } => {
            return Err(Error::Config(format!(
                "Arweave address {arweave_address} on backend {backend} is already a funding \
                 source ({source_id}) owned by another operator; a shared key is expressed by the \
                 owner issuing a grant, not by a second bootstrap"
            )));
        }
    };

    // Step two: make the source drawable service-wide. issue_grant is idempotent per
    // (backend, service): a re-run, or a second source on the same backend, converges
    // on the one live service grant rather than minting a second default. A None here
    // means the source vanished between the two writes (a concurrent delete) or its
    // ownership no longer resolves; report it as a config error rather than a
    // half-bootstrapped source the caller cannot tell apart from success.
    let issued = issue_grant(
        pool,
        owner_operator_id,
        registered.source_id,
        StorageGrantScope::Service,
    )
    .await?
    .ok_or_else(|| {
        Error::Config(format!(
            "funding source {} could not be granted the service scope (it was removed or its \
             ownership no longer resolves between register and grant)",
            registered.source_id
        ))
    })?;

    let (grant_id, grant_issued) = match issued {
        IssueOutcome::Issued { grant_id } => (grant_id, true),
        IssueOutcome::AlreadyGranted { grant_id } => (grant_id, false),
        // The backend's service default is already held by another operator. The
        // single-source rule allows one live service grant per backend, so a second
        // operator cannot bootstrap a competing service default; report it as a
        // config error (symmetric with the AddressTaken arm) rather than disclosing
        // the foreign grant.
        IssueOutcome::ServiceDefaultHeldByOtherOwner => {
            return Err(Error::Config(format!(
                "the service default for backend {backend} is already held by another operator; a \
                 backend carries one shared service funding default, so this source cannot be \
                 bootstrapped as a second default"
            )));
        }
    };

    Ok(BootstrapOutcome {
        source_id: registered.source_id,
        grant_id,
        source_created: registered.inserted,
        grant_issued,
    })
}
