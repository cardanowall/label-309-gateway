//! The scope registry helpers.
//!
//! Scopes are NOT a hardcoded enum: the legal set lives in `cw_core.api_scope`,
//! seeded with the core scopes and extended by a vendor with more rows. These
//! helpers name the core scopes the engine's own routes require, validate a
//! requested scope set against the registry at mint time, and check a scope
//! against a key's granted set. A vendor scope is just a string the registry
//! knows about; the engine never special-cases one.

use crate::{Error, Result};

/// The core scope a read endpoint requires (list, get, verify, PoE events).
pub const SCOPE_POE_READ: &str = "poe:read";

/// The core scope a create endpoint requires (quote, publish, uploads).
pub const SCOPE_POE_CREATE: &str = "poe:create";

/// The core scope a balance read requires (balance, balance events).
pub const SCOPE_ACCOUNT_READ: &str = "account:read";

/// The core scope a webhook read endpoint requires (list, read a subscription).
pub const SCOPE_WEBHOOKS_READ: &str = "webhooks:read";

/// The core scope a webhook write endpoint requires (create, patch, delete a
/// subscription).
pub const SCOPE_WEBHOOKS_WRITE: &str = "webhooks:write";

/// The scopes the engine's own routes enforce, in one place so the in-code
/// catalogue and the migration seed can be bound together by a test.
///
/// `billing:read` is seeded in the registry as a reserved core scope but gates
/// no engine route, so it is deliberately not in this list: this is the set a
/// data-plane guard can actually require, not the set of registered names.
pub const CORE_SCOPES: &[&str] = &[
    SCOPE_POE_READ,
    SCOPE_POE_CREATE,
    SCOPE_ACCOUNT_READ,
    SCOPE_WEBHOOKS_READ,
    SCOPE_WEBHOOKS_WRITE,
];

/// Whether a key's granted scopes include the required scope.
///
/// A pure set-membership check: the route names the scope it needs, the key
/// carries the scopes it was issued. No scope is special-cased here, so a vendor
/// scope authorizes the same way a core one does.
#[must_use]
pub fn authorizes(granted: &[String], required: &str) -> bool {
    granted.iter().any(|s| s == required)
}

/// Validate every requested scope exists in the registry.
///
/// The single registry check both issuing paths (api-key create and
/// account-token mint) share, so a credential is never minted carrying a scope
/// no route understands. An empty `scopes` is Ok — the caller decides whether
/// an empty set is legal for the credential it mints (a key requires at least
/// one scope; a token may carry none).
///
/// An unknown scope is an [`Error::Config`] whose message names every unknown
/// scope AND lists the registered names, so the caller can self-correct from
/// the error alone instead of having to query the registry out of band.
///
/// The executor is generic so the check can ride the caller's transaction (a
/// mint that commits atomically with its audit row) or run standalone against
/// a pool.
pub async fn validate_registered<'a, A>(executor: A, scopes: &[String]) -> Result<()>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    if scopes.is_empty() {
        return Ok(());
    }

    let registered: Vec<String> =
        sqlx::query_scalar("SELECT scope FROM cw_core.api_scope ORDER BY scope")
            .fetch_all(executor)
            .await?;

    let mut unknown: Vec<&String> = scopes
        .iter()
        .filter(|requested| !registered.contains(requested))
        .collect();
    unknown.sort();
    unknown.dedup();
    if unknown.is_empty() {
        return Ok(());
    }

    let unknown_list = unknown
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let registered_list = registered.join(", ");
    let (noun, verb) = if unknown.len() == 1 {
        ("scope", "is")
    } else {
        ("scopes", "are")
    };
    Err(Error::Config(format!(
        "{noun} {unknown_list} {verb} not registered; the registered scopes are: {registered_list}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizes_when_the_scope_is_granted() {
        let granted = vec![SCOPE_POE_READ.to_string(), SCOPE_POE_CREATE.to_string()];
        assert!(authorizes(&granted, SCOPE_POE_READ));
        assert!(authorizes(&granted, SCOPE_POE_CREATE));
    }

    #[test]
    fn rejects_a_missing_scope() {
        let granted = vec![SCOPE_POE_READ.to_string()];
        assert!(!authorizes(&granted, SCOPE_POE_CREATE));
        assert!(!authorizes(&granted, SCOPE_ACCOUNT_READ));
    }

    #[test]
    fn authorizes_an_arbitrary_vendor_scope() {
        // The engine does not special-case core scopes: a vendor scope present in
        // the granted set authorizes the same way.
        let granted = vec!["vendor:custom".to_string()];
        assert!(authorizes(&granted, "vendor:custom"));
    }
}
