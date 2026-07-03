//! Typed principals: the privilege-confusion fix.
//!
//! Every authenticated caller resolves to a [`Principal`], an enum that makes the
//! caller's authority a type rather than an implicit property of which table the
//! credential came from. The data plane and the control plane each accept a
//! specific subset, enforced at the type level by pattern-matching the enum, so a
//! credential can never be used on a surface it was not minted for:
//!
//!   - the DATA plane accepts [`Principal::ApiKey`] and [`Principal::AccountToken`]
//!     only (both account-bound; the account token is the dogfood bridge), and
//!     rejects an operator token presented to it;
//!   - the CONTROL plane's operator routes accept [`Principal::OperatorToken`] and
//!     [`Principal::OperatorRoot`] only;
//!   - the CONTROL plane's account-level routes accept an [`Principal::AccountToken`]
//!     acting on itself, or an operator principal acting on a named account.
//!
//! Resolution ([`resolve_principal`]) inspects the Bearer secret against all three
//! credential stores in turn (api key, access token, root credential) and returns
//! the first match as its typed principal. A secret that matches none resolves to
//! [`AuthOutcome::Unknown`].

use uuid::Uuid;

use crate::api::control::credential::{resolve_access_token, resolve_root_credential};
use crate::api::middleware::auth::resolve_bearer;
use crate::Result;

/// An authenticated caller, typed by the authority its credential carries.
///
/// The variant IS the authority: a route authorizes by matching the variants it
/// accepts, so a credential minted for one surface cannot be replayed on another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A data-plane api key: account-bound, carrying the scopes the key was
    /// issued. The third-party caller of the data plane.
    ApiKey {
        /// The api-key row id (the rate-limit subject and audit handle).
        key_id: Uuid,
        /// The account the key belongs to.
        account_id: Uuid,
        /// The scopes the key was granted.
        scopes: Vec<String>,
        /// The key's custom per-minute request budget, or `None` to meter
        /// against the data-plane default.
        rate_limit_per_min: Option<i32>,
    },
    /// A short-lived account-scoped access token: account-bound, carrying the
    /// data-plane scopes it may exercise. The dogfood bridge a wrapper uses, and
    /// the credential an account-level control route accepts for self-service.
    AccountToken {
        /// The token row id (the audit handle).
        token_id: Uuid,
        /// The operator that owns the token.
        operator_id: Uuid,
        /// The account the token is scoped to.
        account_id: Uuid,
        /// The data-plane scopes the token carries.
        scopes: Vec<String>,
        /// The token's custom per-minute request budget, or `None` to meter
        /// against the data-plane default.
        rate_limit_per_min: Option<i32>,
    },
    /// A short-lived operator access token: authorizes the operator control
    /// surface. Carries no account binding.
    OperatorToken {
        /// The token row id (the audit handle).
        token_id: Uuid,
        /// The operator the token authorizes.
        operator_id: Uuid,
    },
    /// The long-lived operator root credential: the single bearer that may mint
    /// operator tokens. Authorizes the operator control surface directly too, so
    /// the bootstrap path is usable before a token is minted.
    OperatorRoot {
        /// The credential row id (the audit handle).
        credential_id: Uuid,
        /// The operator the credential authorizes.
        operator_id: Uuid,
    },
}

impl Principal {
    /// The operator this principal acts under, when it is an operator principal.
    /// `None` for an account-bound principal that carries no operator authority.
    #[must_use]
    pub fn operator_id(&self) -> Option<Uuid> {
        match self {
            Principal::OperatorToken { operator_id, .. }
            | Principal::OperatorRoot { operator_id, .. }
            | Principal::AccountToken { operator_id, .. } => Some(*operator_id),
            Principal::ApiKey { .. } => None,
        }
    }

    /// The account this principal is bound to, when it is account-scoped.
    #[must_use]
    pub fn account_id(&self) -> Option<Uuid> {
        match self {
            Principal::ApiKey { account_id, .. } | Principal::AccountToken { account_id, .. } => {
                Some(*account_id)
            }
            Principal::OperatorToken { .. } | Principal::OperatorRoot { .. } => None,
        }
    }

    /// Whether this principal carries operator authority (a token or the root).
    #[must_use]
    pub fn is_operator(&self) -> bool {
        matches!(
            self,
            Principal::OperatorToken { .. } | Principal::OperatorRoot { .. }
        )
    }

    /// The audit `actor_kind` token this principal records its actions under.
    #[must_use]
    pub fn actor_kind(&self) -> &'static str {
        if self.is_operator() {
            "operator"
        } else {
            "account"
        }
    }

    /// The audit `actor_id` this principal records: the operator id for an
    /// operator principal, the account id for an account principal.
    #[must_use]
    pub fn actor_id(&self) -> Option<Uuid> {
        if self.is_operator() {
            self.operator_id()
        } else {
            self.account_id()
        }
    }

    /// The row id of the credential this principal authenticated with, across
    /// the three stores (api key, access token, root credential).
    ///
    /// This is the MINT LINEAGE handle: a token minted under this principal
    /// records it as `minted_by`, and revoking this exact row invalidates the
    /// token (and everything beneath it) at resolve time. Distinct from
    /// [`Principal::actor_id`], which names the operator/account the principal
    /// acts FOR, not the credential row it authenticated WITH.
    #[must_use]
    pub fn credential_row_id(&self) -> Uuid {
        match self {
            Principal::ApiKey { key_id, .. } => *key_id,
            Principal::AccountToken { token_id, .. }
            | Principal::OperatorToken { token_id, .. } => *token_id,
            Principal::OperatorRoot { credential_id, .. } => *credential_id,
        }
    }
}

/// The outcome of resolving a Bearer secret to a principal.
///
/// A malformed/empty header and an unknown-or-revoked credential both collapse to
/// [`AuthOutcome::Unknown`] at the HTTP boundary (a 401) so a scanner cannot tell
/// a malformed credential from a well-formed but unknown one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The secret resolved to a typed principal.
    Resolved(Principal),
    /// The secret matched no live credential.
    Unknown,
}

/// Resolve a Bearer secret to its typed principal across all credential stores.
///
/// Tried in order: a data-plane api key, then a short-lived access token (account
/// or operator), then the operator root credential. The first store that matches
/// fixes the principal's type; a secret matching none resolves to
/// [`AuthOutcome::Unknown`]. The stores partition by hash, so at most one matches
/// any given secret.
pub async fn resolve_principal(pool: &sqlx::PgPool, secret: &str) -> Result<AuthOutcome> {
    // Api key: the hot path (most data-plane traffic), tried first.
    if let Ok(viewer) = resolve_bearer(pool, secret).await? {
        return Ok(AuthOutcome::Resolved(Principal::ApiKey {
            key_id: viewer.key_id,
            account_id: viewer.account_id,
            scopes: viewer.scopes,
            rate_limit_per_min: viewer.rate_limit_per_min,
        }));
    }

    // Access token: an account-scoped token (dogfood bridge / self-service) or an
    // operator token (the operator control surface).
    if let Some(token) = resolve_access_token(pool, secret).await? {
        let principal = match token.account_id {
            Some(account_id) => Principal::AccountToken {
                token_id: token.token_id,
                operator_id: token.operator_id,
                account_id,
                scopes: token.scopes,
                rate_limit_per_min: token.rate_limit_per_min,
            },
            None => Principal::OperatorToken {
                token_id: token.token_id,
                operator_id: token.operator_id,
            },
        };
        return Ok(AuthOutcome::Resolved(principal));
    }

    // Operator root: the long-lived bootstrap bearer that mints operator tokens.
    if let Some(root) = resolve_root_credential(pool, secret).await? {
        return Ok(AuthOutcome::Resolved(Principal::OperatorRoot {
            credential_id: root.credential_id,
            operator_id: root.operator_id,
        }));
    }

    Ok(AuthOutcome::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_key() -> Principal {
        Principal::ApiKey {
            key_id: Uuid::now_v7(),
            account_id: Uuid::now_v7(),
            scopes: vec!["poe:read".into()],
            rate_limit_per_min: Some(60),
        }
    }

    #[test]
    fn data_plane_principals_carry_an_account_and_no_operator_authority() {
        let acct = Uuid::now_v7();
        let token = Principal::AccountToken {
            token_id: Uuid::now_v7(),
            operator_id: Uuid::now_v7(),
            account_id: acct,
            scopes: vec![],
            rate_limit_per_min: None,
        };
        assert_eq!(token.account_id(), Some(acct));
        assert!(!token.is_operator());
        assert!(api_key().account_id().is_some());
        assert!(!api_key().is_operator());
    }

    #[test]
    fn operator_principals_carry_operator_authority_and_no_account() {
        let op = Uuid::now_v7();
        let tok = Principal::OperatorToken {
            token_id: Uuid::now_v7(),
            operator_id: op,
        };
        assert!(tok.is_operator());
        assert_eq!(tok.operator_id(), Some(op));
        assert_eq!(tok.account_id(), None);

        let root = Principal::OperatorRoot {
            credential_id: Uuid::now_v7(),
            operator_id: op,
        };
        assert!(root.is_operator());
        assert_eq!(root.operator_id(), Some(op));
        assert_eq!(root.account_id(), None);
    }

    #[test]
    fn actor_kind_and_id_track_the_principal_class() {
        let op = Uuid::now_v7();
        let acct = Uuid::now_v7();
        let operator = Principal::OperatorToken {
            token_id: Uuid::now_v7(),
            operator_id: op,
        };
        assert_eq!(operator.actor_kind(), "operator");
        assert_eq!(operator.actor_id(), Some(op));

        let account = Principal::AccountToken {
            token_id: Uuid::now_v7(),
            operator_id: op,
            account_id: acct,
            scopes: vec![],
            rate_limit_per_min: None,
        };
        assert_eq!(account.actor_kind(), "account");
        assert_eq!(account.actor_id(), Some(acct));
    }
}
