//! The data-plane middleware: authentication, rate limiting, idempotency.
//!
//! Each concern is a focused module the route layer composes:
//!
//! - [`auth`] — resolve and authorize a Bearer credential against
//!   `cw_core.api_key` (8-byte lookup prefix + constant-time full-hash compare),
//!   producing a [`auth::Viewer`] the handler reads the account and scopes from.
//! - [`rate_limit`] — a restart-survivable sliding-window limiter over
//!   `cw_core.rate_limit_bucket` that emits the IETF `RateLimit-*` headers and a
//!   `Retry-After` on a 429.
//! - [`idempotency`] — byte-for-byte replay of a prior committed response for a
//!   repeated `(account, Idempotency-Key)` pair, with a conflict on a changed
//!   payload and a non-committing carve-out for 402s.
//! - [`scope`] — the extensible scope registry helpers.

pub mod auth;
pub mod idempotency;
pub mod rate_limit;
pub mod scope;
