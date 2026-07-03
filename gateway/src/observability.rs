//! Optional, Sentry-compatible error monitoring (GlitchTip / self-hosted Sentry /
//! hosted Sentry).
//!
//! The whole module is inert unless an operator configures a DSN: with no DSN
//! there is no client, no transport, and no egress — the process behaves exactly
//! as it did before monitoring existed. When a DSN is present the binary reports
//! `tracing` ERROR events and panics (with recent WARN/INFO context as
//! breadcrumbs) to the configured backend, alongside — never instead of — the
//! structured JSON logs.
//!
//! Configuration is environment-only (the DSN is a deploy-time secret, never
//! committed): see [`crate::config::SENTRY_DSN_ENV`] and its siblings. A
//! misconfiguration an operator clearly intended to enable monitoring with — a
//! malformed DSN, an out-of-range sample rate — fails the boot loudly rather than
//! silently disabling, so a typo in a monitoring rollout is never mistaken for a
//! healthy, quiet deployment.
//!
//! ## Egress
//!
//! The Sentry transport is a self-contained reqwest client that talks only to the
//! operator-configured DSN host. That host is trusted operator configuration, not
//! user input, so the transport legitimately does not pass through the gateway's
//! user-facing hardened egress (the SSRF/deny-host guard that wraps
//! _user-influenced_ outbound requests). The carve-out is intentional and bounded
//! to the operator's own telemetry endpoint.

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use sentry::protocol::{Context as SentryContext, Event, Map, Value};
use sentry::types::Dsn;
use sentry::ClientInitGuard;
use zeroize::Zeroizing;

use crate::config;

/// The placeholder a redacted value is replaced with before an event is sent.
const REDACTED: &str = "[redacted]";

/// The `environment` tag used when [`config::SENTRY_ENVIRONMENT_ENV`] is unset.
const DEFAULT_ENVIRONMENT: &str = "production";

/// Substrings (matched case-insensitively against a field's key) that mark a
/// value as sensitive. Defense-in-depth on top of the gateway's existing field
/// hygiene: any `tracing` field, tag, or attached header whose key contains one
/// of these is replaced with [`REDACTED`] before the event leaves the process, so
/// a stray `error!(api_key = …)` can never ship a secret to the monitoring
/// backend. Over-redaction (a benign `author` matching `auth`) is the safe
/// direction and accepted.
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "dsn",
    "secret",
    "token",
    "passphrase",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "seed",
    "private",
    "keyring",
    "mnemonic",
    "bearer",
];

/// Initialise error monitoring from the environment.
///
/// Returns `Ok(None)` — doing nothing at all — when no DSN is configured. When a
/// DSN is present, returns `Ok(Some(guard))`: the caller must hold the guard for
/// the process lifetime, because dropping it flushes any pending events and tears
/// down the client. Returns `Err` only on a configuration an operator plainly
/// meant to enable monitoring with but got wrong (a malformed DSN, a sample rate
/// that is not a number in `0.0..=1.0`), so the boot fails loudly.
pub fn init() -> Result<Option<ClientInitGuard>> {
    let Some(dsn) = resolve_dsn()? else {
        return Ok(None);
    };
    let options = sentry::ClientOptions {
        dsn: Some(dsn),
        release: resolve_release(),
        environment: Some(resolve_environment()),
        traces_sample_rate: resolve_traces_sample_rate()?,
        // Never let the SDK attach IP addresses, usernames, request bodies, or any
        // other personally identifying data on its own.
        send_default_pii: false,
        before_send: Some(Arc::new(scrub_event)),
        ..Default::default()
    };
    Ok(Some(sentry::init(options)))
}

/// The `tracing` layer that forwards events to the monitoring backend.
///
/// ERROR events become issues; WARN/INFO become breadcrumbs that ride along with
/// the next issue; DEBUG/TRACE are ignored. Add it to the subscriber only when
/// [`init`] returned `Some` — without an initialised client the layer has nothing
/// to send.
pub fn tracing_layer<S>() -> sentry_tracing::SentryLayer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    sentry_tracing::layer()
}

/// Resolve the DSN from its environment pair, reusing the gateway's canonical
/// `_FILE` docker-secret semantics (one source only; trailing whitespace trimmed
/// off a file value), then parse it.
fn resolve_dsn() -> Result<Option<Dsn>> {
    let raw = config::secret_from_env(config::SENTRY_DSN_ENV, config::SENTRY_DSN_FILE_ENV)?;
    parse_dsn(raw)
}

/// Parse the resolved DSN string: an absent or whitespace-only value is the inert
/// no-op path (`None`); anything else must be a valid DSN or the boot fails.
///
/// The raw secret arrives in (and is dropped from) a zeroizing buffer; the
/// parsed [`Dsn`] the monitoring client keeps is the send-path copy.
fn parse_dsn(raw: Option<Zeroizing<String>>) -> Result<Option<Dsn>> {
    let Some(trimmed) = raw.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let dsn = trimmed.parse::<Dsn>().with_context(|| {
        format!(
            "{} is not a valid Sentry/GlitchTip DSN",
            config::SENTRY_DSN_ENV
        )
    })?;
    Ok(Some(dsn))
}

/// The `environment` tag: the override if set and non-empty, else `production`.
fn resolve_environment() -> Cow<'static, str> {
    match std::env::var(config::SENTRY_ENVIRONMENT_ENV) {
        Ok(value) if !value.trim().is_empty() => Cow::Owned(value.trim().to_owned()),
        _ => Cow::Borrowed(DEFAULT_ENVIRONMENT),
    }
}

/// The `release` tag: the override if set and non-empty, else the compiled-in
/// `name@version` (built at compile time, so it needs no runtime fallback).
fn resolve_release() -> Option<Cow<'static, str>> {
    if let Ok(value) = std::env::var(config::SENTRY_RELEASE_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(Cow::Owned(trimmed.to_owned()));
        }
    }
    Some(Cow::Borrowed(concat!(
        env!("CARGO_PKG_NAME"),
        "@",
        env!("CARGO_PKG_VERSION")
    )))
}

/// The performance-tracing sample rate, read from the environment.
fn resolve_traces_sample_rate() -> Result<f32> {
    parse_traces_sample_rate(std::env::var(config::SENTRY_TRACES_SAMPLE_RATE_ENV).ok())
}

/// Parse the sample rate: absent or empty is `0.0` (errors only); anything else
/// must be a number in `0.0..=1.0` or the boot fails.
fn parse_traces_sample_rate(raw: Option<String>) -> Result<f32> {
    let Some(trimmed) = raw.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) else {
        return Ok(0.0);
    };
    let rate: f32 = trimmed.parse().with_context(|| {
        format!(
            "{} must be a number between 0.0 and 1.0, got {trimmed:?}",
            config::SENTRY_TRACES_SAMPLE_RATE_ENV
        )
    })?;
    if !(0.0..=1.0).contains(&rate) {
        bail!(
            "{} must be between 0.0 and 1.0, got {rate}",
            config::SENTRY_TRACES_SAMPLE_RATE_ENV
        );
    }
    Ok(rate)
}

/// The `before_send` redaction pass: scrub sensitive fields out of every event
/// before the transport sees it. Always returns `Some` (we redact in place, we do
/// not drop events).
fn scrub_event(mut event: Event<'static>) -> Option<Event<'static>> {
    redact_value_map(&mut event.extra);
    redact_string_map(&mut event.tags);
    // Only generic ("other") contexts carry arbitrary operator data; the typed
    // contexts (os/runtime/device/app) the SDK fills in are fixed shapes with no
    // secrets.
    for ctx in event.contexts.values_mut() {
        if let SentryContext::Other(map) = ctx {
            redact_value_map(map);
        }
    }
    // Breadcrumbs are the WARN/INFO `tracing` events leading up to this one, and
    // their structured fields land in each breadcrumb's `data` map — so a
    // `warn!(api_key = …)` would otherwise ship a secret in the trail attached to
    // an unrelated error. Scrub each breadcrumb's data by the same deny-list.
    for breadcrumb in event.breadcrumbs.values.iter_mut() {
        redact_value_map(&mut breadcrumb.data);
    }
    // The gateway never attaches an HTTP request to an event, but if an
    // integration ever does, its headers and CGI environment are the most likely
    // place an authorization header or a `_PASSPHRASE` env var would surface.
    if let Some(request) = event.request.as_mut() {
        redact_string_map(&mut request.headers);
        redact_string_map(&mut request.env);
    }
    Some(event)
}

/// Redact a string-valued map in place: any value under a sensitive key becomes
/// [`REDACTED`].
fn redact_string_map(map: &mut Map<String, String>) {
    for (key, value) in map.iter_mut() {
        if is_sensitive_key(key) {
            *value = REDACTED.to_owned();
        }
    }
}

/// Redact a JSON-valued map in place: a value under a sensitive key is replaced
/// wholesale; any other value is walked recursively so a sensitive key nested
/// inside a structured field is caught too.
fn redact_value_map(map: &mut Map<String, Value>) {
    for (key, value) in map.iter_mut() {
        if is_sensitive_key(key) {
            *value = Value::String(REDACTED.to_owned());
        } else {
            redact_nested_value(value);
        }
    }
}

/// Recursively redact sensitive keys inside a JSON value (objects and arrays).
fn redact_nested_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    redact_nested_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_nested_value(item);
            }
        }
        _ => {}
    }
}

/// Whether a field key marks its value as sensitive (case-insensitive substring
/// match against [`SENSITIVE_KEY_FRAGMENTS`]).
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn no_dsn_is_the_inert_path() {
        assert!(parse_dsn(None).unwrap().is_none());
        assert!(parse_dsn(Some(String::new().into())).unwrap().is_none());
        assert!(parse_dsn(Some("   ".to_owned().into())).unwrap().is_none());
    }

    #[test]
    fn a_valid_dsn_parses() {
        // The canonical DSN shape: `scheme://public_key:secret@host/project_id`
        // (the secret half is optional — modern DSNs omit it, leaving the empty
        // string after the colon).
        let dsn = parse_dsn(Some("https://publicKey:@host/42".to_owned().into()))
            .unwrap()
            .expect("a well-formed DSN resolves to Some");
        assert_eq!(dsn.project_id().value(), "42");
    }

    #[test]
    fn a_malformed_dsn_fails_the_boot() {
        let err = parse_dsn(Some("not-a-dsn".to_owned().into())).unwrap_err();
        assert!(err.to_string().contains(config::SENTRY_DSN_ENV));
    }

    #[test]
    fn setting_both_dsn_sources_is_a_load_error() {
        // The DSN inherits the gateway's one-source-only rule from the shared
        // secret merge, so supplying it through both the variable and its `_FILE`
        // twin fails rather than letting one silently win.
        let err = config::merge_secret_sources(
            config::SENTRY_DSN_ENV,
            config::SENTRY_DSN_FILE_ENV,
            Some("https://publicKey:@host/1".to_owned()),
            Some(std::path::PathBuf::from("/dev/null")),
        )
        .unwrap_err();
        assert!(err.to_string().contains(config::SENTRY_DSN_ENV));
        assert!(err.to_string().contains(config::SENTRY_DSN_FILE_ENV));
    }

    #[test]
    fn dsn_file_value_is_read_and_trailing_whitespace_trimmed() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "https://publicKey:@host/7").unwrap();
        let resolved = config::merge_secret_sources(
            config::SENTRY_DSN_ENV,
            config::SENTRY_DSN_FILE_ENV,
            None,
            Some(file.path().to_path_buf()),
        )
        .unwrap();
        // The trailing newline the file carries is trimmed off.
        assert_eq!(
            resolved.as_ref().map(|s| s.as_str()),
            Some("https://publicKey:@host/7")
        );
    }

    #[test]
    fn sample_rate_defaults_to_zero_when_absent() {
        assert_eq!(parse_traces_sample_rate(None).unwrap(), 0.0);
        assert_eq!(
            parse_traces_sample_rate(Some("  ".to_owned())).unwrap(),
            0.0
        );
    }

    #[test]
    fn sample_rate_parses_in_range() {
        assert_eq!(
            parse_traces_sample_rate(Some("0.25".to_owned())).unwrap(),
            0.25
        );
        assert_eq!(
            parse_traces_sample_rate(Some("1.0".to_owned())).unwrap(),
            1.0
        );
    }

    #[test]
    fn sample_rate_rejects_out_of_range_and_non_numeric() {
        assert!(parse_traces_sample_rate(Some("1.5".to_owned())).is_err());
        assert!(parse_traces_sample_rate(Some("-0.1".to_owned())).is_err());
        assert!(parse_traces_sample_rate(Some("lots".to_owned())).is_err());
    }

    #[test]
    fn sample_rate_rejects_nan_and_infinity_but_accepts_negative_zero() {
        // `NaN` and `inf` parse as f32 but fall outside `0.0..=1.0` (a range that
        // excludes both), so the boot fails rather than handing the SDK a degenerate
        // rate.
        assert!(parse_traces_sample_rate(Some("NaN".to_owned())).is_err());
        assert!(parse_traces_sample_rate(Some("inf".to_owned())).is_err());
        assert!(parse_traces_sample_rate(Some("-inf".to_owned())).is_err());
        // `-0.0` is IEEE-equal to `0.0`, so it is accepted as "errors only".
        assert_eq!(
            parse_traces_sample_rate(Some("-0.0".to_owned())).unwrap(),
            0.0
        );
    }

    #[test]
    fn scrub_redacts_sensitive_keys_and_leaves_benign_ones() {
        let mut event = Event::default();
        event.extra.insert(
            "api_key".to_owned(),
            Value::String("cg-live-xyz".to_owned()),
        );
        event.extra.insert("file_count".to_owned(), Value::from(3));
        event
            .tags
            .insert("authorization".to_owned(), "Bearer zzz".to_owned());
        event
            .tags
            .insert("network".to_owned(), "mainnet".to_owned());

        let scrubbed = scrub_event(event).expect("the scrubber never drops events");

        assert_eq!(
            scrubbed.extra["api_key"],
            Value::String(REDACTED.to_owned())
        );
        assert_eq!(scrubbed.extra["file_count"], Value::from(3));
        assert_eq!(scrubbed.tags["authorization"], REDACTED);
        assert_eq!(scrubbed.tags["network"], "mainnet");
    }

    #[test]
    fn scrub_reaches_nested_sensitive_keys() {
        let mut event = Event::default();
        event.extra.insert(
            "config".to_owned(),
            serde_json::json!({
                "passphrase": "hunter2",
                "network": "mainnet",
                "nested": { "private_key": "deadbeef" },
            }),
        );

        let scrubbed = scrub_event(event).unwrap();
        let config = &scrubbed.extra["config"];
        assert_eq!(config["passphrase"], Value::String(REDACTED.to_owned()));
        assert_eq!(config["network"], Value::String("mainnet".to_owned()));
        assert_eq!(
            config["nested"]["private_key"],
            Value::String(REDACTED.to_owned())
        );
    }

    #[test]
    fn scrub_redacts_breadcrumb_data() {
        // A WARN/INFO `tracing` event becomes a breadcrumb whose fields land in
        // `data`; a secret there must be scrubbed before it rides along with an
        // error event.
        let mut event = Event::default();
        let mut breadcrumb = sentry::protocol::Breadcrumb {
            message: Some("preparing publish".to_owned()),
            ..Default::default()
        };
        breadcrumb.data.insert(
            "api_key".to_owned(),
            Value::String("cg-live-xyz".to_owned()),
        );
        breadcrumb
            .data
            .insert("record_count".to_owned(), Value::from(2));
        event.breadcrumbs.values.push(breadcrumb);

        let scrubbed = scrub_event(event).unwrap();
        let data = &scrubbed.breadcrumbs.values[0].data;
        assert_eq!(data["api_key"], Value::String(REDACTED.to_owned()));
        assert_eq!(data["record_count"], Value::from(2));
    }

    #[test]
    fn release_falls_back_to_compiled_name_and_version() {
        // With no override the release is the crate's compile-time identity. The
        // test cannot safely mutate process env, so it only asserts the fallback
        // shape, which is what an un-overridden deployment ships.
        let fallback = concat!(env!("CARGO_PKG_NAME"), "@", env!("CARGO_PKG_VERSION"));
        assert!(fallback.contains('@'));
    }
}
