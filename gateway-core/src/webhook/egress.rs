//! The hardened webhook delivery egress.
//!
//! A webhook target is a user-supplied URL — the textbook SSRF vector. Rather than
//! build a new chokepoint, delivery reuses the SDK's `Webhook`-purpose egress,
//! which is already a dependency of this crate and is unit-tested there:
//!
//! 1. [`assert_webhook_url_safe`] parses the URL (HTTPS only by default; `http://`
//!    only under the self-host/dev opt-in), resolves A+AAAA, and rejects the whole
//!    request if any resolved address falls in a blocked range (private, loopback,
//!    link-local `169.254.0.0/16`, multicast, IPv4-mapped IPv6, the cloud-metadata
//!    IP). It returns the validated IP.
//! 2. [`ReqwestTransport::pinned`] pins the TCP connection to that IP, refuses to
//!    resolve any other host (closing the DNS-rebind window), follows no redirect
//!    (`Policy::none`), and ignores proxy environment inheritance (`HTTP_PROXY` /
//!    `HTTPS_PROXY` / `ALL_PROXY` cannot re-route the socket around the IP pin).
//!
//! A redirect toward `169.254.169.254` is therefore structurally impossible: the
//! connection is pinned to a pre-validated public IP and redirects are not
//! followed. The response body is discarded — only the status decides the outcome.
//!
//! # Config seams
//!
//! [`EgressConfig`] carries the two self-host/test toggles, mapped onto the SDK
//! guard's two INDEPENDENT loosenings by [`EgressConfig::assert_options`] — the
//! one mapping the registration guards (data and control plane) and every
//! delivery share. `allow_insecure_http` permits `http://` targets and nothing
//! else: the loopback/private/link-local/metadata range-block stays enforced, so
//! a self-hosted deployment delivering to an internal plain-HTTP endpoint never
//! opens an SSRF path for its tenants. `allow_loopback` maps to the SDK's
//! test-only `allow_private_for_tests` seam so the conformance harness can reach
//! a loopback receiver. Both default off, so production keeps the full
//! HTTPS-only, public-IP-only guard.

use cardanowall::verifier::fetch::{
    assert_webhook_url_safe, AssertWebhookUrlSafeOptions, FetchOutboundOptions, FetchTransport,
    HttpMethod, HttpPurpose, ReqwestTransport, WebhookUrlUnsafeError,
};

/// Self-host / test toggles for the delivery egress.
///
/// Both default off, so a production instance delivers only to HTTPS endpoints
/// that resolve to a public IP. A self-hosted or test deployment opts in to the
/// looser modes explicitly.
#[derive(Debug, Clone, Copy, Default)]
pub struct EgressConfig {
    /// Allow `http://` targets (self-host/dev). Off in production, where only
    /// `https://` is accepted. Loosens ONLY the scheme requirement: the
    /// loopback/private range-block stays enforced regardless.
    pub allow_insecure_http: bool,
    /// Allow loopback/private targets — the SDK's `allow_private_for_tests` seam.
    /// Off in production; the conformance harness turns it on to reach a local
    /// receiver. Loosens ONLY the range-block: plain `http://` still requires
    /// `allow_insecure_http`.
    pub allow_loopback: bool,
}

impl EgressConfig {
    /// The SDK-guard options this config maps to — the single point where the
    /// gateway's two webhook knobs meet the guard, shared by the registration
    /// guards on both planes (via [`crate::api::WebhookState::egress_config`])
    /// and by every delivery, so the posture can never split between the two
    /// stages.
    ///
    /// The mapping keeps the two axes independent: `allow_insecure_http`
    /// loosens only the scheme requirement and `allow_loopback` loosens only
    /// the IP range-block. A tenant-supplied `http://` target pointing at a
    /// private, loopback, link-local, or cloud-metadata address is therefore
    /// refused even on a deployment that legitimately delivers to internal
    /// plain-HTTP endpoints.
    #[must_use]
    pub fn assert_options(self) -> AssertWebhookUrlSafeOptions<'static> {
        AssertWebhookUrlSafeOptions {
            allow_http_scheme: self.allow_insecure_http,
            allow_private_for_tests: self.allow_loopback,
            resolve_host: None,
        }
    }
}

/// The outcome of one delivery attempt.
///
/// The delivery worker classifies these: an `Ok(status)` in the 2xx range is a
/// success, any other status or an `Err` is a transient failure that consumes an
/// attempt and re-schedules with backoff. `Refused` is the SSRF-guard rejection,
/// which the worker also treats as a (non-retryable-at-the-URL but attempt-
/// consuming) failure since the URL was validated at registration and a later
/// resolution change is the only way it fails here.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The target URL was judged unsafe by the SSRF guard (blocked range, non-
    /// HTTPS without the opt-in, DNS failure, or an unparseable URL).
    #[error("webhook target refused by egress guard: {0}")]
    Refused(#[from] WebhookUrlUnsafeError),
    /// The transport failed (connection refused, timeout, TLS error, body read).
    #[error("webhook delivery transport error: {0}")]
    Transport(String),
}

/// The status of a completed delivery attempt that reached the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryResponse {
    /// The HTTP status the endpoint returned.
    pub status: u16,
}

impl DeliveryResponse {
    /// Whether the endpoint acknowledged the delivery (`2xx`).
    #[must_use]
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Validate `url` through the SSRF guard and POST `body` to it with `headers`,
/// pinning the connection to the validated IP.
///
/// Blocking: it drives the SDK's blocking pinned transport, so the delivery worker
/// calls it on a blocking task. Returns the endpoint's HTTP status on a completed
/// request, or a [`DeliveryError`] when the URL is refused or the transport fails.
/// The response body is never read past the status — only the status matters.
pub fn deliver(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
    config: EgressConfig,
) -> Result<DeliveryResponse, DeliveryError> {
    let safe = assert_webhook_url_safe(url, &config.assert_options())?;

    // Pin the connection to the IP the guard validated; the SDK transport refuses
    // any other host, follows no redirect, and ignores proxy env on this path.
    let transport = ReqwestTransport::pinned(safe.hostname, safe.resolved_ip);

    let mut opts = FetchOutboundOptions::new(HttpMethod::Post, HttpPurpose::Webhook);
    opts.headers = headers.to_vec();
    opts.body = Some(String::from_utf8_lossy(body).into_owned());
    // The response body is irrelevant to a webhook ack, but a hostile endpoint
    // could stream an unbounded body; cap it small so the status is all we buffer.
    opts.max_bytes = Some(MAX_RESPONSE_BYTES);

    let result = transport
        .fetch(url, &opts)
        .map_err(|e| DeliveryError::Transport(e.to_string()))?;

    Ok(DeliveryResponse {
        status: result.status,
    })
}

/// The response-body cap for a delivery: a webhook ack carries no payload we read,
/// so a small bound is enough and a hostile endpoint cannot force a large buffer.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use cardanowall::verifier::fetch::WebhookUrlUnsafeReason;

    #[test]
    fn delivery_response_success_is_2xx_only() {
        assert!(DeliveryResponse { status: 200 }.is_success());
        assert!(DeliveryResponse { status: 204 }.is_success());
        assert!(DeliveryResponse { status: 299 }.is_success());
        assert!(!DeliveryResponse { status: 300 }.is_success());
        assert!(!DeliveryResponse { status: 199 }.is_success());
        assert!(!DeliveryResponse { status: 500 }.is_success());
    }

    #[test]
    fn production_config_refuses_a_blocked_range_target() {
        // Default config (production): a literal private IP is refused by the
        // guard before any socket is opened.
        let err =
            deliver("https://10.0.0.1/hook", b"{}", &[], EgressConfig::default()).unwrap_err();
        assert!(matches!(err, DeliveryError::Refused(_)));
    }

    #[test]
    fn production_config_refuses_loopback_and_metadata() {
        for url in [
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/hook",
        ] {
            let err = deliver(url, b"{}", &[], EgressConfig::default()).unwrap_err();
            assert!(
                matches!(err, DeliveryError::Refused(_)),
                "{url} must be refused by the production egress"
            );
        }
    }

    #[test]
    fn production_config_refuses_plain_http() {
        let err = deliver(
            "http://example.com/hook",
            b"{}",
            &[],
            EgressConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, DeliveryError::Refused(_)));
    }

    #[test]
    fn insecure_http_optin_keeps_the_range_block() {
        // The self-host scheme opt-in must NOT loosen the SSRF range-block: a
        // tenant-supplied plain-HTTP target in a blocked range is refused at
        // delivery exactly as under the default config, before any socket opens.
        let config = EgressConfig {
            allow_insecure_http: true,
            allow_loopback: false,
        };
        for url in [
            "http://127.0.0.1/hook",
            "http://10.0.0.1/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/hook",
        ] {
            match deliver(url, b"{}", &[], config).unwrap_err() {
                DeliveryError::Refused(e) => assert_eq!(
                    e.reason,
                    WebhookUrlUnsafeReason::BlockedIpRange,
                    "{url} must stay range-blocked under allow_insecure_http"
                ),
                other => panic!("{url} must be range-refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn insecure_http_optin_permits_a_public_plain_http_target() {
        // Guard-level check (no socket): with only the scheme opt-in, plain
        // HTTP to a public address passes the same guard `deliver` runs first.
        let config = EgressConfig {
            allow_insecure_http: true,
            allow_loopback: false,
        };
        let ok = assert_webhook_url_safe("http://8.8.8.8/hook", &config.assert_options())
            .expect("a public plain-HTTP target passes the guard");
        assert_eq!(ok.resolved_ip.to_string(), "8.8.8.8");
    }

    #[test]
    fn loopback_seam_does_not_permit_plain_http() {
        // The test seam loosens only the range-block: an http:// target is
        // still scheme-refused, while https:// to the loopback passes the guard.
        let config = EgressConfig {
            allow_insecure_http: false,
            allow_loopback: true,
        };
        match deliver("http://127.0.0.1/hook", b"{}", &[], config).unwrap_err() {
            DeliveryError::Refused(e) => {
                assert_eq!(e.reason, WebhookUrlUnsafeReason::UnsupportedProtocol);
            }
            other => panic!("must be scheme-refused, got {other:?}"),
        }
        assert!(
            assert_webhook_url_safe("https://127.0.0.1/hook", &config.assert_options()).is_ok(),
            "the seam still opens HTTPS to the loopback"
        );
    }
}
