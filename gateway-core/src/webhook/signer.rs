//! The webhook delivery signature: HMAC-SHA256 over `"{id}.{timestamp}.{body}"`.
//!
//! Every delivery POST carries a `Webhook-Signature: t=<unix>,v1=<hex>` header
//! plus `Webhook-Id` and `Webhook-Timestamp`. The signature MACs the per-delivery
//! id, the timestamp, and the exact body bytes joined by dots
//! (`"{id}.{timestamp}.{body}"`), so it is bound to both the delivery identity and
//! a time: the `Webhook-Id` header cannot be swapped onto a different payload, and
//! a receiver can reject a replayed body outside a tolerance window. This is the
//! signed content the Standard-Webhooks scheme prescribes. The `v1` value is the
//! lowercase hex of `HMAC_SHA256(secret, signed_payload)`.
//!
//! # Dual signing during a rotation window
//!
//! A subscription may hold two active secrets while it rotates (a primary and its
//! successor). During that window the gateway emits one `v1=` per active secret
//! over the identical signed payload, so a receiver that has deployed either
//! secret can validate the delivery: `t=<unix>,v1=<primary>,v1=<next>`. Outside a
//! window there is exactly one `v1`. Signing with both secrets (rather than
//! primary-only) is what makes "the receiver may validate with either" actually
//! hold — a receiver cannot validate the successor unless the gateway MACed the
//! body with it too.
//!
//! # Why this lives apart from the delivery transport
//!
//! The signer is a pure function over `(secrets, timestamp, id, body)`; it never
//! touches the keyring, the database, or the network. The delivery worker unwraps
//! the endpoint secret(s) from the wrap key, calls [`sign_delivery`], and hands
//! the resulting headers to the egress. Keeping the signer pure lets it be pinned
//! to a committed worked vector and reused identically by the conformance receiver.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The `User-Agent` every delivery POST carries. Vendor-neutral: the gateway
/// implements the Label 309 standard, so the agent names the standard, not a
/// brand.
pub const WEBHOOK_USER_AGENT: &str = "label-309-gateway-webhooks/1";

/// The signed header set for one delivery.
///
/// `id` is the per-delivery `Webhook-Id` (`kind:id:seq:endpoint_id`), reused
/// verbatim across a redelivery so a receiver dedupes a retry; `timestamp` is the
/// `Webhook-Timestamp` (re-stamped fresh on each send so the receiver's tolerance
/// window passes); `signature` is the `Webhook-Signature` value carrying one `v1`
/// per active secret over `"{id}.{timestamp}.{body}"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// The `Webhook-Id` header value (the per-delivery dedupe key).
    pub id: String,
    /// The `Webhook-Timestamp` header value (the Unix seconds used in the MAC).
    pub timestamp: i64,
    /// The `Webhook-Signature` header value: `t=<unix>,v1=<hex>[,v1=<hex>]`.
    pub signature: String,
}

impl SignedHeaders {
    /// The header name/value pairs to set on the delivery request, in a stable
    /// order. Includes the fixed `Content-Type` and `User-Agent` so the call site
    /// sets the full delivery header set from one place.
    #[must_use]
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), WEBHOOK_USER_AGENT.to_string()),
            ("Webhook-Id".to_string(), self.id.clone()),
            ("Webhook-Timestamp".to_string(), self.timestamp.to_string()),
            ("Webhook-Signature".to_string(), self.signature.clone()),
        ]
    }
}

/// Compute the lowercase-hex `v1` MAC of `"{id}.{timestamp}.{body}"` under one
/// secret.
///
/// `id` is the per-delivery `Webhook-Id`; binding it into the MAC means the id a
/// receiver dedupes on is authenticated, so the `Webhook-Id` header cannot be
/// moved onto a different payload. `body` is the exact serialized envelope bytes
/// that go on the wire, so the signature is over the literal payload a receiver
/// re-reads, with no re-serialization in between. This is the signed content the
/// Standard-Webhooks scheme prescribes.
#[must_use]
pub fn sign_v1(id: &str, secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    // HMAC accepts a key of any length, so a `new_from_slice` over the secret
    // bytes never fails; the explicit expect documents that invariant.
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Build the signed header set for a delivery, dual-signing when a second active
/// secret is present.
///
/// `secrets` is the ordered set of active secrets: the primary first, then the
/// rotation successor when a window is open. One `v1=` is emitted per secret over
/// the identical signed payload, and a receiver accepts a constant-time match on
/// any of them. `secrets` must be non-empty (an endpoint always has at least a
/// primary); an empty set is a programming error the caller prevents, and yields
/// a signature with no `v1` rather than panicking.
///
/// The secrets are only borrowed (any byte-slice-backed element works, e.g. a
/// `Zeroizing<Vec<u8>>`), so the caller can keep the plaintext in a wiped-on-drop
/// buffer for its whole lifetime; signing never takes an owned, non-zeroized copy.
#[must_use]
pub fn sign_delivery<S: AsRef<[u8]>>(
    webhook_id: &str,
    timestamp: i64,
    body: &[u8],
    secrets: &[S],
) -> SignedHeaders {
    let mut signature = format!("t={timestamp}");
    for secret in secrets {
        let v1 = sign_v1(webhook_id, secret.as_ref(), timestamp, body);
        signature.push_str(",v1=");
        signature.push_str(&v1);
    }
    SignedHeaders {
        id: webhook_id.to_string(),
        timestamp,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pinned worked vector. The `v1` hex values are computed independently
    // (Node's
    // `crypto.createHmac("sha256", secret).update("{id}.{t}.{body}").digest`)
    // from the exact id/timestamp/body below, then committed here, so a regression
    // in the signing input (the `{id}.` prefix, the `{t}.` prefix, the body bytes,
    // the lowercase hex) is caught against an external reference rather than
    // against our own code.
    const VECTOR_ID: &str =
        "poe_record:00000000-0000-7000-8000-000000000001:1:00000000-0000-7000-8000-0000000000ee";
    const VECTOR_SECRET: &[u8] = b"whsec_test_0123456789abcdef";
    const VECTOR_SECRET_NEXT: &[u8] = b"whsec_test_fedcba9876543210";
    const VECTOR_TIMESTAMP: i64 = 1_733_600_000;
    const VECTOR_BODY: &str = "{\"id\":\"poe_record:00000000-0000-7000-8000-000000000001:1:00000000-0000-7000-8000-0000000000ee\",\"type\":\"poe_status_changed\",\"created_at\":\"2026-06-07T00:00:00Z\",\"data\":{\"id\":\"poe_2zk...\",\"status\":\"confirming\",\"num_confirmations\":0}}";
    const VECTOR_V1: &str = "46e5e8daf613a602376eed18164324360f23374a6a36a686c23b49b7e7249535";
    const VECTOR_V1_NEXT: &str = "e441fd691e60c74ce8f4bd1ad01ceda44763a247e53e8c386ac8b942e7d3d330";

    /// The signed content `HMAC_SHA256(secret, "{id}.{timestamp}.{body}")` is taken
    /// over independently, so a receiver reconstructing the input the same way
    /// matches. Recomputing it inline here (rather than calling `sign_v1`) is what
    /// lets the test catch a change to the input ordering or the dot separators.
    fn independent_v1(id: &str, secret: &[u8], timestamp: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
        mac.update(id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn sign_v1_matches_the_committed_vector() {
        let v1 = sign_v1(
            VECTOR_ID,
            VECTOR_SECRET,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
        );
        assert_eq!(v1, VECTOR_V1);
    }

    #[test]
    fn sign_v1_signs_over_id_timestamp_body() {
        // The MAC input is exactly `"{id}.{timestamp}.{body}"`: an independent
        // reconstruction of that string matches, proving the id is in the signed
        // content. (This is the Standard-Webhooks signed-content shape.)
        let expected = independent_v1(
            VECTOR_ID,
            VECTOR_SECRET,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
        );
        assert_eq!(
            sign_v1(
                VECTOR_ID,
                VECTOR_SECRET,
                VECTOR_TIMESTAMP,
                VECTOR_BODY.as_bytes()
            ),
            expected
        );
    }

    #[test]
    fn signed_payload_binds_the_webhook_id() {
        // Changing only the id changes the MAC, so the `Webhook-Id` header is
        // cryptographically bound to the payload and cannot be swapped.
        let a = sign_v1(
            VECTOR_ID,
            VECTOR_SECRET,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
        );
        let b = sign_v1(
            "poe_record:00000000-0000-7000-8000-000000000001:2:00000000-0000-7000-8000-0000000000ee",
            VECTOR_SECRET,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
        );
        assert_ne!(a, b, "the id is part of the signed content");

        // A MAC computed the old, id-less way (`"{timestamp}.{body}"`) does NOT
        // match, so a regression that drops the id from the input is caught.
        let mut id_less = HmacSha256::new_from_slice(VECTOR_SECRET).expect("hmac key");
        id_less.update(VECTOR_TIMESTAMP.to_string().as_bytes());
        id_less.update(b".");
        id_less.update(VECTOR_BODY.as_bytes());
        let id_less = hex::encode(id_less.finalize().into_bytes());
        assert_ne!(a, id_less, "the signed content is not the id-less form");
    }

    #[test]
    fn single_secret_emits_one_v1() {
        let headers = sign_delivery(
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
            &[VECTOR_SECRET.to_vec()],
        );
        assert_eq!(headers.id, VECTOR_ID);
        assert_eq!(headers.timestamp, VECTOR_TIMESTAMP);
        assert_eq!(
            headers.signature,
            format!("t={VECTOR_TIMESTAMP},v1={VECTOR_V1}")
        );
        // Exactly one v1 outside a rotation window.
        assert_eq!(headers.signature.matches("v1=").count(), 1);
    }

    #[test]
    fn dual_sign_emits_one_v1_per_active_secret() {
        let headers = sign_delivery(
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
            &[VECTOR_SECRET.to_vec(), VECTOR_SECRET_NEXT.to_vec()],
        );
        // Two v1 values, primary then successor, over the identical payload.
        assert_eq!(
            headers.signature,
            format!("t={VECTOR_TIMESTAMP},v1={VECTOR_V1},v1={VECTOR_V1_NEXT}")
        );
        assert_eq!(headers.signature.matches("v1=").count(), 2);
        // The successor's v1 is exactly the single-secret MAC of the successor
        // secret over the SAME id+timestamp+body, proving each v1 is an independent
        // MAC over the same signed content.
        assert_eq!(
            sign_v1(
                VECTOR_ID,
                VECTOR_SECRET_NEXT,
                VECTOR_TIMESTAMP,
                VECTOR_BODY.as_bytes()
            ),
            VECTOR_V1_NEXT
        );
    }

    #[test]
    fn zeroizing_secrets_sign_byte_identically() {
        // The delivery worker keeps unwrapped secrets in `Zeroizing<Vec<u8>>`
        // for their whole lifetime and the signer only borrows the bytes. The
        // MAC over a zeroizing buffer must be byte-identical to the committed
        // vector, so the wipe-on-drop wrapper can never alter the signature.
        let secrets = vec![
            zeroize::Zeroizing::new(VECTOR_SECRET.to_vec()),
            zeroize::Zeroizing::new(VECTOR_SECRET_NEXT.to_vec()),
        ];
        let headers = sign_delivery(
            VECTOR_ID,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
            &secrets,
        );
        assert_eq!(
            headers.signature,
            format!("t={VECTOR_TIMESTAMP},v1={VECTOR_V1},v1={VECTOR_V1_NEXT}")
        );
    }

    #[test]
    fn signed_payload_binds_the_timestamp() {
        // The same id + secret + body under a different timestamp yields a
        // different MAC, which is what lets a receiver reject a replayed body by
        // its time.
        let a = sign_v1(
            VECTOR_ID,
            VECTOR_SECRET,
            VECTOR_TIMESTAMP,
            VECTOR_BODY.as_bytes(),
        );
        let b = sign_v1(
            VECTOR_ID,
            VECTOR_SECRET,
            VECTOR_TIMESTAMP + 1,
            VECTOR_BODY.as_bytes(),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn header_pairs_carry_the_full_delivery_set() {
        let headers = sign_delivery(
            "kind:id:7:endpoint",
            VECTOR_TIMESTAMP,
            b"{}",
            &[b"s".to_vec()],
        );
        let pairs = headers.to_pairs();
        let lookup = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(lookup("Content-Type"), Some("application/json"));
        assert_eq!(lookup("User-Agent"), Some(WEBHOOK_USER_AGENT));
        assert_eq!(lookup("Webhook-Id"), Some("kind:id:7:endpoint"));
        assert_eq!(
            lookup("Webhook-Timestamp"),
            Some(VECTOR_TIMESTAMP.to_string().as_str())
        );
        assert!(lookup("Webhook-Signature").unwrap().starts_with("t="));
    }
}
