//! The wire projection layer.
//!
//! The engine's internal state names are NOT the wire names the published SDKs
//! deserialize. This module is the single explicit place that maps between them,
//! so a route never invents a wire string inline and the projection is
//! verifiable in one spot.
//!
//! The **record status** projection lives here: the engine's
//! `cw_core.poe_record.status` lifecycle is
//! `draft -> submitting -> submitted -> confirmed -> permanent_failure`, and the
//! wire status the SDK reads is `submitting | confirming | confirmed | failed`.
//! `draft` is never exposed (a draft is not yet a published record).
//!
//! The **event-name** projection (a `subject_event.event_type` to its public SSE /
//! webhook event name and visibility) lives in `webhook::projection`, where one
//! closed mapping serves both transports; the published event-name vocabulary a
//! subscription may filter on is [`WIRE_EVENT_NAMES`].

/// The wire status of a published record, as the SDK deserializes it.
///
/// Carried as the JSON strings `submitting`, `confirming`, `confirmed`,
/// `failed`. `draft` has no wire form: a draft record is not a published one and
/// is filtered out before projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireStatus {
    /// The transaction is being built/submitted (engine `submitting`).
    Submitting,
    /// The transaction is on chain but below the confirmation threshold (engine
    /// `submitted`).
    Confirming,
    /// The transaction crossed the confirmation threshold (engine `confirmed`).
    Confirmed,
    /// The publish failed terminally (engine `permanent_failure`).
    Failed,
}

impl WireStatus {
    /// The wire string the SDK deserializes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WireStatus::Submitting => "submitting",
            WireStatus::Confirming => "confirming",
            WireStatus::Confirmed => "confirmed",
            WireStatus::Failed => "failed",
        }
    }

    /// Project an engine `poe_record.status` to its wire status.
    ///
    /// Returns `None` for `draft`, which has no wire form: a draft is not a
    /// published record and is never projected onto the wire.
    #[must_use]
    pub fn from_core(core_status: &str) -> Option<WireStatus> {
        match core_status {
            "submitting" => Some(WireStatus::Submitting),
            "submitted" => Some(WireStatus::Confirming),
            "confirmed" => Some(WireStatus::Confirmed),
            "permanent_failure" => Some(WireStatus::Failed),
            // `draft` is deliberately not projected.
            _ => None,
        }
    }
}

/// The public wire event names a subscriber may filter a webhook subscription on.
///
/// These are the projected SSE/webhook event names the published SDKs already
/// listen for, NOT the internal `subject_event.event_type` literals. The webhook
/// `enabled_events` filter is validated against this set so a subscription can
/// never carry an internal name (`submitted`, `balance.changed`) the wire never
/// exposes, and so the filter vocabulary has one source rather than being spelled
/// inline at each route.
///
/// The set spans both planes: an account-scoped subscription will only ever
/// *match* the account-visible subset (the operator-only refund names never reach
/// an account), but the filter validation accepts any published name so a
/// subscriber gets a clear "unknown event" rejection rather than a silent
/// never-matches filter.
pub const WIRE_EVENT_NAMES: &[&str] = &[
    "poe_status_changed",
    "cardano_submission_failed",
    "balance_changed",
    "storage_upload_failed",
    "poe_refund_intent",
    "storage_refund_intent",
    // Emitted when the delivery worker auto-disables a flapping endpoint, so an
    // owner that subscribes to its own administrative events is told the moment a
    // sibling endpoint goes dark.
    "webhook_endpoint_disabled",
];

/// Whether `name` is a published wire event name a subscription may filter on.
#[must_use]
pub fn is_wire_event_name(name: &str) -> bool {
    WIRE_EVENT_NAMES.contains(&name)
}

/// The conformance profile a record satisfies, projected from its scheme and
/// signature presence.
///
/// `core` (open, unsigned), `signed` (open, record-signed), `sealed` (an
/// encryption scheme present, unsigned), `recipient-sealed` (encryption present
/// and record-signed). Mirrors the SDK's `ConformanceProfile`.
#[must_use]
pub fn conformance_profile(scheme: u8, signed: bool) -> &'static str {
    match (scheme, signed) {
        (0, false) => "core",
        (0, true) => "signed",
        (_, false) => "sealed",
        (_, true) => "recipient-sealed",
    }
}

/// The full publish-response projection of a record, decoded from its canonical
/// CBOR bytes.
///
/// The publish and publish-batch handlers both return the SDK's `PublishResponse`
/// shape, whose `items`, `signed`, `sealed`, `items_count`, and
/// `conformance_profile` fields are all derived from the record bytes alone. This
/// is the single place that derivation lives so the two handlers project a record
/// identically and a verifier indexing the same bytes agrees on every column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordProjection {
    /// The number of content items.
    pub items_count: u32,
    /// Whether the record carries any record-level signature.
    pub signed: bool,
    /// Whether the first item carries an encryption envelope (a sealed PoE).
    pub sealed: bool,
    /// The encryption-scheme projection of the first item (0 open, 1
    /// recipient-sealed, 2 passphrase-sealed), derived from the envelope's
    /// shape by the indexer's single scheme derivation.
    pub scheme: u8,
    /// The per-item projections, each the SDK `PoeItemResponse` JSON shape.
    pub items: Vec<serde_json::Value>,
}

impl RecordProjection {
    /// The conformance profile this record satisfies.
    #[must_use]
    pub fn conformance_profile(&self) -> &'static str {
        conformance_profile(self.scheme, self.signed)
    }
}

/// Decode a canonical Label 309 record's CBOR and project it to the
/// publish-response shape.
///
/// Validates under the public reading — an envelope under unsupported
/// identifiers degrades to opaque rather than failing the record, so the
/// publish surface accepts everything a public verifier accepts. Returns
/// `None` when the bytes are not a structurally valid record, so the publish
/// path rejects a malformed record before it inserts a row, rather than
/// projecting fabricated items. The per-item `enc` projection mirrors the host
/// indexer's wire shape: only the fields the envelope actually carries appear.
#[must_use]
pub fn project_record(record_bytes: &[u8]) -> Option<RecordProjection> {
    use cardanowall::poe_standard::{validate_poe_record, ValidateResult, ValidatorOptions};

    let record = match validate_poe_record(record_bytes, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => record,
        ValidateResult::Fail { .. } => return None,
    };

    let items = record.items.as_deref().unwrap_or(&[]);
    let items_count = u32::try_from(items.len()).ok()?;
    let signed = record.sigs.as_deref().is_some_and(|s| !s.is_empty());
    // The indexer's single scheme derivation, so the publish response and the
    // indexed column always agree on the same bytes.
    let scheme = crate::chain::records::scheme_of_first_item(items);
    let sealed = items.first().and_then(|i| i.enc.as_ref()).is_some();

    let item_values: Vec<serde_json::Value> = items
        .iter()
        .enumerate()
        .map(|(idx, item)| project_item(idx, item))
        .collect();

    Some(RecordProjection {
        items_count,
        signed,
        sealed,
        scheme,
        items: item_values,
    })
}

/// Project one content item to the SDK `PoeItemResponse` JSON shape:
/// `{ item_idx, hashes: { alg: hex }, uris?: [...], enc?: {...} }`.
fn project_item(idx: usize, item: &cardanowall::poe_standard::ItemEntry) -> serde_json::Value {
    use serde_json::{json, Map, Value};

    let mut hashes = Map::new();
    for (alg, digest) in &item.hashes {
        hashes.insert(alg.clone(), Value::String(hex::encode(digest)));
    }

    let uris: Option<Vec<String>> = item.uris.clone();

    let enc = item.enc.as_ref().map(project_enc);

    let mut obj = Map::new();
    obj.insert("item_idx".into(), json!(idx));
    obj.insert("hashes".into(), Value::Object(hashes));
    if let Some(uris) = uris {
        obj.insert("uris".into(), json!(uris));
    }
    if let Some(enc) = enc {
        obj.insert("enc".into(), enc);
    }
    Value::Object(obj)
}

/// Project an encryption envelope to the SDK `enc` JSON shape, emitting only the
/// fields the envelope carries (the KEM-foreign and absent fields are omitted).
///
/// An opaque envelope — one under identifiers this build cannot read — projects
/// only its wire `scheme` value when that value is readable: the response
/// acknowledges the sealed envelope without fabricating fields it cannot
/// validate.
fn project_enc(env: &cardanowall::poe_standard::EncryptionEnvelope) -> serde_json::Value {
    use cardanowall::cbor::CborValue;
    use cardanowall::poe_standard::EncryptionEnvelope;
    use serde_json::{json, Map, Value};

    let mut obj = Map::new();
    match env {
        EncryptionEnvelope::Scheme1(env) => {
            obj.insert("scheme".into(), json!(env.scheme));
            obj.insert("aead".into(), json!(env.aead));
            obj.insert("nonce".into(), json!(hex::encode(&env.nonce)));
            if let Some(kem) = &env.kem {
                obj.insert("kem".into(), json!(kem));
            }
            if let Some(slots) = &env.slots {
                obj.insert("slots_count".into(), json!(slots.len()));
            }
            if let Some(mac) = &env.slots_mac {
                obj.insert("slots_mac".into(), json!(hex::encode(mac)));
            }
            if let Some(p) = &env.passphrase {
                let params: Map<String, Value> = p
                    .params
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v)))
                    .collect();
                obj.insert(
                    "passphrase".into(),
                    json!({
                        "alg": p.alg,
                        "salt": hex::encode(&p.salt),
                        "params": Value::Object(params),
                    }),
                );
            }
        }
        EncryptionEnvelope::Opaque(value) => {
            if let CborValue::Map(pairs) = value {
                for (key, val) in pairs {
                    if let (CborValue::Text(name), CborValue::Unsigned(n)) = (key, val) {
                        if name == "scheme" {
                            obj.insert("scheme".into(), json!(n));
                        }
                    }
                }
            }
        }
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_status_projects_submitted_to_confirming() {
        assert_eq!(
            WireStatus::from_core("submitted"),
            Some(WireStatus::Confirming)
        );
        assert_eq!(
            WireStatus::from_core("submitted").unwrap().as_str(),
            "confirming"
        );
    }

    #[test]
    fn record_status_projects_permanent_failure_to_failed() {
        assert_eq!(
            WireStatus::from_core("permanent_failure"),
            Some(WireStatus::Failed)
        );
    }

    #[test]
    fn record_status_hides_draft() {
        assert_eq!(WireStatus::from_core("draft"), None);
    }

    #[test]
    fn record_status_round_trips_the_identity_mappings() {
        assert_eq!(
            WireStatus::from_core("submitting").unwrap().as_str(),
            "submitting"
        );
        assert_eq!(
            WireStatus::from_core("confirmed").unwrap().as_str(),
            "confirmed"
        );
    }

    #[test]
    fn profile_projects_from_scheme_and_signature() {
        assert_eq!(conformance_profile(0, false), "core");
        assert_eq!(conformance_profile(0, true), "signed");
        assert_eq!(conformance_profile(1, false), "sealed");
        assert_eq!(conformance_profile(1, true), "recipient-sealed");
        assert_eq!(conformance_profile(2, false), "sealed");
    }

    #[test]
    fn projects_an_open_record_to_core() {
        use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
        let record = PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0xab; 32])],
                uris: None,
                enc: None,
            }]),
            ..PoeRecord::default()
        };
        let bytes = encode_poe_record(&record).expect("encode");
        let proj = project_record(&bytes).expect("project");
        assert_eq!(proj.items_count, 1);
        assert!(!proj.signed);
        assert!(!proj.sealed);
        assert_eq!(proj.scheme, 0);
        assert_eq!(proj.conformance_profile(), "core");
        // The single item projects its hash map as alg -> lowercase hex.
        assert_eq!(proj.items[0]["item_idx"], serde_json::json!(0));
        assert_eq!(
            proj.items[0]["hashes"]["sha2-256"],
            serde_json::json!(hex::encode([0xab; 32]))
        );
        // An open item carries no enc projection.
        assert!(proj.items[0].get("enc").is_none());
    }

    #[test]
    fn projects_uris_as_plain_strings() {
        use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
        // A valid ar:// URI is `ar://` + a 43-char base64url id; each record URI
        // is a single text string on the wire and projects verbatim.
        let full = "ar://abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_string();
        let record = PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0x01; 32])],
                uris: Some(vec![full.clone()]),
                enc: None,
            }]),
            ..PoeRecord::default()
        };
        let bytes = encode_poe_record(&record).expect("encode");
        let proj = project_record(&bytes).expect("project");
        assert_eq!(proj.items[0]["uris"], serde_json::json!([full]));
    }

    #[test]
    fn projects_a_passphrase_envelope_as_scheme_2_with_its_kdf_block() {
        use cardanowall::poe_standard::{
            encode_poe_record, EncScheme1, EncryptionEnvelope, ItemEntry, PassphraseBlock,
            PoeRecord,
        };
        // Both sealed paths are `scheme: 1` on the wire; the projection reads
        // the envelope's shape, so a passphrase envelope is the gateway's
        // scheme 2 while its `enc` JSON carries the wire fields verbatim.
        let record = PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0x02; 32])],
                uris: None,
                enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                    scheme: 1,
                    aead: "chacha20-poly1305-stream64k".to_string(),
                    nonce: vec![0x06; 24],
                    kem: None,
                    slots: None,
                    slots_mac: None,
                    passphrase: Some(PassphraseBlock {
                        alg: "argon2id".to_string(),
                        salt: vec![0x0a; 16],
                        params: vec![
                            ("m".to_string(), 65_536),
                            ("t".to_string(), 3),
                            ("p".to_string(), 4),
                        ],
                    }),
                })),
            }]),
            ..PoeRecord::default()
        };
        let bytes = encode_poe_record(&record).expect("encode");
        let proj = project_record(&bytes).expect("project");
        assert!(proj.sealed);
        assert_eq!(proj.scheme, 2);
        assert_eq!(proj.conformance_profile(), "sealed");
        assert_eq!(proj.items[0]["enc"]["scheme"], serde_json::json!(1));
        assert_eq!(
            proj.items[0]["enc"]["passphrase"]["alg"],
            serde_json::json!("argon2id")
        );
        assert_eq!(
            proj.items[0]["enc"]["passphrase"]["params"]["m"],
            serde_json::json!(65_536)
        );
    }

    #[test]
    fn projects_an_unsupported_suite_envelope_as_sealed_with_opaque_enc() {
        use cardanowall::cbor::CborValue;
        use cardanowall::poe_standard::{
            encode_poe_record, EncryptionEnvelope, ItemEntry, PoeRecord,
        };
        // An envelope under an unsupported scheme passes the public validator as
        // opaque. The record is sealed (never `core`), and the `enc` projection
        // carries only the readable wire scheme value.
        let record = PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0x03; 32])],
                uris: None,
                enc: Some(EncryptionEnvelope::Opaque(CborValue::Map(vec![
                    (
                        CborValue::Text("scheme".to_string()),
                        CborValue::Unsigned(7),
                    ),
                    (
                        CborValue::Text("aead".to_string()),
                        CborValue::Text("future-aead".to_string()),
                    ),
                    (
                        CborValue::Text("nonce".to_string()),
                        CborValue::bytes(vec![0x01; 24]),
                    ),
                ]))),
            }]),
            ..PoeRecord::default()
        };
        let bytes = encode_poe_record(&record).expect("encode");
        let proj = project_record(&bytes).expect("project");
        assert!(proj.sealed);
        assert_eq!(proj.scheme, 1, "opaque sealed indexes as the sealed value");
        assert_eq!(proj.conformance_profile(), "sealed");
        assert_eq!(proj.items[0]["enc"]["scheme"], serde_json::json!(7));
        assert!(
            proj.items[0]["enc"].get("aead").is_none(),
            "no fabricated typed fields on an opaque envelope"
        );
    }

    #[test]
    fn rejects_malformed_record_bytes() {
        assert!(project_record(b"not a record").is_none());
        assert!(project_record(&[0xff, 0x00, 0x12]).is_none());
    }
}
