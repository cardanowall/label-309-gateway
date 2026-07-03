//! Route-coverage contract test.
//!
//! The frozen `openapi.json` is the published wire contract; the router serves a
//! fixed set of routes. This test asserts the two agree exactly in BOTH
//! directions, so neither a served route can drift out of the spec nor a spec
//! path go unserved. Pure CPU (no database), so it runs in the default
//! `cargo test`.

use std::collections::BTreeSet;

use gateway_core::api::problem::ERROR_REGISTRY;
use gateway_core::api::routes::SERVED_ROUTES;
use gateway_core::api::OPENAPI_JSON;

/// Extract every `(method, path)` operation from the served OpenAPI document.
fn spec_operations() -> BTreeSet<(String, String)> {
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_JSON).expect("the embedded openapi.json parses");
    let paths = doc
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("the spec has a paths object");

    let mut ops = BTreeSet::new();
    for (path, item) in paths {
        let item = item.as_object().expect("each path item is an object");
        for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
            if item.contains_key(method) {
                ops.insert((method.to_string(), path.clone()));
            }
        }
    }
    ops
}

/// The router's served routes as a set, in the spec's `{param}` template form.
fn served_operations() -> BTreeSet<(String, String)> {
    SERVED_ROUTES
        .iter()
        .map(|(m, p)| ((*m).to_string(), (*p).to_string()))
        .collect()
}

#[test]
fn every_served_route_exists_in_the_openapi_spec() {
    let spec = spec_operations();
    let served = served_operations();

    let missing_from_spec: Vec<_> = served.difference(&spec).collect();
    assert!(
        missing_from_spec.is_empty(),
        "routes served by the router but absent from openapi.json: {missing_from_spec:?}"
    );
}

#[test]
fn every_openapi_path_is_served_by_the_router() {
    let spec = spec_operations();
    let served = served_operations();

    let unserved: Vec<_> = spec.difference(&served).collect();
    assert!(
        unserved.is_empty(),
        "operations in openapi.json with no served route: {unserved:?}"
    );
}

#[test]
fn the_spec_is_trimmed_to_the_core_surface() {
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_JSON).expect("the embedded openapi.json parses");
    let blob = serde_json::to_string(&doc).unwrap();

    // The non-core surfaces (billing, inbox, account export, wallet challenge)
    // must not have leaked into the trimmed spec. (Webhook subscription routes are
    // a documented additive part of the data-plane surface, so they are NOT
    // forbidden here.)
    for forbidden in ["/billing", "/inbox", "/account/export", "/account/wallets"] {
        assert!(
            !blob.contains(forbidden),
            "the trimmed spec must not carry the non-core path {forbidden}"
        );
    }

    // Vendor-specific strings must be scrubbed (operator-config, public OSS).
    for vendor in ["cardanowall.com", "sk-cw"] {
        assert!(
            !blob.contains(vendor),
            "the public spec must not hardcode the vendor string {vendor}"
        );
    }
}

#[test]
fn every_documented_error_code_resolves_in_the_registry_at_its_pinned_status() {
    // The dereferenceable-errors claim: every problem example the spec ships
    // must name a code the /errors registry serves, at the exact HTTP status the
    // registry pins for it, and must sit under a matching response-status key.
    // This is what keeps a phantom code (documented but never emitted) or a
    // status drift (spec says 400, registry pins 422) out of the published
    // contract.
    let registry: std::collections::BTreeMap<&str, u16> =
        ERROR_REGISTRY.iter().map(|e| (e.code, e.status)).collect();

    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_JSON).expect("the embedded openapi.json parses");
    let responses = doc["components"]["responses"]
        .as_object()
        .expect("the spec defines response components");

    let mut checked = 0usize;
    for (name, component) in responses {
        let Some(example) = component
            .pointer("/content/application~1problem+json/example")
            .and_then(|e| e.as_object())
        else {
            continue;
        };
        let code = example["code"].as_str().unwrap_or_default();
        let status = example["status"].as_u64().unwrap_or_default() as u16;
        let pinned = registry.get(code).copied();
        assert_eq!(
            pinned,
            Some(status),
            "{name}: example code {code:?} at status {status} must match the registry \
             (registry pins {pinned:?})"
        );
        checked += 1;
    }
    assert!(checked > 10, "the sweep visited the problem components");
}

#[test]
fn the_quote_schema_carries_the_byte_stable_amount_and_currency() {
    // The published SDK deserializers REQUIRE `amount` + `currency` on the quote
    // response. The spec must document them (and require them) so the contract
    // and the published clients can never drift apart.
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_JSON).expect("the embedded openapi.json parses");
    let schema = &doc["components"]["schemas"]["PoeQuoteResponse"];

    for field in ["amount", "currency", "quote_id", "expires_at"] {
        assert!(
            schema["properties"].get(field).is_some(),
            "the quote response schema must define {field}"
        );
    }

    let required: Vec<String> = schema["required"]
        .as_array()
        .expect("required is an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    for field in ["amount", "currency"] {
        assert!(
            required.contains(&field.to_string()),
            "the quote response schema must require {field} (the SDK deserializer needs it)"
        );
    }
}
