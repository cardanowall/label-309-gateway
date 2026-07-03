//! Control-plane route-coverage contract test.
//!
//! The frozen `openapi-control.json` is the published control-plane wire contract;
//! the control router serves a fixed set of routes. This test asserts the two
//! agree exactly in BOTH directions, so neither a served control route can drift
//! out of the spec nor a spec path go unserved. It also asserts the control spec
//! is distinct from the data-plane spec (it must never share or extend it). Pure
//! CPU (no database), so it runs in the default `cargo test`.

use std::collections::BTreeSet;

use gateway_core::api::control::SERVED_CONTROL_ROUTES;
use gateway_core::api::{OPENAPI_CONTROL_JSON, OPENAPI_JSON};

/// Extract every `(method, path)` operation from a served OpenAPI document.
fn spec_operations(doc_json: &str) -> BTreeSet<(String, String)> {
    let doc: serde_json::Value =
        serde_json::from_str(doc_json).expect("the embedded openapi document parses");
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

/// The control router's served routes as a set, in the spec's `{param}` form.
fn served_operations() -> BTreeSet<(String, String)> {
    SERVED_CONTROL_ROUTES
        .iter()
        .map(|(m, p)| ((*m).to_string(), (*p).to_string()))
        .collect()
}

#[test]
fn every_served_control_route_exists_in_the_control_spec() {
    let spec = spec_operations(OPENAPI_CONTROL_JSON);
    let served = served_operations();

    let missing: Vec<_> = served.difference(&spec).collect();
    assert!(
        missing.is_empty(),
        "control routes served by the router but absent from openapi-control.json: {missing:?}"
    );
}

#[test]
fn every_control_spec_path_is_served_by_the_router() {
    let spec = spec_operations(OPENAPI_CONTROL_JSON);
    let served = served_operations();

    let unserved: Vec<_> = spec.difference(&served).collect();
    assert!(
        unserved.is_empty(),
        "operations in openapi-control.json with no served control route: {unserved:?}"
    );
}

#[test]
fn the_control_spec_is_disjoint_from_the_data_plane_spec() {
    // The two surfaces are independently versioned and must not share routes. Spec
    // `paths` are now BARE (the version segment lives in `servers`), so a bare
    // collection alone would overlap on shared suffixes like `/webhooks` and
    // `/openapi.json`. The real invariant is that the SERVED surfaces are disjoint,
    // so re-apply each plane's version prefix before comparing — exactly what the
    // router does when it nests each plane under its own prefix.
    let control: BTreeSet<(String, String)> = spec_operations(OPENAPI_CONTROL_JSON)
        .into_iter()
        .map(|(m, p)| (m, format!("/control/v1{p}")))
        .collect();
    let data: BTreeSet<(String, String)> = spec_operations(OPENAPI_JSON)
        .into_iter()
        .map(|(m, p)| (m, format!("/api/v1{p}")))
        .collect();

    assert!(
        control.is_disjoint(&data),
        "the control and data-plane served surfaces must not share any operation"
    );
    for (_, path) in &control {
        assert!(
            path.starts_with("/control/v1/"),
            "every served control path must be under /control/v1/, got {path}"
        );
    }
}

#[test]
fn the_clamp_debit_200_response_documents_its_body_schema() {
    // The clamp-debit result is money-bearing: its 200 body (account_id +
    // debited_usd_micros + applied) is the integration contract a caller derives
    // arrears from, so the spec must document the body, not just the path.
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_CONTROL_JSON).expect("control spec parses");

    // The 200 response resolves to the ClampedDebitResult component. The spec path
    // key is now bare (the version segment lives in `servers`).
    let ref_value = doc
        .pointer(
            "/paths/~1accounts~1{account_id}~1ledger-clamp-debit/post/responses/200/content/application~1json/schema/$ref",
        )
        .and_then(|v| v.as_str())
        .expect("the clamp-debit 200 response has a JSON body schema $ref");
    assert_eq!(ref_value, "#/components/schemas/ClampedDebitResult");

    // The component itself declares the money-bearing fields.
    let schema = doc
        .pointer("/components/schemas/ClampedDebitResult")
        .and_then(|v| v.as_object())
        .expect("the ClampedDebitResult component is defined");
    let required: BTreeSet<String> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .expect("ClampedDebitResult declares required fields")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert_eq!(
        required,
        BTreeSet::from([
            "account_id".to_string(),
            "debited_usd_micros".to_string(),
            "applied".to_string(),
        ]),
        "the documented clamp-debit body must carry exactly account_id, debited_usd_micros, applied"
    );
}

#[test]
fn every_control_operation_carries_a_unique_operation_id() {
    // operationId is the stable handle generated clients and integrator tooling
    // key on (the data plane defines one per operation); the control plane must
    // match, and no two operations may share one.
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_CONTROL_JSON).expect("control spec parses");
    let paths = doc["paths"].as_object().expect("paths object");

    let mut seen = std::collections::BTreeMap::<String, (String, String)>::new();
    for (path, item) in paths {
        for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let Some(op) = item.get(method) else { continue };
            let id = op["operationId"].as_str().unwrap_or_default().to_string();
            assert!(
                !id.is_empty(),
                "{method} {path} must define a non-empty operationId"
            );
            if let Some((m0, p0)) = seen.insert(id.clone(), (method.into(), path.clone())) {
                panic!("operationId {id} is shared by {m0} {p0} and {method} {path}");
            }
        }
    }
}

#[test]
fn the_fx_probe_documents_the_snapshot_body() {
    // GET /pricing/fx is the cold-start FX-health probe an operator console keys
    // on; its 200 body must resolve to the FxSnapshot component so the documented
    // contract carries the freshness verdict, not just the path.
    let doc: serde_json::Value =
        serde_json::from_str(OPENAPI_CONTROL_JSON).expect("control spec parses");
    let ref_value = doc
        .pointer("/paths/~1pricing~1fx/get/responses/200/content/application~1json/schema/$ref")
        .and_then(|v| v.as_str())
        .expect("the fx probe's 200 response has a JSON body schema $ref");
    assert_eq!(ref_value, "#/components/schemas/FxSnapshot");
    assert!(
        doc.pointer("/components/schemas/FxSnapshot").is_some(),
        "the FxSnapshot component is defined"
    );
}

#[test]
fn the_control_spec_is_vendor_neutral() {
    // The control spec ships as public OSS: no hardcoded vendor host or brand
    // prefix may leak into it (those are operator config).
    for vendor in ["cardanowall.com", "sk-cw", "CIP-309", "cip-309"] {
        assert!(
            !OPENAPI_CONTROL_JSON.contains(vendor),
            "the public control spec must not hardcode the vendor string {vendor}"
        );
    }
}
