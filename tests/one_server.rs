//! The one-server gates: every module answers behind its prefix, its
//! contract stays byte-identical with its repo golden, and the union
//! document is pinned.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;
use unidpp_server::contract::{self, MODULES};

const UNION_GOLDEN: &str = include_str!("union-golden.yaml");

async fn get(app: &axum::Router, path: &str) -> axum::http::Response<Body> {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("probe request");
    app.clone().oneshot(request).await.expect("probe answered")
}

#[tokio::test]
async fn the_one_server_serves_the_whole_estate() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = |name: &str| root.path().join(name).to_string_lossy().to_string();
    std::env::set_var("UNIDPP_REGISTRY_STATE_FILE", dir("registry-journal.jsonl"));
    std::env::set_var("UNIDPP_TRUST_STATE_FILE", dir("trust-state.jsonl"));
    std::env::set_var("UNIDPP_LOG_STATE_FILE", dir("log-state.jsonl"));
    std::env::set_var("UNIDPP_ISSUER_STATE_FILE", dir("issuer-state.jsonl"));
    std::env::set_var("UNIDPP_ARCHIVE_STATE_FILE", dir("archive-state.jsonl"));
    std::env::set_var("UNIDPP_ARCHIVE_SNAPSHOT_DIR", dir("archive-snapshots"));
    std::env::set_var("UNIDPP_PROJECTOR_PASSPORTS_DIR", dir("passports"));
    std::env::set_var("UNIDPP_PROJECTOR_PRIMMEL_DIR", dir("primmel"));
    std::env::set_var(
        "UNIDPP_GATEWAY_FEEDBACK_JOURNAL",
        dir("feedback-journal.jsonl"),
    );
    // The federation-peer mount rides the same test: one process,
    // two registries, distinct journals.
    std::env::set_var(
        "UNIDPP_SERVER_JP_STATE_FILE",
        dir("jp-registry-journal.jsonl"),
    );

    let app = unidpp_server::build_router().expect("router builds");

    // The shared root surface.
    let response = get(&app, "/healthz").await;
    assert_eq!(response.status(), StatusCode::OK, "GET /healthz");
    assert!(response.headers().contains_key("x-as-of"));
    let response = get(&app, "/").await;
    assert_eq!(response.status(), StatusCode::OK, "GET /");
    let discovery_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let discovery: serde_json::Value =
        serde_json::from_slice(&discovery_bytes).expect("discovery parses");
    assert_eq!(discovery["service"], "unidpp");
    let modules = discovery["modules"].as_array().expect("modules array");
    assert_eq!(modules.len(), MODULES.len());
    for (index, (name, source, _)) in MODULES.iter().enumerate() {
        assert_eq!(modules[index]["name"], *name);
        assert_eq!(modules[index]["service"], *source);
        assert_eq!(modules[index]["contract"], format!("/{name}/openapi.yaml"));
    }
    let response = get(&app, "/version").await;
    assert_eq!(response.status(), StatusCode::OK, "GET /version");

    // Every module answers behind its prefix, and its contract is
    // byte-identical with the repo golden (the drift gate, unchanged).
    for (name, _source, golden) in MODULES {
        let response = get(&app, &format!("/{name}/healthz")).await;
        assert_eq!(response.status(), StatusCode::OK, "GET /{name}/healthz");
        let response = get(&app, &format!("/{name}/openapi.yaml")).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "GET /{name}/openapi.yaml"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        assert_eq!(
            bytes.as_ref(),
            golden.as_bytes(),
            "{name}: the served contract differs from the repo golden"
        );
    }

    // The peer mount: a second registry, its own journal, the same
    // golden contract behind its prefix.
    let registry_golden = MODULES
        .iter()
        .find(|(name, _, _)| *name == "registry")
        .map(|(_, _, yaml)| *yaml)
        .expect("registry in MODULES");
    let response = get(&app, "/registry-jp/healthz").await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /registry-jp/healthz"
    );
    let response = get(&app, "/registry-jp/openapi.yaml").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    assert_eq!(bytes.as_ref(), registry_golden.as_bytes());

    // The union document equals its committed golden.
    let response = get(&app, "/openapi.yaml").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    assert_eq!(bytes.as_ref(), UNION_GOLDEN.as_bytes());

    // Off the surface: 404; wrong method: 405.
    let response = get(&app, "/nope").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let request = Request::builder()
        .method("DELETE")
        .uri("/healthz")
        .body(Body::empty())
        .expect("probe request");
    let response = app.oneshot(request).await.expect("probe answered");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn the_discovery_document_names_the_modules() {
    let doc = contract::discovery_document();
    let modules = doc
        .get("modules")
        .and_then(|m| m.as_sequence().cloned())
        .unwrap_or_default();
    assert_eq!(modules.len(), MODULES.len());
    for (index, (name, source, _)) in MODULES.iter().enumerate() {
        let entry = &modules[index];
        assert_eq!(entry.get("name").and_then(|v| v.as_str()), Some(*name));
        assert_eq!(entry.get("service").and_then(|v| v.as_str()), Some(*source));
        assert_eq!(
            entry.get("contract").and_then(|v| v.as_str()),
            Some(format!("/{name}/openapi.yaml").as_str())
        );
    }
}

#[test]
fn the_union_contract_is_well_formed() {
    let doc = contract::union_contract();
    let paths = doc
        .get("paths")
        .and_then(|p| p.as_mapping())
        .expect("paths mapping");
    // Every module's paths appear exactly once, under the prefix.
    for (name, _, golden) in MODULES {
        let module_doc: serde_yaml::Value = serde_yaml::from_str(golden).expect("golden parses");
        let module_paths = module_doc
            .get("paths")
            .and_then(|p| p.as_mapping())
            .expect("paths");
        for (key, value) in module_paths {
            let path = key.as_str().expect("path key");
            let prefixed = format!("/{name}{path}");
            let union_entry = paths
                .get(serde_yaml::Value::from(prefixed.as_str()))
                .unwrap_or_else(|| panic!("{prefixed}: missing from the union"));
            assert_eq!(union_entry, value, "{prefixed}: altered by the union");
        }
    }
    // The env contract is the union of the modules' keys.
    let keys = doc
        .get("info")
        .and_then(|i| i.get("x-unidpp-env-keys"))
        .and_then(|k| k.as_sequence())
        .expect("env keys");
    assert!(keys.len() >= 30, "the union env contract is substantial");
}

#[test]
#[ignore = "regenerates tests/union-golden.yaml: cargo test -- --ignored export_golden"]
fn export_golden() {
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/union-golden.yaml"),
        contract::contract_yaml(),
    )
    .expect("golden written");
}
