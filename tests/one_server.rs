//! The one-server gates: every module answers behind its prefix, its
//! contract stays byte-identical with its repo golden, and the union
//! document is pinned.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;
use unidpp_server::contract::{self, MODULES};

const UNION_GOLDEN: &str = include_str!("union-golden.yaml");

async fn post_json(
    app: &axum::Router,
    path: &str,
    body: &str,
    bearer: Option<&str>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("probe request");
    app.clone().oneshot(request).await.expect("probe answered")
}

async fn get_with(
    app: &axum::Router,
    path: &str,
    bearer: Option<&str>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::empty()).expect("probe request");
    app.clone().oneshot(request).await.expect("probe answered")
}

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
    // The operator console rides when the manifest exists: the test
    // writes the minimal one and the mount appears.
    std::fs::write(
        root.path().join("unidpp-operator.yaml"),
        "api_version: unidpp.org/v1\ndeployment:\n  name: server-test\n  profile: whitelabel\n  base_url: https://dpp.example.org\nbranding:\n  organization: Test Operator\n  product_name: Test DPP\nservices:\n  registry:\n    bind: 127.0.0.1:1\n",
    )
    .expect("manifest written");
    std::env::set_var("UNIDPP_CONSOLE_MANIFEST", dir("unidpp-operator.yaml"));
    std::env::set_var("UNIDPP_IDENTITY_STATE_FILE", dir("identity-journal.jsonl"));

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

    // The console mount: the operator surface at /console, its
    // links carrying the prefix, its contract among the union.
    let response = get(&app, "/console/healthz").await;
    assert_eq!(response.status(), StatusCode::OK, "GET /console/healthz");
    let response = get(&app, "/console").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let console_html = String::from_utf8_lossy(&body_bytes).into_owned();
    assert!(
        console_html.contains(r#"href="/console/config""#),
        "the console's nav carries its mount prefix"
    );
    assert!(
        console_html.contains(r#"href="/console""#),
        "the dashboard item points at the mount root, without a trailing slash"
    );

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
    let response = app.clone().oneshot(request).await.expect("probe answered");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // -----------------------------------------------------------------
    // The identity flow (REARCH R4/R5), last because enrollment closes
    // the open mode this test started in.
    // -----------------------------------------------------------------
    let mode: serde_json::Value = {
        let response = get(&app, "/identity/keyring").await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        serde_json::from_slice(&bytes).expect("mode parses")
    };
    assert_eq!(mode["mode"], "open", "an unenrolled deployment serves open");

    // The open-mode write: the deployment has no actors, so a module
    // admin operation answers as it always has.
    let response = post_json(&app, "/registry/admin/seed", "{}", None).await;
    assert!(
        response.status().as_u16() < 400,
        "the open mode lets a module admin through: {}",
        response.status()
    );

    // Bootstrap enrollment: the first actor needs no credential.
    let response = post_json(
        &app,
        "/identity/actors",
        r#"{"org":"border-agency","name":"Inspector J","scopes":["registry:admin","issuer:read"]}"#,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "bootstrap enrolls");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let enrolled: serde_json::Value = serde_json::from_slice(&bytes).expect("enrollment parses");
    let bearer = enrolled["bearer"]
        .as_str()
        .expect("the one-time bearer")
        .to_string();

    // Enrollment closed the deployment: the same write, unauthenticated,
    // now refuses with the missing scope named.
    let response = post_json(&app, "/registry/admin/seed", "{}", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // A reader credential doing an admin write: the scope is named.
    let reader = post_json(
        &app,
        "/identity/actors",
        r#"{"org":"bike-club","name":"Curious Reader","scopes":["views:read"]}"#,
        None,
    )
    .await;
    assert_eq!(
        reader.status(),
        StatusCode::UNAUTHORIZED,
        "a second bootstrap is refused: the deployment is closed"
    );
    let response = post_json(&app, "/registry/admin/seed", "{}", Some(&bearer)).await;
    assert!(
        response.status().as_u16() < 400,
        "the scoped credential acts: {}",
        response.status()
    );

    // The negative per-role probe: a registry credential is not a
    // views reader.
    let response = get_with(&app, "/views/openapi.yaml", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = get_with(&app, "/trust/keyring", Some(&bearer)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let refusal: serde_json::Value = serde_json::from_slice(&body).expect("refusal parses");
    assert_eq!(refusal["missing_scope"], "trust:read");

    // whoami states the actor and its scopes.
    let response = get_with(&app, "/identity/whoami", Some(&bearer)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let who: serde_json::Value = serde_json::from_slice(&body).expect("whoami parses");
    assert_eq!(who["org"], "border-agency");

    // Self-rotation: the new link works, the old is refused.
    let credential_id = enrolled["credential"]
        .as_str()
        .expect("credential id")
        .to_string();
    let response = post_json(
        &app,
        &format!("/identity/credentials/{credential_id}/rotate"),
        r#"{"reason":"scheduled"}"#,
        Some(&bearer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let rotated: serde_json::Value = serde_json::from_slice(&body).expect("rotation parses");
    let new_bearer = rotated["bearer"].as_str().expect("new bearer").to_string();
    let old_response = get_with(&app, "/identity/whoami", Some(&bearer)).await;
    assert_eq!(
        old_response.status(),
        StatusCode::UNAUTHORIZED,
        "the old link revokes"
    );
    let new_response = get_with(&app, "/identity/whoami", Some(&new_bearer)).await;
    assert_eq!(
        new_response.status(),
        StatusCode::OK,
        "the new link resolves"
    );

    // Self-revocation of the new link, stated with a reason.
    let new_id = rotated["credential"]
        .as_str()
        .expect("new credential id")
        .to_string();
    let response = post_json(
        &app,
        &format!("/identity/credentials/{new_id}/revoke"),
        r#"{"reason":"test over"}"#,
        Some(&new_bearer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let gone = get_with(&app, "/identity/whoami", Some(&new_bearer)).await;
    assert_eq!(
        gone.status(),
        StatusCode::UNAUTHORIZED,
        "the revoked link refuses"
    );

    // The scope table: every module carries its scopes.
    let response = get(&app, "/identity/scopes").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let table: serde_json::Value = serde_json::from_slice(&body).expect("table parses");
    let modules = table["modules"].as_array().expect("module rows");
    assert!(modules.len() >= 8, "the table covers the modules");
    let mode_response = get(&app, "/identity/keyring").await;
    let body = axum::body::to_bytes(mode_response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let mode_after: serde_json::Value = serde_json::from_slice(&body).expect("mode parses");
    assert_eq!(
        mode_after["mode"], "enforcing",
        "enrollment closed the mode"
    );
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
#[ignore = "regenerates tests/union-golden.yaml + openapi/identity.yaml: cargo test -- --ignored export_golden"]
fn export_golden() {
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/union-golden.yaml"),
        contract::contract_yaml(),
    )
    .expect("union golden written");
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/openapi/identity.yaml"),
        unidpp_server::identity::api::contract_yaml(),
    )
    .expect("identity golden written");
}
