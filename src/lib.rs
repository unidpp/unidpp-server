//! The one deployment: every module of the estate in one process,
//! one port, one data root (REARCH R1). The modules are the existing
//! service crates, mounted unchanged behind their prefixes (D3);
//! this crate adds only the composition, the shared root surface and
//! the union contract.

pub mod contract;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

/// The deployment's bind address (`UNIDPP_SERVER_BIND`).
pub const BIND_KEY: &str = "UNIDPP_SERVER_BIND";
/// The optional federation-peer registry's journal
/// (`UNIDPP_SERVER_JP_STATE_FILE`): when set, a second registry
/// instance mounts at `/registry-jp`.
pub const JP_STATE_KEY: &str = "UNIDPP_SERVER_JP_STATE_FILE";
const DEFAULT_BIND: &str = "127.0.0.1:8090";

fn other<E: std::fmt::Display>(error: E) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn as_of() -> String {
    unidpp_model::time::Timestamp::now().to_string()
}

/// This deployment's own loopback origin (the bind it is about to
/// serve on): the embedded console routes its module calls here.
fn origin() -> String {
    let bind = std::env::var(BIND_KEY)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    format!("http://{}", bind)
}

fn json_response(body: serde_json::Value) -> Response {
    (StatusCode::OK, [("x-as-of", as_of())], Json(body)).into_response()
}

async fn healthz() -> Response {
    json_response(json!({"status": "ok"}))
}

async fn discovery() -> Response {
    let document = serde_json::to_value(contract::discovery_document())
        .expect("the discovery document serializes");
    json_response(document)
}

async fn openapi_yaml() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/yaml")],
        contract::contract_yaml(),
    )
        .into_response()
}

async fn openapi_json() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        contract::contract_json(),
    )
        .into_response()
}

async fn version() -> Response {
    json_response(json!({"service": "unidpp", "version": env!("CARGO_PKG_VERSION")}))
}

async fn fallback() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no such path"})),
    )
        .into_response()
}

/// The whole estate as one router. Each module keeps its own env
/// contract (`Config::from_env`); the runner sets the keys under one
/// data root and points every inter-module `*_URL` at its prefixed
/// base on this same origin (D4/D7).
pub fn build_router() -> std::io::Result<Router> {
    let registry = Arc::new(unidpp_registry::api::AppState::new(
        unidpp_registry::Config::from_env(),
    )?);

    let trust_config = unidpp_trust::Config::from_env();
    let (trust_keyring, warnings) =
        unidpp_trust::Keyring::from_env(trust_config.dev_seed.as_deref());
    for warning in &warnings {
        eprintln!("unidpp-trust: {warning}");
    }
    let trust = Arc::new(unidpp_trust::api::AppState::new(
        trust_config,
        trust_keyring,
    )?);

    let log_config = unidpp_log::Config::from_env().map_err(other)?;
    let log = Arc::new(unidpp_log::api::AppState::new(log_config).map_err(other)?);

    let (issuer_config, warnings) = unidpp_issuer::Config::from_env();
    if let Some(warning) = &warnings {
        eprintln!("unidpp-issuer: {warning}");
    }
    let issuer = Arc::new(unidpp_issuer::api::AppState::new(issuer_config)?);

    let views = Arc::new(unidpp_projector::api::AppState::new(
        unidpp_projector::Config::from_env(),
    ));

    let render = Arc::new(unidpp_gateway::AppState::new(
        unidpp_gateway::Config::from_env(),
    ));

    let archive_config = unidpp_archive::Config::from_env();
    let (archive_keyring, warnings) =
        unidpp_archive::Keyring::from_env(archive_config.dev_seed.as_deref());
    for warning in &warnings {
        eprintln!("unidpp-archive: {warning}");
    }
    let archive = Arc::new(
        unidpp_archive::api::AppState::new(archive_config, archive_keyring).map_err(other)?,
    );

    let relay = Arc::new(unidpp_hub::AppState::new(unidpp_hub::Config::from_env()).map_err(other)?);

    let mut router = Router::new()
        .nest("/registry", unidpp_registry::api::router(registry))
        .nest("/trust", unidpp_trust::api::router(trust))
        .nest("/log", unidpp_log::api::router(log))
        .nest("/issuer", unidpp_issuer::api::router(issuer))
        .nest("/views", unidpp_projector::api::router(views))
        .nest("/render", unidpp_gateway::router(render))
        .nest("/archive", unidpp_archive::api::router(archive))
        .nest("/relay", unidpp_hub::router(relay));

    // The operator console rides inside the process when the
    // deployment carries a manifest for it (REARCH R3): mounted at
    // /console, its links carry the prefix, and its module calls go
    // through this same origin. No manifest in the environment, no
    // console — the minimal install serves the modules alone.
    if std::env::var("UNIDPP_CONSOLE_MANIFEST")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        let mut console_config = unidpp_console::Config::from_env().map_err(other)?;
        console_config.base_path = "/console".to_string();
        console_config.self_origin = Some(origin());
        let console = Arc::new(unidpp_console::AppState::new(console_config).map_err(other)?);
        router = router.nest("/console", unidpp_console::router(console));
    }

    // The optional federation-peer mount: a second registry instance
    // with its own journal (the reference deployment's JP peer, one
    // process). Absent state file, absent mount.
    if let Some(jp_state_file) = std::env::var(JP_STATE_KEY)
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        let mut jp_config = unidpp_registry::Config::from_env();
        jp_config.state_file = Some(jp_state_file.into());
        let jp = Arc::new(unidpp_registry::api::AppState::new(jp_config)?);
        router = router.nest("/registry-jp", unidpp_registry::api::router(jp));
    }

    Ok(router
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/openapi.yaml", get(openapi_yaml))
        .route("/openapi.json", get(openapi_json))
        .route("/version", get(version))
        .fallback(fallback))
}

/// Bind and serve until stopped (used by `main`).
pub async fn run() -> std::io::Result<()> {
    let bind = std::env::var(BIND_KEY)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    let app = build_router()?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("unidpp-server listening on http://{}", bind);
    axum::serve(listener, app).await
}
