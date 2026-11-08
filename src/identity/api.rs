//! The identity surface: actor and credential management, the
//! whoami check, the mode truth, and the scope table (REARCH R4/R5).
//! The management operations are `identity:admin`; the bootstrap is
//! the store's own open-mode cliff: the first actor enrolls while
//! the deployment has enrolled nobody, and enrollment closes it.
//! A deployment that prefers an explicit lock sets the operator
//! token, which acts with every scope.

use std::path::PathBuf;
use std::sync::RwLock;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use utoipa::OpenApi;

use super::scope;
use super::{
    enroll_actor, issue_for_actor, rotate_credential, Actor, Credential, CredentialState,
    IdentityStore, Op, ResolvedCredential,
};

/// The identity state: the replayed store, its journal (when the
/// deployment persists identity at all), and the operator token.
pub struct IdentityState {
    store: RwLock<IdentityStore>,
    journal_path: Option<PathBuf>,
    operator_token: Option<String>,
    /// The tenant scope this state serves (REARCH R6): `None` for the
    /// reference deployment, the folder name for a tenant mount.
    tenant: Option<String>,
}

impl IdentityState {
    /// Build from the environment: `UNIDPP_IDENTITY_STATE_FILE`
    /// persists the journal (absent = in-memory identity, which a
    /// fresh install runs), `UNIDPP_SERVER_OPERATOR_TOKEN` is the
    /// operator's bypass credential.
    pub fn from_env() -> IdentityState {
        let journal_path = std::env::var("UNIDPP_IDENTITY_STATE_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let operator_token = std::env::var("UNIDPP_SERVER_OPERATOR_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let mut store = IdentityStore::empty();
        if let Some(path) = &journal_path {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(op) = serde_json::from_str::<Op>(line) {
                        store.replay([op]);
                    }
                }
            }
        }
        IdentityState {
            store: RwLock::new(store),
            journal_path,
            operator_token,
            tenant: std::env::var("UNIDPP_SERVER_TENANT")
                .ok()
                .filter(|v| !v.trim().is_empty()),
        }
    }

    /// Whether enforcement is live: an operator token is set, or the
    /// store has enrolled at least one actor. An unconfigured
    /// deployment serves open, exactly as its modules always have.
    pub fn enforcing(&self) -> bool {
        self.operator_token.is_some() || !self.store.read().expect("store").is_empty()
    }

    /// The operator token, compared with the presented bearer.
    pub fn operator_is(&self, token: &str) -> bool {
        self.operator_token
            .as_deref()
            .map(|t| constant_time_eq(t, token))
            .unwrap_or(false)
    }

    pub fn resolve(&self, token: &str) -> Option<ResolvedCredential> {
        self.store.read().expect("store").resolve(token)
    }

    pub fn store_empty(&self) -> bool {
        self.store.read().expect("store").is_empty()
    }

    /// Persist and apply the operations (append-first: a crash
    /// between journal and memory replays on restart).
    fn commit(&self, ops: &[Op]) {
        if let Some(path) = &self.journal_path {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("identity journal opens");
            for op in ops {
                let line = serde_json::to_string(op).expect("op serializes");
                writeln!(file, "{line}").expect("identity journal appends");
            }
        }
        self.store.write().expect("store").replay(ops.to_vec());
    }

    pub fn snapshot_actors(&self) -> Vec<Actor> {
        let store = self.store.read().expect("store");
        store.actors().cloned().collect()
    }

    pub fn snapshot_credentials(&self) -> Vec<Credential> {
        let store = self.store.read().expect("store");
        store.credentials().cloned().collect()
    }

    pub fn actor(&self, id: &str) -> Option<Actor> {
        self.store.read().expect("store").actor(id).cloned()
    }

    pub fn credential(&self, id: &str) -> Option<Credential> {
        self.store.read().expect("store").credential(id).cloned()
    }
}

/// Constant-time equality (tokens and secrets).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn as_of() -> String {
    unidpp_model::time::Timestamp::now().to_string()
}

fn json_response(body: serde_json::Value, status: StatusCode) -> Response {
    (status, [("x-as-of", as_of())], Json(body)).into_response()
}

/// The presented bearer credential, resolved; `None` renders a 401.
fn resolve_request(state: &IdentityState, headers: &HeaderMap) -> Option<ResolvedCredential> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;
    state.resolve(token)
}

fn unauthorized() -> Response {
    json_response(
        serde_json::json!({"error": "authentication required: present a scoped credential or the operator token"}),
        StatusCode::UNAUTHORIZED,
    )
}

fn forbidden(scope: &str) -> Response {
    json_response(
        serde_json::json!({"error": format!("this operation requires the scope `{scope}`"), "missing_scope": scope}),
        StatusCode::FORBIDDEN,
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Enroll an actor and issue its first credential. While the
/// deployment has enrolled nobody this is the bootstrap and needs no
/// credential; afterwards it is `identity:admin`.
#[utoipa::path(
    post,
    path = "/identity/actors",
    tag = "identity",
    request_body(content = EnrollRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The actor and its first credential; the bearer is stated once", body = Enrolled),
        (status = 403, description = "The deployment has actors, and the caller holds no `identity:admin` credential", body = ErrorBody),
    )
)]
async fn enroll(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Response {
    let bootstrap = state.store_empty();
    if !bootstrap {
        let Some(resolved) = resolve_request(&state, &headers) else {
            return unauthorized();
        };
        if !resolved.has_scope("identity:admin") {
            return forbidden("identity:admin");
        }
    }
    if req.org.trim().is_empty() || req.name.trim().is_empty() {
        return json_response(
            serde_json::json!({"error": "org and name are required"}),
            StatusCode::BAD_REQUEST,
        );
    }
    let issued = enroll_actor(&req.org, &req.name, &req.scopes, &as_of());
    state.commit(&issued.ops);
    json_response(
        serde_json::json!({
            "actor": issued.actor_id,
            "credential": issued.credential_id,
            "bearer": issued.bearer,
            "scopes": issued.scopes,
            "note": "the bearer is stated once; the store keeps only its digest",
        }),
        StatusCode::CREATED,
    )
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct EnrollRequest {
    pub org: String,
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Enrolled {
    pub actor: String,
    pub credential: String,
    pub bearer: String,
    pub scopes: Vec<String>,
    pub note: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// The actors of the deployment (`identity:admin`).
#[utoipa::path(
    get,
    path = "/identity/actors",
    tag = "identity",
    responses(
        (status = 200, description = "The actors", body = Actors),
        (status = 401, description = "No credential presented", body = ErrorBody),
        (status = 403, description = "The credential lacks `identity:admin`", body = ErrorBody),
    )
)]
async fn actors(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    if !resolved.has_scope("identity:admin") {
        return forbidden("identity:admin");
    }
    json_response(
        serde_json::json!({ "actors": state.snapshot_actors() }),
        StatusCode::OK,
    )
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Actors {
    pub actors: Vec<Actor>,
}

/// Issue an additional credential for an actor (`identity:admin`).
#[utoipa::path(
    post,
    path = "/identity/actors/{id}/credentials",
    tag = "identity",
    params(("id" = String, Path)),
    request_body(content = IssueRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The credential; the bearer is stated once", body = Enrolled),
        (status = 401, description = "No credential presented", body = ErrorBody),
        (status = 403, description = "The credential lacks `identity:admin`", body = ErrorBody),
        (status = 404, description = "No such actor", body = ErrorBody),
    )
)]
async fn issue(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<IssueRequest>,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    if !resolved.has_scope("identity:admin") {
        return forbidden("identity:admin");
    }
    let Some(actor) = state.actor(&id) else {
        return json_response(
            serde_json::json!({"error": format!("no actor {id}")}),
            StatusCode::NOT_FOUND,
        );
    };
    let issued = issue_for_actor(&actor, &req.scopes, &as_of());
    state.commit(&issued.ops);
    json_response(
        serde_json::json!({
            "actor": issued.actor_id,
            "credential": issued.credential_id,
            "bearer": issued.bearer,
            "scopes": issued.scopes,
            "note": "the bearer is stated once; the store keeps only its digest",
        }),
        StatusCode::CREATED,
    )
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct IssueRequest {
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Rotate a credential: a new link issues, the old revokes, the
/// chain states its predecessor. The presenting credential may
/// rotate itself; anything else is `identity:admin`.
#[utoipa::path(
    post,
    path = "/identity/credentials/{id}/rotate",
    tag = "identity",
    params(("id" = String, Path)),
    request_body(content = ReasonRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "The rotated credential; the new bearer is stated once", body = Enrolled),
        (status = 401, description = "No credential presented", body = ErrorBody),
        (status = 403, description = "Rotating a foreign credential without `identity:admin`", body = ErrorBody),
        (status = 404, description = "No such credential", body = ErrorBody),
    )
)]
async fn rotate(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ReasonRequest>,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    let self_rotation = resolved.credential.id == id;
    if !self_rotation && !resolved.has_scope("identity:admin") {
        return forbidden("identity:admin");
    }
    let Some(old) = state.credential(&id) else {
        return json_response(
            serde_json::json!({"error": format!("no credential {id}")}),
            StatusCode::NOT_FOUND,
        );
    };
    if old.state != CredentialState::Active {
        return json_response(
            serde_json::json!({"error": format!("credential {id} is not active")}),
            StatusCode::CONFLICT,
        );
    }
    let Some(actor) = state.actor(&old.actor_id) else {
        return json_response(
            serde_json::json!({"error": "the credential's actor is gone"}),
            StatusCode::CONFLICT,
        );
    };
    let rotated = rotate_credential(&actor, &old, req.reason.as_deref(), &as_of());
    state.commit(&rotated.ops);
    json_response(
        serde_json::json!({
            "actor": rotated.actor_id,
            "credential": rotated.credential_id,
            "bearer": rotated.bearer,
            "scopes": rotated.scopes,
            "rotated_from": old.id,
            "note": "the old link is revoked; the new bearer is stated once",
        }),
        StatusCode::CREATED,
    )
}

#[derive(serde::Deserialize, utoipa::ToSchema, Default)]
pub struct ReasonRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Revoke a credential. The presenting credential may revoke itself;
/// anything else is `identity:admin`.
#[utoipa::path(
    post,
    path = "/identity/credentials/{id}/revoke",
    tag = "identity",
    params(("id" = String, Path)),
    request_body(content = ReasonRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The credential is revoked", body = Credential),
        (status = 401, description = "No credential presented", body = ErrorBody),
        (status = 403, description = "Revoking a foreign credential without `identity:admin`", body = ErrorBody),
        (status = 404, description = "No such credential", body = ErrorBody),
    )
)]
async fn revoke(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ReasonRequest>,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    let self_revocation = resolved.credential.id == id;
    if !self_revocation && !resolved.has_scope("identity:admin") {
        return forbidden("identity:admin");
    }
    let Some(credential) = state.credential(&id) else {
        return json_response(
            serde_json::json!({"error": format!("no credential {id}")}),
            StatusCode::NOT_FOUND,
        );
    };
    let reason = req
        .reason
        .unwrap_or_else(|| format!("revoked by {}", resolved.credential.id));
    let op = Op::CredentialRevoked {
        id: credential.id.clone(),
        reason,
    };
    state.commit(std::slice::from_ref(&op));
    json_response(serde_json::json!({ "revoked": id }), StatusCode::OK)
}

/// The credentials of the deployment (`identity:admin`). Secrets are
/// never stated; the store does not have them.
#[utoipa::path(
    get,
    path = "/identity/credentials",
    tag = "identity",
    responses(
        (status = 200, description = "The credentials, without secrets", body = Credentials),
        (status = 401, description = "No credential presented", body = ErrorBody),
        (status = 403, description = "The credential lacks `identity:admin`", body = ErrorBody),
    )
)]
async fn credentials(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    if !resolved.has_scope("identity:admin") {
        return forbidden("identity:admin");
    }
    json_response(
        serde_json::json!({ "credentials": state.snapshot_credentials() }),
        StatusCode::OK,
    )
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Credentials {
    pub credentials: Vec<Credential>,
}

/// The presenting credential, its actor and its scopes.
#[utoipa::path(
    get,
    path = "/identity/whoami",
    tag = "identity",
    responses(
        (status = 200, description = "The resolved credential and actor", body = Whoami),
        (status = 401, description = "No credential presented", body = ErrorBody),
    )
)]
async fn whoami(
    State(state): State<std::sync::Arc<IdentityState>>,
    headers: HeaderMap,
) -> Response {
    let Some(resolved) = resolve_request(&state, &headers) else {
        return unauthorized();
    };
    let operator = state
        .operator_token
        .as_deref()
        .map(|t| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|presented| constant_time_eq(presented, t))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    json_response(
        serde_json::json!({
            "actor": resolved.actor.id,
            "org": resolved.actor.org,
            "credential": resolved.credential.id,
            "scopes": resolved.credential.scopes,
            "operator": operator,
            "tenant": state.tenant,
        }),
        StatusCode::OK,
    )
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Whoami {
    pub actor: String,
    pub org: String,
    pub credential: String,
    pub scopes: Vec<String>,
    pub operator: bool,
}

/// The identity mode: whether enforcement is live and why.
#[utoipa::path(
    get,
    path = "/identity/keyring",
    tag = "identity",
    responses(
        (status = 200, description = "The mode truth", body = Mode),
    )
)]
async fn keyring(State(state): State<std::sync::Arc<IdentityState>>) -> Response {
    json_response(
        serde_json::json!({
            "mode": if state.enforcing() { "enforcing" } else { "open" },
            "actors": state.snapshot_actors().len(),
            "credentials": state.snapshot_credentials().len(),
            "operator_token": state.operator_token.is_some(),
            "note": "open = an unconfigured deployment; enrollment or an operator token closes it",
        }),
        StatusCode::OK,
    )
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Mode {
    pub mode: String,
    pub actors: usize,
    pub credentials: usize,
    pub operator_token: bool,
    pub note: String,
}

/// The scope table: the documented and enforced truth.
#[utoipa::path(
    get,
    path = "/identity/scopes",
    tag = "identity",
    responses(
        (status = 200, description = "The scope table", body = ScopeTable),
    )
)]
async fn scopes() -> Response {
    json_response(scope::table(), StatusCode::OK)
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ScopeTable {
    pub format: String,
    pub rule: String,
    pub public: Vec<String>,
    pub modules: Vec<serde_json::Value>,
}

pub mod paths {
    pub const HEALTHZ: &str = "/healthz";
    pub const ACTORS: &str = "/actors";
    pub const ACTOR_CREDENTIALS: &str = "/actors/{id}/credentials";
    pub const CREDENTIALS: &str = "/credentials";
    pub const CREDENTIAL_ROTATE: &str = "/credentials/{id}/rotate";
    pub const CREDENTIAL_REVOKE: &str = "/credentials/{id}/revoke";
    pub const WHOAMI: &str = "/whoami";
    pub const KEYRING: &str = "/keyring";
    pub const SCOPES: &str = "/scopes";
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
    pub const CONTRACT_JSON: &str = "/openapi.json";
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP identity",
        version = env!("CARGO_PKG_VERSION"),
        description = "The identity surface of the one deployment: actors, scoped credentials (issue, rotate, revoke), the whoami check, the mode truth and the scope table. Enforcement is live once the deployment has an actor or an operator token; an unconfigured deployment serves open, exactly as its modules always have.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(enroll, actors, issue, rotate, revoke, credentials, whoami, keyring, scopes),
    tags(
        (name = "identity", description = "Actors, credentials and the scope table"),
    )
)]
struct ApiDoc;

/// The identity contract document, as the modules serve theirs (the
/// deployment keys stated; the union carries it beside theirs).
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] =
        serde_json::json!(["UNIDPP_IDENTITY_STATE_FILE", "UNIDPP_SERVER_OPERATOR_TOKEN"]);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

pub fn contract_json() -> String {
    let mut value = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    value["info"]["x-unidpp-env-keys"] =
        serde_json::json!(["UNIDPP_IDENTITY_STATE_FILE", "UNIDPP_SERVER_OPERATOR_TOKEN"]);
    serde_json::to_string(&value).expect("contract serializes")
}

async fn openapi_yaml() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/yaml")],
        contract_yaml(),
    )
        .into_response()
}

async fn openapi_json() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        contract_json(),
    )
        .into_response()
}

async fn healthz() -> Response {
    json_response(serde_json::json!({"status": "ok"}), StatusCode::OK)
}

/// The identity router, mounted at `/identity`.
pub fn router(state: std::sync::Arc<IdentityState>) -> Router {
    Router::new()
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::ACTORS, post(enroll).get(actors))
        .route(paths::ACTOR_CREDENTIALS, post(issue))
        .route(paths::CREDENTIALS, get(credentials))
        .route(paths::CREDENTIAL_ROTATE, post(rotate))
        .route(paths::CREDENTIAL_REVOKE, post(revoke))
        .route(paths::WHOAMI, get(whoami))
        .route(paths::KEYRING, get(keyring))
        .route(paths::SCOPES, get(scopes))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
        .route(paths::CONTRACT_JSON, get(openapi_json))
        .with_state(state)
}
