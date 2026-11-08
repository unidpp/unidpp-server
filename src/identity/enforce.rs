//! The enforcement layer: one middleware before everything the
//! deployment serves. It consults the scope table, resolves the
//! presented credential, and either passes the request through or
//! refuses it with the missing scope named. What it does NOT touch:
//! the deployment's own surface, the relay (authentication-free by
//! contract), the operator console (which gates its own sessions),
//! and the identity surface (whose handlers enforce themselves,
//! bootstrap included).

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::api::IdentityState;
use super::scope;

fn refusal(status: StatusCode, error: String, missing: Option<String>) -> Response {
    let mut body = serde_json::json!({ "error": error });
    if let Some(scope) = missing {
        body["missing_scope"] = serde_json::json!(scope);
    }
    (status, [("x-as-of", now())], Json(body)).into_response()
}

fn now() -> String {
    unidpp_model::time::Timestamp::now().to_string()
}

/// The module a path belongs to (its first segment); "" for the
/// deployment's own surface.
fn module_of(path: &str) -> &str {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((module, _)) => module,
        None => trimmed,
    }
}

/// The paths the middleware never gates.
fn is_public(module: &str) -> bool {
    matches!(module, "" | "relay" | "console" | "identity")
}

pub async fn enforce(
    State(identity): State<std::sync::Arc<IdentityState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let module = module_of(&path);
    if is_public(module) {
        return next.run(request).await;
    }
    // The open mode: an unconfigured deployment serves exactly as its
    // modules always have.
    if !identity.enforcing() {
        return next.run(request).await;
    }
    let presented = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(token) = presented else {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "authentication required: this deployment enforces identity; present a scoped credential or the operator token".to_string(),
            None,
        );
    };
    if identity.operator_is(token) {
        return next.run(request).await;
    }
    let Some(resolved) = identity.resolve(token) else {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "the presented credential does not resolve (unknown, revoked, or its actor is suspended)".to_string(),
            None,
        );
    };
    let method = request.method().as_str().to_string();
    match scope::required_scope(module, &method, &path) {
        Some(required) => {
            if resolved.has_scope(&required) {
                next.run(request).await
            } else {
                refusal(
                    StatusCode::FORBIDDEN,
                    format!(
                        "this operation requires the scope `{required}`; the credential carries {:?}",
                        resolved.credential.scopes
                    ),
                    Some(required),
                )
            }
        }
        None => next.run(request).await,
    }
}

use axum::http::StatusCode;
