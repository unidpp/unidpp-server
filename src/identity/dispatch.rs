//! The tenant dispatch: one middleware at the outermost layer that
//! reads the request's Host and, when it names a tenant folder's
//! hostname, serves the request from that tenant's own router — its
//! own module states, its own identity, its own branding (REARCH
//! R6). A tenant is a folder and a manifest; the reference
//! deployment answers every other Host, including loopback.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

/// The served tenants, in folder order.
#[derive(Clone)]
pub struct TenantTable {
    pub entries: std::sync::Arc<Vec<(String, axum::Router)>>,
}

/// The Host a request names, without its port.
fn host_of(request: &Request) -> String {
    request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default()
}

pub async fn dispatch(
    State(table): State<std::sync::Arc<TenantTable>>,
    request: Request,
    next: Next,
) -> Response {
    let host = host_of(&request);
    for (hostname, router) in table.entries.iter() {
        if *hostname == host {
            // The outer router's match already left its route-param
            // state in the extensions; the tenant router re-matches
            // the path itself, and axum MERGES param state rather
            // than replacing it — a stale outer set would make every
            // Path extractor count its captures twice. The tenant
            // chain rebuilds what it needs; nothing in the family
            // reads outer-match extensions.
            let (mut parts, body) = request.into_parts();
            parts.extensions.clear();
            return router
                .clone()
                .oneshot(Request::from_parts(parts, body))
                .await
                .expect("the tenant router answers");
        }
    }
    next.run(request).await
}

use tower::util::ServiceExt;
