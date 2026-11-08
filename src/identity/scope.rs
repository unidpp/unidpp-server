//! The scope table: the documented and enforced truth in one place
//! (REARCH R5). Every module's operations map to a scope of the form
//! `<module>:<level>`; the middleware consults this table, the
//! identity surface serves it, and the golden pins it — a scope
//! change is a table change is a contract change.

/// The level a method classifies as.
pub fn level_of(method: &str, path: &str) -> Level {
    match method {
        "GET" | "HEAD" => Level::Read,
        _ => {
            if path.contains("/admin/") {
                Level::Admin
            } else {
                Level::Write
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Read,
    Write,
    Admin,
}

/// The scope a request requires, from the module prefix it carries
/// and its method/path classification. `None` = the request is
/// public by contract and needs no credential:
/// - the deployment's own surface (`/`, `/healthz`, the contracts,
///   the version),
/// - the relay, whose contract is authentication-free by design
///   (a stateless relay between willing pairs; SI-3),
/// - the operator console, which gates its own sessions.
///
/// The federation peer shares the registry's scopes: it is a second
/// instance of the same module.
pub fn required_scope(module: &str, method: &str, path: &str) -> Option<String> {
    match module {
        // The identity surface enforces itself (bootstrap semantics
        // and self-rotation live in its handlers).
        "" | "relay" | "console" | "identity" => None,
        "registry-jp" => Some(levelled("registry", method, path)),
        other => Some(levelled(other, method, path)),
    }
}

fn levelled(module: &str, method: &str, path: &str) -> String {
    match level_of(method, path) {
        Level::Read => format!("{module}:read"),
        Level::Write => format!("{module}:write"),
        Level::Admin => format!("{module}:admin"),
    }
}

/// One row of the served table: the module, the three scopes, and
/// whether the module carries them (the relay carries none).
pub fn table() -> serde_json::Value {
    let modules = [
        "registry", "trust", "log", "issuer", "views", "render", "archive", "identity",
    ];
    let rows: Vec<serde_json::Value> = modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "module": m,
                "read": format!("{m}:read"),
                "write": format!("{m}:write"),
                "admin": format!("{m}:admin"),
                "note": if *m == "log" {
                    "the transparency log's append is a write; its anchors are reads"
                } else {
                    ""
                },
            })
        })
        .collect();
    serde_json::json!({
        "format": "unidpp-identity/scope-table@1",
        "rule": "GET is a read; a mutation on an /admin path is an admin; any other mutation is a write",
        "public": ["/", "/healthz", "/openapi.yaml", "/openapi.json", "/version", "/relay/*", "/console/*"],
        "modules": rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_writes_and_admins_classify() {
        assert_eq!(
            required_scope("registry", "GET", "/items"),
            Some("registry:read".to_string())
        );
        assert_eq!(
            required_scope("issuer", "POST", "/passports"),
            Some("issuer:write".to_string())
        );
        assert_eq!(
            required_scope("registry", "POST", "/admin/seed"),
            Some("registry:admin".to_string())
        );
        assert_eq!(required_scope("relay", "POST", "/relay"), None);
        assert_eq!(required_scope("console", "GET", "/config"), None);
        assert_eq!(required_scope("", "GET", "/healthz"), None);
    }

    #[test]
    fn the_peer_shares_the_registry_scopes() {
        assert_eq!(
            required_scope("registry-jp", "POST", "/items"),
            Some("registry:write".to_string())
        );
    }
}
