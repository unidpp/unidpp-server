//! The union contract: every module's golden `openapi.yaml`, embedded
//! verbatim, re-keyed under its prefix, with the deployment keys
//! unioned. The served root document and the committed union golden
//! both derive from this one builder (R1, D2).

use serde_yaml::{Mapping, Value};

/// (module name = URL prefix, source service, the golden document).
/// The order is the union document's order — stable by construction.
pub const MODULES: &[(&str, &str, &str)] = &[
    (
        "registry",
        "unidpp-registry",
        include_str!("../../unidpp-registry/openapi.yaml"),
    ),
    (
        "trust",
        "unidpp-trust",
        include_str!("../../unidpp-trust/openapi.yaml"),
    ),
    (
        "log",
        "unidpp-log",
        include_str!("../../unidpp-log/openapi.yaml"),
    ),
    (
        "issuer",
        "unidpp-issuer",
        include_str!("../../unidpp-issuer/openapi.yaml"),
    ),
    (
        "views",
        "unidpp-projector",
        include_str!("../../unidpp-projector/openapi.yaml"),
    ),
    (
        "render",
        "unidpp-gateway",
        include_str!("../../unidpp-gateway/openapi.yaml"),
    ),
    (
        "archive",
        "unidpp-archive",
        include_str!("../../unidpp-archive/openapi.yaml"),
    ),
    (
        "relay",
        "unidpp-hub",
        include_str!("../../unidpp-hub/openapi.yaml"),
    ),
];

fn base_document() -> Mapping {
    let mut license = Mapping::new();
    license.insert(Value::from("name"), Value::from("Apache-2.0"));
    license.insert(Value::from("identifier"), Value::from("Apache-2.0"));

    let mut info = Mapping::new();
    info.insert(
        Value::from("title"),
        Value::from("UniDPP — the one deployment"),
    );
    info.insert(
        Value::from("version"),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    info.insert(
        Value::from("description"),
        Value::from(
            "UniDPP serves the whole estate as one deployment: every module (registry, trust, \
             log, issuer, views, render, archive, relay) keeps its own contract behind its \
             prefix, and this document is the union of them. Each module's golden document is \
             served byte-identically at `/<module>/openapi.yaml`; this document exists so a \
             client of the whole deployment reads one surface.",
        ),
    );
    info.insert(Value::from("license"), Value::Mapping(license));

    let mut server = Mapping::new();
    server.insert(Value::from("url"), Value::from("/"));

    let mut doc = Mapping::new();
    doc.insert(Value::from("openapi"), Value::from("3.1.0"));
    doc.insert(Value::from("info"), Value::Mapping(info));
    doc.insert(
        Value::from("servers"),
        Value::from(vec![Value::Mapping(server)]),
    );
    doc
}

fn module_contract(module: &str, yaml: &str) -> Value {
    serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("module {module}: golden parses: {e}"))
}

/// The union of every module's contract. Deterministic: module order
/// is `MODULES` order, path order is golden order, keys deduplicate
/// on first sight.
pub fn union_contract() -> Value {
    let mut doc = base_document();

    let mut paths = Mapping::new();
    let mut env_keys: Vec<String> = Vec::new();
    let mut tags: Vec<Value> = Vec::new();
    let mut tag_names: Vec<String> = Vec::new();

    for (name, _source, yaml) in MODULES {
        let module_doc = module_contract(name, yaml);
        let prefix = format!("/{name}");
        if let Some(module_paths) = module_doc.get("paths").and_then(Value::as_mapping) {
            for (path, item) in module_paths {
                if let Some(p) = path.as_str() {
                    paths.insert(Value::from(format!("{prefix}{p}")), item.clone());
                }
            }
        }
        let keys = module_doc
            .get("info")
            .and_then(|info| info.get("x-unidpp-env-keys"))
            .and_then(Value::as_sequence);
        if let Some(keys) = keys {
            for key in keys {
                if let Some(text) = key.as_str() {
                    if !env_keys.iter().any(|k| k == text) {
                        env_keys.push(text.to_string());
                    }
                }
            }
        }
        if let Some(module_tags) = module_doc.get("tags").and_then(Value::as_sequence) {
            for tag in module_tags {
                let tag_name = tag
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if !tag_names.contains(&tag_name) {
                    tag_names.push(tag_name);
                    tags.push(tag.clone());
                }
            }
        }
    }

    {
        let info = doc
            .get_mut("info")
            .and_then(Value::as_mapping_mut)
            .expect("info mapping");
        let unioned: Vec<Value> = env_keys.iter().map(|k| Value::from(k.as_str())).collect();
        info.insert(Value::from("x-unidpp-env-keys"), Value::from(unioned));
    }
    if !tags.is_empty() {
        doc.insert(Value::from("tags"), Value::from(tags));
    }
    doc.insert(Value::from("paths"), Value::Mapping(paths));
    Value::Mapping(doc)
}

/// The served root contract (the union document as YAML).
pub fn contract_yaml() -> String {
    serde_yaml::to_string(&union_contract()).expect("the union contract renders")
}

/// The served root contract as compact JSON (`/openapi.json`).
pub fn contract_json() -> String {
    serde_json::to_string(&union_contract()).expect("the union contract serializes")
}

/// The deployment discovery document at `/`.
pub fn discovery_document() -> Value {
    let mut modules: Vec<Value> = Vec::new();
    for (name, source, _) in MODULES {
        let mut entry = Mapping::new();
        entry.insert(Value::from("name"), Value::from(*name));
        entry.insert(Value::from("service"), Value::from(*source));
        entry.insert(Value::from("prefix"), Value::from(format!("/{name}")));
        entry.insert(
            Value::from("contract"),
            Value::from(format!("/{name}/openapi.yaml")),
        );
        entry.insert(
            Value::from("health"),
            Value::from(format!("/{name}/healthz")),
        );
        modules.push(Value::Mapping(entry));
    }

    let mut doc = Mapping::new();
    doc.insert(Value::from("service"), Value::from("unidpp"));
    doc.insert(
        Value::from("version"),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    doc.insert(
        Value::from("description"),
        Value::from(
            "UniDPP as one deployment: every module of the estate in one process, one port, \
             one data root (the REARCH consolidation)",
        ),
    );
    doc.insert(Value::from("modules"), Value::from(modules));
    doc.insert(
        Value::from("contract"),
        Value::from(vec![
            Value::from("one service: every module shares one process, one port and one data root"),
            Value::from(
                "contracts unchanged: each module serves its golden document behind its prefix",
            ),
            Value::from("multi-user: operations carry actor scopes (the identity module)"),
            Value::from("multi-tenant: tenants are folders under one process, not deployments"),
        ]),
    );
    Value::Mapping(doc)
}
