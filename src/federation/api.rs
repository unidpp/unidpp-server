//! The federation routes: the estate's /s13 surface on the
//! self-hosted deployment — the custodian's keys, the node
//! registry, the policy registry, the segment pins, the signed
//! exchange, the counter-signature, the replay, and the dossier
//! encoders with the composition law.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use unidpp_grid::PolicyObject;
use unidpp_model::CanonicalWriter;
use unidpp_s13::coverage::CoverageReport;
use unidpp_s13::route::{compose as compose_law, LayerVector, RouteStep, VerificationRoute};
use unidpp_s13::{S13Request, S13Response};
use unidpp_signatif::s13::{NonRepudiableResponse, SignedS13Request, SignedS13Response};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain};

use super::{
    decode_hex, hex_of, verify_slot, Entry, FederationState, JournalLine, NodeRecord, SegmentPin,
    Store,
};

fn refused(status: StatusCode, error: String) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

fn stamped(status: StatusCode, body: serde_json::Value) -> Response {
    (status, [("x-as-of", crate::as_of())], Json(body)).into_response()
}

pub fn router(state: Arc<FederationState>) -> Router {
    Router::new()
        .route("/custodian", get(custodian_document))
        .route("/nodes", get(list_nodes).post(register_node))
        .route("/policies", get(list_policies).post(register_policy))
        .route("/segments", get(list_segments).post(pin_segment))
        .route("/requests", post(answer))
        .route("/countersign", post(countersign))
        .route("/journal", get(replay))
        .route("/route/encode", post(encode_route))
        .route("/coverage/encode", post(encode_coverage))
        .route("/compose", post(compose))
        .with_state(state)
}

async fn custodian_document(State(state): State<Arc<FederationState>>) -> Response {
    state.with_store(|store| {
        let custodian = store.nodes.get(&state.custodian().node_id);
        let authority = store.nodes.get(&state.authority().node_id);
        stamped(
            StatusCode::OK,
            serde_json::json!({
                "custodian": state.custodian().node_id,
                "key_id": custodian.map(|n| n.key_id.clone()),
                "public_hex": custodian.map(|n| n.public_hex.clone()),
                "authority": state.authority().node_id,
                "authority_key_id": authority.map(|n| n.key_id.clone()),
                "authority_public_hex": authority.map(|n| n.public_hex.clone()),
            }),
        )
    })
}

async fn list_nodes(State(state): State<Arc<FederationState>>) -> Response {
    state.with_store(|store| {
        let nodes: Vec<&NodeRecord> = store.nodes.values().collect();
        stamped(
            StatusCode::OK,
            serde_json::json!({ "count": nodes.len(), "nodes": nodes }),
        )
    })
}

async fn register_node(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let node_id = match body.get("node_id").and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return refused(StatusCode::BAD_REQUEST, "`node_id` is required".into()),
    };
    let suite = body
        .get("suite")
        .and_then(|v| v.as_str())
        .unwrap_or("ed25519")
        .to_string();
    let public_hex = body
        .get("public_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    if public_hex.is_empty() {
        return refused(StatusCode::BAD_REQUEST, "`public_hex` is required".into());
    }
    if suite != "ed25519" {
        return refused(StatusCode::BAD_REQUEST, format!("unknown suite `{suite}`"));
    }
    let key_bytes = match decode_hex(&public_hex) {
        Ok(bytes) => bytes,
        Err(e) => return refused(StatusCode::BAD_REQUEST, format!("`public_hex`: {e}")),
    };
    let public = match unidpp_signatif::PublicKey::from_bytes_in(
        unidpp_signatif::Suite::Ed25519,
        &key_bytes,
    ) {
        Ok(public) => public,
        Err(_) => {
            return refused(
                StatusCode::BAD_REQUEST,
                "the key bytes are unreadable".into(),
            )
        }
    };
    let record = NodeRecord {
        node_id: node_id.clone(),
        suite,
        public_hex,
        key_id: unidpp_signatif::KeyId::of(&public).as_str().to_string(),
    };
    let line = JournalLine::Node(record.clone());
    state.with_store_mut(vec![line], |store| {
        store.apply(JournalLine::Node(record.clone()));
        stamped(
            StatusCode::CREATED,
            serde_json::to_value(&record).expect("record"),
        )
    })
}

async fn list_policies(State(state): State<Arc<FederationState>>) -> Response {
    state.with_store(|store| {
        let policies: Vec<&PolicyObject> = store.policies.values().collect();
        stamped(
            StatusCode::OK,
            serde_json::json!({ "count": policies.len(), "policies": policies }),
        )
    })
}

async fn register_policy(
    State(state): State<Arc<FederationState>>,
    Json(policy): Json<PolicyObject>,
) -> Response {
    let line = JournalLine::Policy(policy.clone());
    state.with_store_mut(vec![line.clone()], |store| {
        store.apply(line);
        stamped(
            StatusCode::CREATED,
            serde_json::json!({
                "policy_id": policy.policy_id,
                "version": policy.version,
                "registered": true,
            }),
        )
    })
}

async fn list_segments(State(state): State<Arc<FederationState>>) -> Response {
    state.with_store(|store| {
        let segments: Vec<serde_json::Value> = store
            .segments
            .iter()
            .map(|(segment, pin)| {
                serde_json::json!({ "segment": segment, "policy_id": pin.policy_id, "version": pin.version })
            })
            .collect();
        stamped(
            StatusCode::OK,
            serde_json::json!({ "count": segments.len(), "segments": segments }),
        )
    })
}

async fn pin_segment(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let segment = match body.get("segment").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return refused(StatusCode::BAD_REQUEST, "`segment` is required".into()),
    };
    let policy_id = match body.get("policy_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return refused(StatusCode::BAD_REQUEST, "`policy_id` is required".into()),
    };
    let version = match body.get("version").and_then(|v| v.as_u64()) {
        Some(v) if v >= 1 => v,
        _ => {
            return refused(
                StatusCode::BAD_REQUEST,
                "`version` must be a positive integer".into(),
            )
        }
    };
    let present = state.with_store(|store| {
        store
            .policies
            .contains_key(&format!("{policy_id}@{version}"))
    });
    if !present {
        return refused(
            StatusCode::BAD_REQUEST,
            format!("no policy `{policy_id}` version {version} is registered"),
        );
    }
    let pin = SegmentPin { policy_id, version };
    let line = JournalLine::Segment {
        segment: segment.clone(),
        pin: pin.clone(),
    };
    state.with_store_mut(vec![line.clone()], |store| {
        store.apply(line);
        stamped(
            StatusCode::CREATED,
            serde_json::json!({
                "segment": segment,
                "policy_id": pin.policy_id,
                "version": pin.version,
                "pinned": true,
            }),
        )
    })
}

/// The seam's answer: verify the signed request under the registered
/// graph, evaluate the governing policy (the crate's own evaluate),
/// sign the answer, journal both sides.
async fn answer(
    State(state): State<Arc<FederationState>>,
    Json(signed): Json<SignedS13Request>,
) -> Response {
    let verification = state.with_store(|store| {
        verify_slot(
            store,
            &signed.requester,
            &signed.signature,
            &signed.request.canonical_bytes(),
        )
    });
    if let Err(error) = verification {
        return refused(StatusCode::FORBIDDEN, error);
    }
    let digest_hex = hex_of(&signed.request.digest());
    let response = state.with_store(|store| evaluate_for(store, &signed.request, &state));
    let canonical = response.canonical_bytes();
    let slot = SignatureSlot::sign(
        &state.custodian().key,
        SigningDomain::S13Message,
        &canonical,
    )
    .expect("the answer signs");
    let signed_response = SignedS13Response {
        response,
        signature: slot,
    };
    let request_line = JournalLine::Request(signed.clone());
    let response_line = JournalLine::Response(signed_response.clone());
    state.with_store_mut(vec![request_line, response_line], |store: &mut Store| {
        store.apply(JournalLine::Request(signed.clone()));
        store.apply(JournalLine::Response(signed_response.clone()));
        stamped(
            StatusCode::CREATED,
            serde_json::json!({
                "request_digest": digest_hex,
                "signed_response": serde_json::to_value(&signed_response).expect("wire"),
            }),
        )
    })
}

/// The policy evaluation: the segment's pin selects the governing
/// policy; no pin (or a missing version) answers a stated denial —
/// never silent, never an error code.
fn evaluate_for(store: &Store, request: &S13Request, state: &Arc<FederationState>) -> S13Response {
    let deny = |reason: String, policy: String, version: u64| S13Response {
        request_digest: request.digest(),
        outcome: unidpp_s13::S13Outcome::Deny { reason },
        governing_policy: policy,
        governing_policy_version: version,
        custodian: state.custodian().node_id.clone(),
    };
    let Some(pin) = store.segments.get(&request.segment) else {
        return deny(
            format!(
                "no governing policy is pinned for segment `{}`",
                request.segment
            ),
            String::new(),
            0,
        );
    };
    let Some(policy) = store
        .policies
        .get(&format!("{}@{}", pin.policy_id, pin.version))
    else {
        return deny(
            format!(
                "the pinned policy `{}` version {} is not registered",
                pin.policy_id, pin.version
            ),
            pin.policy_id.clone(),
            pin.version,
        );
    };
    S13Response::evaluate(request, policy, &state.custodian().node_id)
}

/// The non-repudiable answer (XB-7): the policy authority
/// counter-signs the custodian's answer and its place in the
/// per-(subject, custodian) sequence.
async fn countersign(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Some(digest_text) = body.get("request_digest").and_then(|v| v.as_str()) else {
        return refused(
            StatusCode::BAD_REQUEST,
            "`request_digest` is required".into(),
        );
    };
    let digest = match decode_hex(digest_text) {
        Ok(d) if d.len() == 32 => d,
        _ => {
            return refused(
                StatusCode::BAD_REQUEST,
                "`request_digest` must be 32 bytes of hex".into(),
            )
        }
    };
    // The place in the per-(subject, custodian) sequence counts the
    // subject's counter-signed answers across digests, not this
    // answer alone (XB-7: the authority counter-signs each place).
    let found = state.with_store(|store| {
        let mut subjects: std::collections::BTreeMap<[u8; 32], String> =
            std::collections::BTreeMap::new();
        for entry in &store.entries {
            if let Entry::Request(signed) = entry {
                subjects.insert(signed.request.digest(), signed.request.subject.clone());
            }
        }
        let this_subject: Option<String> = subjects.get(digest.as_slice()).cloned();
        let mut answered: Option<SignedS13Response> = None;
        let mut last_sequence = 0u64;
        for entry in &store.entries {
            match entry {
                Entry::Response(signed) => {
                    if signed.response.request_digest.as_slice() == digest.as_slice() {
                        answered = Some(signed.clone());
                    }
                }
                Entry::Countersigned(nr) => {
                    let subject = subjects
                        .get(&nr.signed.response.request_digest)
                        .cloned()
                        .unwrap_or_default();
                    if Some(subject) == this_subject
                        && nr.signed.response.custodian == state.custodian().node_id
                    {
                        last_sequence = last_sequence.max(nr.sequence);
                    }
                }
                _ => {}
            }
        }
        answered.map(|signed| {
            let subject = subjects
                .get(&signed.response.request_digest)
                .cloned()
                .unwrap_or_default();
            (signed, subject, last_sequence)
        })
    });
    let Some((signed, _subject, last_sequence)) = found else {
        return refused(
            StatusCode::NOT_FOUND,
            "no journaled answer carries that request digest".into(),
        );
    };
    let sequence = last_sequence + 1;
    let mut payload = CanonicalWriter::new();
    payload.write_bytes(&signed.response.request_digest);
    payload.write_bytes(&sequence.to_le_bytes());
    payload.write_bytes(signed.response.governing_policy.as_bytes());
    payload.write_bytes(&signed.response.governing_policy_version.to_le_bytes());
    let slot = SignatureSlot::sign(
        &state.authority().key,
        SigningDomain::S13Message,
        &payload.into_bytes(),
    )
    .expect("the counter-signature signs");
    let non_repudiable = NonRepudiableResponse {
        authority: state.authority().node_id.clone(),
        authority_signature: slot,
        sequence,
        signed: signed.clone(),
    };
    let line = JournalLine::Countersigned(non_repudiable.clone());
    state.with_store_mut(vec![line.clone()], |store| {
        store.apply(line);
        stamped(
            StatusCode::CREATED,
            serde_json::to_value(&non_repudiable).expect("wire"),
        )
    })
}

/// The choreography replay (XB-6): every entry verifies under the
/// registered graph, every answer binds to a journaled request, and
/// every counter-signature sits at its exact monotone place per
/// (subject, custodian), from 1. A failure is the tampering
/// evidence itself (409 with the entry and the reason).
async fn replay(State(state): State<Arc<FederationState>>) -> Response {
    let outcome = state.with_store(replay_store);
    match outcome {
        Ok(decisions) => {
            let entries = state.with_store(|store| {
                store
                    .entries
                    .iter()
                    .map(|entry| match entry {
                        Entry::Request(signed) => serde_json::to_value(signed).expect("wire"),
                        Entry::Response(signed) => serde_json::to_value(signed).expect("wire"),
                        Entry::Countersigned(nr) => serde_json::to_value(nr).expect("wire"),
                    })
                    .collect::<Vec<_>>()
            });
            stamped(
                StatusCode::OK,
                serde_json::json!({
                    "side": "custodian",
                    "count": entries.len(),
                    "entries": entries,
                    "decisions": decisions,
                }),
            )
        }
        Err((index, error)) => stamped(
            StatusCode::CONFLICT,
            serde_json::json!({ "valid": false, "entry": index, "error": error }),
        ),
    }
}

fn replay_store(store: &Store) -> Result<Vec<serde_json::Value>, (usize, String)> {
    let mut decisions = Vec::new();
    let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let mut subjects: std::collections::BTreeMap<[u8; 32], String> =
        std::collections::BTreeMap::new();
    let mut sequences: std::collections::BTreeMap<(String, String), u64> =
        std::collections::BTreeMap::new();
    for (index, entry) in store.entries.iter().enumerate() {
        let index = index + 1;
        match entry {
            Entry::Request(signed) => {
                if let Err(error) = verify_slot(
                    store,
                    &signed.requester,
                    &signed.signature,
                    &signed.request.canonical_bytes(),
                ) {
                    return Err((index, error));
                }
                let digest = signed.request.digest();
                subjects.insert(digest, signed.request.subject.clone());
                seen.insert(digest);
            }
            Entry::Response(signed) => {
                if let Err(error) = verify_slot(
                    store,
                    &signed.response.custodian,
                    &signed.signature,
                    &signed.response.canonical_bytes(),
                ) {
                    return Err((index, error));
                }
                if !seen.contains(&signed.response.request_digest) {
                    return Err((
                        index,
                        "an answer is bound to no journaled request".to_string(),
                    ));
                }
                decisions.push(decision_of(&signed.response));
            }
            Entry::Countersigned(nr) => {
                if !seen.contains(&nr.signed.response.request_digest) {
                    return Err((
                        index,
                        "an answer is bound to no journaled request".to_string(),
                    ));
                }
                let subject = subjects
                    .get(&nr.signed.response.request_digest)
                    .cloned()
                    .unwrap_or_default();
                let place = (subject, nr.signed.response.custodian.clone());
                let expected = sequences.get(&place).copied().unwrap_or(0) + 1;
                if nr.sequence != expected {
                    return Err((
                        index,
                        format!(
                            "s13 non-repudiation: stale sequence {} (expected {expected}) — a replayed answer",
                            nr.sequence
                        ),
                    ));
                }
                let custodian_ok = verify_slot(
                    store,
                    &nr.signed.response.custodian,
                    &nr.signed.signature,
                    &nr.signed.response.canonical_bytes(),
                );
                if let Err(error) = custodian_ok {
                    return Err((index, error));
                }
                let mut payload = CanonicalWriter::new();
                payload.write_bytes(&nr.signed.response.request_digest);
                payload.write_bytes(&nr.sequence.to_le_bytes());
                payload.write_bytes(nr.signed.response.governing_policy.as_bytes());
                payload.write_bytes(&nr.signed.response.governing_policy_version.to_le_bytes());
                if let Err(error) = verify_slot(
                    store,
                    &nr.authority,
                    &nr.authority_signature,
                    &payload.into_bytes(),
                ) {
                    return Err((index, error));
                }
                sequences.insert(place, nr.sequence);
                decisions.push(decision_of(&nr.signed.response));
            }
        }
    }
    Ok(decisions)
}

fn decision_of(response: &S13Response) -> serde_json::Value {
    serde_json::json!({
        "request_digest_hex": hex_of(&response.request_digest),
        "outcome": response.outcome.token(),
        "governing_policy": response.governing_policy,
        "governing_policy_version": response.governing_policy_version,
    })
}

async fn encode_route(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let _ = state;
    let Some(steps) = body.get("steps").and_then(|v| v.as_array()) else {
        return refused(
            StatusCode::BAD_REQUEST,
            "`steps` is required (a JSON array)".into(),
        );
    };
    let parsed: Result<Vec<RouteStep>, _> = steps
        .iter()
        .map(|step| serde_json::from_value(step.clone()))
        .collect();
    let steps = match parsed {
        Ok(steps) => steps,
        Err(e) => return refused(StatusCode::BAD_REQUEST, format!("route refused: {e}")),
    };
    let mut route = VerificationRoute::new();
    route.steps = steps;
    stamped(
        StatusCode::OK,
        serde_json::json!({
            "canonical_hex": hex_of(&route.canonical_bytes()),
            "digest_hex": hex_of(&route.digest()),
        }),
    )
}

async fn encode_coverage(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let _ = state;
    let report: CoverageReport = match body
        .get("report")
        .map(|v| serde_json::from_value(v.clone()))
    {
        Some(Ok(report)) => report,
        _ => return refused(StatusCode::BAD_REQUEST, "`report` is required".into()),
    };
    stamped(
        StatusCode::OK,
        serde_json::json!({
            "canonical_hex": hex_of(&report.canonical_bytes()),
            "digest_hex": hex_of(&report.digest()),
        }),
    )
}

async fn compose(
    State(state): State<Arc<FederationState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let _ = state;
    let vector: LayerVector = match body
        .get("vector")
        .map(|v| serde_json::from_value(v.clone()))
    {
        Some(Ok(vector)) => vector,
        _ => {
            return refused(
                StatusCode::BAD_REQUEST,
                "`vector` is required (the six layers)".into(),
            )
        }
    };
    let policy_cap = match body.get("policy_cap").and_then(|v| v.as_u64()) {
        Some(cap) if cap <= 255 => cap as u8,
        _ => {
            return refused(
                StatusCode::BAD_REQUEST,
                "`policy_cap` must be a non-negative integer within the scale".into(),
            )
        }
    };
    let composition = compose_law(&vector, policy_cap);
    stamped(
        StatusCode::OK,
        serde_json::to_value(&composition).expect("law"),
    )
}
