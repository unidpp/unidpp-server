//! The federation gates on the one-binary estate: a foreign
//! verifier's signed request answers under the governing policy (the
//! s13 crate's own evaluation), the answer verifies under the
//! custodian's published key, the choreography journals and replays,
//! the authority counter-signs at the monotone place, and the
//! dossier encoders reproduce the corpus digest — the same journey
//! the edge serves, native.

use axum::body::Body;
use axum::http::Request;
use tower::util::ServiceExt;
use unidpp_s13::S13Request;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::s13::SignedS13Request;
use unidpp_signatif::sign::{SigningDomain, Suite};

const ROUTE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../unidpp-core/crates/s13/fixtures/canonical/verification-route.json"
);
const ROUTE_DIGEST: &str = "4ac3b495cfea7a2bb04f15812a04f479fcbe65bd77d8807125a264a7a50a63c6";

async fn app() -> axum::Router {
    unidpp_server::build_router().expect("the router builds")
}

async fn post_json(app: &axum::Router, path: &str, body: &str) -> axum::http::Response<Body> {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("probe request");
    app.clone().oneshot(request).await.expect("probe answered")
}

async fn get(app: &axum::Router, path: &str) -> axum::http::Response<Body> {
    let request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("probe request");
    app.clone().oneshot(request).await.expect("probe answered")
}

async fn body_of(
    response: impl std::future::Future<Output = axum::http::Response<Body>>,
) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.await.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_id": "cn-dynamic-bms",
        "version": 1,
        "authority": "cn-samr",
        "readers": ["cn-customs"],
        "verifiers": ["cn-customs", "de-zoll"],
        "writers": ["weilian-shenzhen"],
        "reveal": "OriginSealed",
        "suites": ["sm2"],
        "valid_from": "2027-01-01T00:00:00Z",
        "valid_to": null,
        "superseded_by": null,
    })
}

fn request_for(subject: &str) -> S13Request {
    S13Request {
        verifier: "de-zoll".into(),
        subject: subject.into(),
        profile: "urn:unidpp:profile:eu-battery".into(),
        segment: "cn-dynamic".into(),
        at: "2030-06-01T08:00:00Z".into(),
    }
}

#[tokio::test]
async fn the_foreign_verifier_completes_the_journey() {
    let app = app().await;

    // The custodian announces its seeded keys.
    let custodian = body_of(get(&app, "/s13/custodian")).await;
    assert_eq!(custodian["custodian"], "unidpp-custodian");
    assert!(
        custodian["key_id"]
            .as_str()
            .expect("key id")
            .starts_with("k-"),
        "the custodian's key id is derived"
    );

    // The foreign verifier registers under its own key.
    let verifier_key = KeyPair::seeded(Suite::Ed25519, b"s13/test-verifier").expect("key");
    let public_hex = hex_of(verifier_key.public().as_bytes());
    let registered = body_of(post_json(
        &app,
        "/s13/nodes",
        &serde_json::json!({
            "node_id": "de-zoll",
            "suite": "ed25519",
            "public_hex": public_hex,
        })
        .to_string(),
    ))
    .await;
    assert_eq!(registered["node_id"], "de-zoll");

    // The policy registers and the segment pins.
    let policy = body_of(post_json(&app, "/s13/policies", &policy().to_string())).await;
    assert_eq!(policy["registered"], true);
    let pin = body_of(post_json(
        &app,
        "/s13/segments",
        &serde_json::json!({
            "segment": "cn-dynamic",
            "policy_id": "cn-dynamic-bms",
            "version": 1,
        })
        .to_string(),
    ))
    .await;
    assert_eq!(pin["pinned"], true);

    // The signed request answers: origin-sealed offers the
    // authority's attestation service, citing the governing policy.
    let signed_request = SignedS13Request::issue(
        request_for("urn:unidpp:passport:pack-0001"),
        "de-zoll",
        &verifier_key,
    )
    .expect("the request signs");
    let answered = body_of(post_json(
        &app,
        "/s13/requests",
        &serde_json::to_string(&signed_request).expect("wire"),
    ))
    .await;
    assert_eq!(
        answered["signed_response"]["response"]["outcome"]["outcome"],
        "attestation-offer"
    );
    assert_eq!(
        answered["signed_response"]["response"]["outcome"]["attestation_service"],
        "cn-samr-attestation"
    );
    assert_eq!(
        answered["signed_response"]["response"]["governing_policy"],
        "cn-dynamic-bms"
    );

    // The answer verifies under the custodian's published key (the
    // native slot verify, in the test's own hands).
    let custodian_public = unidpp_signatif::PublicKey::from_bytes_in(
        Suite::Ed25519,
        &hex_to_bytes(custodian["public_hex"].as_str().expect("public")),
    )
    .expect("key");
    let signed_response: unidpp_signatif::s13::SignedS13Response =
        serde_json::from_value(answered["signed_response"].clone()).expect("wire");
    signed_response
        .signature
        .verify(
            SigningDomain::S13Message,
            &signed_response.response.canonical_bytes(),
            &custodian_public,
        )
        .expect("the answer verifies");

    // The journal replays with the decision.
    let journal = body_of(get(&app, "/s13/journal")).await;
    assert_eq!(journal["side"], "custodian");
    let decisions = journal["decisions"].as_array().expect("decisions");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["outcome"], "attestation-offer");

    // The authority counter-signs at the place (sequence 1), and the
    // counter-signature verifies under the authority's key.
    let countersigned = body_of(post_json(
        &app,
        "/s13/countersign",
        &serde_json::json!({ "request_digest": answered["request_digest"] }).to_string(),
    ))
    .await;
    assert_eq!(countersigned["sequence"], 1);
    assert_eq!(countersigned["authority"], "unidpp-authority");
    let authority_public = unidpp_signatif::PublicKey::from_bytes_in(
        Suite::Ed25519,
        &hex_to_bytes(custodian["authority_public_hex"].as_str().expect("public")),
    )
    .expect("key");
    let non_repudiable: unidpp_signatif::s13::NonRepudiableResponse =
        serde_json::from_value(countersigned.clone()).expect("wire");
    let mut payload = unidpp_model::CanonicalWriter::new();
    payload.write_bytes(&non_repudiable.signed.response.request_digest);
    payload.write_bytes(&non_repudiable.sequence.to_le_bytes());
    payload.write_bytes(non_repudiable.signed.response.governing_policy.as_bytes());
    payload.write_bytes(
        &non_repudiable
            .signed
            .response
            .governing_policy_version
            .to_le_bytes(),
    );
    non_repudiable
        .authority_signature
        .verify(
            SigningDomain::S13Message,
            &payload.into_bytes(),
            &authority_public,
        )
        .expect("the counter-signature verifies");

    // A second answer for the same subject countersigns at the next
    // place; the journal replays with every decision in sequence.
    let second_request = SignedS13Request::issue(
        request_for("urn:unidpp:passport:pack-0002"),
        "de-zoll",
        &verifier_key,
    )
    .expect("the request signs");
    let second = body_of(post_json(
        &app,
        "/s13/requests",
        &serde_json::to_string(&second_request).expect("wire"),
    ))
    .await;
    assert_eq!(
        second["signed_response"]["response"]["outcome"]["outcome"],
        "attestation-offer"
    );
    let second_countersigned = body_of(post_json(
        &app,
        "/s13/countersign",
        &serde_json::json!({ "request_digest": second["request_digest"] }).to_string(),
    ))
    .await;
    assert_eq!(second_countersigned["sequence"], 1);
    let third_request = SignedS13Request::issue(
        request_for("urn:unidpp:passport:pack-0002"),
        "de-zoll",
        &verifier_key,
    )
    .expect("the request signs");
    let third = body_of(post_json(
        &app,
        "/s13/requests",
        &serde_json::to_string(&third_request).expect("wire"),
    ))
    .await;
    let third_countersigned = body_of(post_json(
        &app,
        "/s13/countersign",
        &serde_json::json!({ "request_digest": third["request_digest"] }).to_string(),
    ))
    .await;
    assert_eq!(third_countersigned["sequence"], 2);
    let replayed = body_of(get(&app, "/s13/journal")).await;
    assert_eq!(
        replayed["decisions"].as_array().expect("decisions").len(),
        6
    );

    // An unregistered verifier refuses before any evaluation.
    let stranger_key = KeyPair::seeded(Suite::Ed25519, b"s13/test-stranger").expect("key");
    let stranger = SignedS13Request::issue(
        request_for("urn:unidpp:passport:pack-0003"),
        "jp-meti",
        &stranger_key,
    )
    .expect("the request signs");
    let refused = post_json(
        &app,
        "/s13/requests",
        &serde_json::to_string(&stranger).expect("wire"),
    )
    .await;
    assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_dossier_encoders_reproduce_the_corpus() {
    let app = app().await;
    let fixture = std::fs::read_to_string(ROUTE_FIXTURE).expect("the corpus fixture");
    let parsed: serde_json::Value = serde_json::from_str(&fixture).expect("fixture");
    let encoded = body_of(post_json(
        &app,
        "/s13/route/encode",
        &serde_json::json!({ "steps": parsed["route"]["steps"] }).to_string(),
    ))
    .await;
    assert_eq!(encoded["digest_hex"], ROUTE_DIGEST);
    let composed = body_of(post_json(
        &app,
        "/s13/compose",
        &serde_json::json!({
            "vector": {
                "transport": "same",
                "protocol": "same",
                "structure": "gap",
                "semantics": "same",
                "identity": "same",
                "trust": "same",
            },
            "policy_cap": 4,
        })
        .to_string(),
    ))
    .await;
    assert_eq!(composed["level"], 0);
    assert_eq!(composed["bottleneck"], "structure");
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
