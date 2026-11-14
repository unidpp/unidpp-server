//! The federation surface (the S13 seam) for the self-hosted
//! estate: a verifier's SIGNED request answers under the governing
//! grid policy, the custodian's answer is signed in the S13-MESSAGE
//! domain, the authority counter-signs the answer's place (XB-7),
//! and the whole choreography replays from the journal alone (XB-6).
//! The policy evaluation and every signature ride the s13 and
//! signatif crates' own code; this module carries the trust-graph
//! projection (the registered peer keys), the policy registry, the
//! segment pins, and the journal — the same shape the estate's edge
//! serves behind /s13, with the same seed degrades.

pub mod api;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::Serialize;
use unidpp_grid::PolicyObject;
use unidpp_model::sha256;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::s13::{NonRepudiableResponse, SignedS13Request, SignedS13Response};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_signatif::{KeyId, PublicKey};

#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub suite: String,
    pub public_hex: String,
    pub key_id: String,
}

#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct SegmentPin {
    pub policy_id: String,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub enum Entry {
    Request(SignedS13Request),
    Response(SignedS13Response),
    Countersigned(NonRepudiableResponse),
}

#[derive(Default)]
pub struct Store {
    pub nodes: BTreeMap<String, NodeRecord>,
    pub policies: BTreeMap<String, PolicyObject>,
    pub segments: BTreeMap<String, SegmentPin>,
    pub entries: Vec<Entry>,
}

pub struct Operator {
    pub node_id: String,
    pub key: KeyPair,
}

pub struct FederationState {
    store: RwLock<Store>,
    journal_path: Option<PathBuf>,
    custodian: Operator,
    authority: Operator,
}

fn seeded(label: &str) -> KeyPair {
    let digest = sha256(&[label.as_bytes()]);
    KeyPair::seeded(Suite::Ed25519, digest.as_bytes()).expect("seeded keypair")
}

fn seed_from_env(value: Option<String>, label: &str) -> KeyPair {
    if let Some(hex) = value.filter(|v| !v.trim().is_empty()) {
        let hex = hex.trim().to_string();
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut seed = [0u8; 32];
            if (0..32).all(|i| {
                u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                    .map(|b| {
                        seed[i] = b;
                        true
                    })
                    .is_ok()
            }) {
                if let Ok(key) = KeyPair::seeded(Suite::Ed25519, &seed) {
                    return key;
                }
            }
        }
    }
    seeded(label)
}

fn record_of(node_id: &str, key: &KeyPair) -> NodeRecord {
    NodeRecord {
        node_id: node_id.to_string(),
        suite: "ed25519".to_string(),
        public_hex: hex_of(key.public().as_bytes()),
        key_id: KeyId::of(key.public()).as_str().to_string(),
    }
}

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// The journal line: every mutation persists as one line, replayed
/// on boot (the estate's journal discipline).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum JournalLine {
    Node(NodeRecord),
    Policy(PolicyObject),
    Segment { segment: String, pin: SegmentPin },
    Request(SignedS13Request),
    Response(SignedS13Response),
    Countersigned(NonRepudiableResponse),
}

impl Store {
    fn apply(&mut self, line: JournalLine) {
        match line {
            JournalLine::Node(record) => {
                if !record.key_id.is_empty() {
                    self.nodes.insert(record.node_id.clone(), record);
                }
            }
            JournalLine::Policy(policy) => {
                self.policies
                    .insert(format!("{}@{}", policy.policy_id, policy.version), policy);
            }
            JournalLine::Segment { segment, pin } => {
                self.segments.insert(segment, pin);
            }
            JournalLine::Request(signed) => self.entries.push(Entry::Request(signed)),
            JournalLine::Response(signed) => self.entries.push(Entry::Response(signed)),
            JournalLine::Countersigned(nr) => self.entries.push(Entry::Countersigned(nr)),
        }
    }
}

impl FederationState {
    /// Build from the environment: `UNIDPP_S13_STATE_FILE` persists
    /// the journal (absent = in-memory federation, the fresh-install
    /// degrade); the custodian and the policy authority derive their
    /// seeded keys from `UNIDPP_S13_CUSTODIAN_SEED` /
    /// `UNIDPP_S13_AUTHORITY_SEED` (hex, 64 chars) or the
    /// deterministic dev seeds — the same degrades the edge carries.
    pub fn from_env() -> FederationState {
        let journal_path = std::env::var("UNIDPP_S13_STATE_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let custodian = Operator {
            node_id: std::env::var("UNIDPP_S13_CUSTODIAN_ID")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "unidpp-custodian".to_string()),
            key: seed_from_env(
                std::env::var("UNIDPP_S13_CUSTODIAN_SEED").ok(),
                "UNIDPP-S13/CUSTODIAN-SEED",
            ),
        };
        let authority = Operator {
            node_id: std::env::var("UNIDPP_S13_AUTHORITY_ID")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "unidpp-authority".to_string()),
            key: seed_from_env(
                std::env::var("UNIDPP_S13_AUTHORITY_SEED").ok(),
                "UNIDPP-S13/AUTHORITY-SEED",
            ),
        };
        let mut store = Store::default();
        if let Some(path) = &journal_path {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(line) = serde_json::from_str::<JournalLine>(line) {
                        store.apply(line);
                    }
                }
            }
        }
        let state = FederationState {
            store: RwLock::new(store),
            journal_path,
            custodian,
            authority,
        };
        state.ensure_operators();
        state
    }

    /// The custodian and the policy authority register their seeded
    /// keys, so every journaled answer verifies under this graph.
    fn ensure_operators(&self) {
        let mut store = self.store.write().expect("store");
        let mut lines = Vec::new();
        for operator in [&self.custodian, &self.authority] {
            if store.nodes.contains_key(&operator.node_id) {
                continue;
            }
            let record = record_of(&operator.node_id, &operator.key);
            lines.push(JournalLine::Node(record.clone()));
            store.apply(lines.last().expect("line").clone());
        }
        drop(store);
        self.persist(&lines);
    }

    /// Append the journal lines to the state file (append-only; the
    /// lines are deterministic for the seeded operators, so a boot
    /// replay restores them even if a write never landed).
    pub fn persist(&self, lines: &[JournalLine]) {
        let Some(path) = &self.journal_path else {
            return;
        };
        let mut text = String::new();
        for line in lines {
            text.push_str(&serde_json::to_string(line).expect("line"));
            text.push('\n');
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(text.as_bytes());
        }
    }

    pub fn custodian(&self) -> &Operator {
        &self.custodian
    }

    pub fn authority(&self) -> &Operator {
        &self.authority
    }

    pub fn with_store<T>(&self, f: impl FnOnce(&Store) -> T) -> T {
        f(&self.store.read().expect("store"))
    }

    /// Mutate the store under the lock, appending the given journal
    /// lines when the deployment persists federation at all.
    pub fn with_store_mut<T>(&self, lines: Vec<JournalLine>, f: impl FnOnce(&mut Store) -> T) -> T {
        let mut store = self.store.write().expect("store");
        let outcome = f(&mut store);
        drop(store);
        self.persist(&lines);
        outcome
    }
}

/// The verification against the registered graph: the signature must
/// resolve to the DECLARED node's registered key (a valid signature
/// from any other node is not this envelope).
pub fn verify_slot(
    store: &Store,
    node: &str,
    slot: &SignatureSlot,
    payload: &[u8],
) -> Result<(), String> {
    let record = store
        .nodes
        .get(node)
        .ok_or_else(|| format!("s13 node `{node}` has no such keys"))?;
    if record.key_id != slot.key_id.as_str() {
        return Err(format!("s13 node `{node}` has no such key"));
    }
    let public = PublicKey::from_bytes_in(Suite::Ed25519, &decode_hex(&record.public_hex)?)
        .map_err(|_| format!("s13 node `{node}` carries an unreadable key"))?;
    slot.verify(SigningDomain::S13Message, payload, &public)
        .map_err(|_| format!("the signature does not verify under `{node}`'s key"))
}
