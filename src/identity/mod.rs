//! The identity model: actors and their scoped credentials, an
//! append-only journal, and replay (REARCH R4). A credential's
//! secret is shown exactly once at issuance; the store keeps its
//! SHA-256 digest and compares constant-time. Rotation issues a new
//! credential and revokes the old in one journal step, so the
//! rotation history reads from the store itself.

pub mod api;
pub mod enforce;
pub mod scope;

use std::collections::BTreeMap;

use unidpp_model::sha256;

/// The audience every credential is minted for: one deployment, one
/// audience.
pub const AUDIENCE: &str = "unidpp";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum ActorState {
    Active,
    Suspended,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Actor {
    pub id: String,
    pub org: String,
    pub name: String,
    #[schema(value_type = String)]
    pub state: ActorState,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum CredentialState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Credential {
    pub id: String,
    pub actor_id: String,
    pub org: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[schema(value_type = String)]
    pub state: CredentialState,
    pub secret_sha256: String,
    pub created_at: String,
    /// The credential this one superseded (the rotation chain's
    /// previous link), when issued by a rotation.
    pub rotated_from: Option<String>,
    pub revoked_reason: Option<String>,
}

/// One journal record: the store is the replay of these, in order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op")]
pub enum Op {
    ActorUpserted {
        actor: Actor,
    },
    CredentialIssued {
        credential: Credential,
    },
    CredentialRotated {
        old_id: String,
        new: Credential,
        reason: Option<String>,
    },
    CredentialRevoked {
        id: String,
        reason: String,
    },
}

/// The replayed store: actors by id, credentials by id, and the
/// credential-index-by-secret digest for constant-time lookup.
#[derive(Debug, Default)]
pub struct IdentityStore {
    actors: BTreeMap<String, Actor>,
    credentials: BTreeMap<String, Credential>,
    by_secret: BTreeMap<String, String>,
    journal: Vec<Op>,
}

/// The bearer token as presented: `credential-id.secret`.
fn split_bearer(token: &str) -> Option<(&str, &str)> {
    token.split_once('.')
}

fn digest_secret(secret: &str) -> String {
    let digest = sha256(&[b"UNIDPP-IDENTITY/CREDENTIAL", secret.as_bytes()]).0;
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

impl IdentityStore {
    /// An empty store (a deployment that has enrolled nobody).
    pub fn empty() -> IdentityStore {
        IdentityStore::default()
    }

    /// Replay journal records, in order.
    pub fn replay(&mut self, ops: impl IntoIterator<Item = Op>) {
        for op in ops {
            self.apply(op);
        }
    }

    fn apply(&mut self, op: Op) {
        match &op {
            Op::ActorUpserted { actor } => {
                self.actors.insert(actor.id.clone(), actor.clone());
            }
            Op::CredentialIssued { credential } => {
                self.by_secret
                    .insert(credential.secret_sha256.clone(), credential.id.clone());
                self.credentials
                    .insert(credential.id.clone(), credential.clone());
            }
            Op::CredentialRotated { old_id, new, .. } => {
                self.by_secret
                    .insert(new.secret_sha256.clone(), new.id.clone());
                if let Some(old) = self.credentials.get_mut(old_id) {
                    old.state = CredentialState::Revoked;
                }
                self.credentials.insert(new.id.clone(), new.clone());
            }
            Op::CredentialRevoked { id, reason } => {
                if let Some(credential) = self.credentials.get_mut(id) {
                    credential.state = CredentialState::Revoked;
                    credential.revoked_reason = Some(reason.clone());
                }
            }
        }
        self.journal.push(op);
    }

    /// The journal, for persistence.
    pub fn journal(&self) -> &[Op] {
        &self.journal
    }

    pub fn actor(&self, id: &str) -> Option<&Actor> {
        self.actors.get(id)
    }

    pub fn actors(&self) -> impl Iterator<Item = &Actor> {
        self.actors.values()
    }

    pub fn credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.get(id)
    }

    pub fn credentials(&self) -> impl Iterator<Item = &Credential> {
        self.credentials.values()
    }

    pub fn credentials_of(&self, actor_id: &str) -> Vec<&Credential> {
        self.credentials
            .values()
            .filter(|c| c.actor_id == actor_id)
            .collect()
    }

    /// The live credential a presented bearer token resolves to, if
    /// its secret matches and neither it nor its actor is revoked,
    /// suspended or retired. The digest lookup is exact; the digest
    /// inputs make equals-length secrets compare in constant work.
    pub fn resolve(&self, token: &str) -> Option<ResolvedCredential> {
        let (id, secret) = split_bearer(token)?;
        let credential = self.credentials.get(id)?;
        let presented = digest_secret(secret);
        // Constant-time compare of the two digests.
        if !constant_time_eq(&presented, &credential.secret_sha256) {
            return None;
        }
        if credential.state != CredentialState::Active {
            return None;
        }
        let actor = self.actors.get(&credential.actor_id)?;
        if actor.state != ActorState::Active {
            return None;
        }
        Some(ResolvedCredential {
            credential: credential.clone(),
            actor: actor.clone(),
        })
    }

    /// Whether the deployment has enrolled anyone: the open-mode
    /// cliff. An empty store serves an unconfigured deployment.
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }
}

/// A credential resolved for a request, with its actor.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub credential: Credential,
    pub actor: Actor,
}

impl ResolvedCredential {
    /// Whether this credential may act under `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.credential.scopes.iter().any(|s| s == scope)
    }
}

/// Constant-time equality over equal-length hex digests.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// A fresh identifier with a random suffix (`act-…`, `cred-…`).
fn new_id(kind: &str) -> String {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("platform randomness");
    let suffix: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("{kind}-{suffix}")
}

/// A fresh credential secret (the only time it exists in the clear).
fn new_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("platform randomness");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The mint: actor upsert + credential issuance as journal operations
/// the caller persists, with the one-time secret returned beside it.
pub struct IssuedCredential {
    pub ops: Vec<Op>,
    pub actor_id: String,
    pub credential_id: String,
    /// The bearer token, shown once: `credential-id.secret`.
    pub bearer: String,
    pub scopes: Vec<String>,
}

/// Enroll an actor (or re-state an existing one) and issue its first
/// credential.
pub fn enroll_actor(org: &str, name: &str, scopes: &[String], now: &str) -> IssuedCredential {
    let actor = Actor {
        id: new_id("act"),
        org: org.to_string(),
        name: name.to_string(),
        state: ActorState::Active,
        created_at: now.to_string(),
    };
    let actor_id = actor.id.clone();
    let (ops, credential_id, bearer, scopes) =
        issue_credential_ops(&actor_id, org, scopes, None, now);
    let mut all = vec![Op::ActorUpserted { actor }];
    all.extend(ops);
    IssuedCredential {
        ops: all,
        actor_id,
        credential_id,
        bearer,
        scopes,
    }
}

/// Issue an additional credential for an existing actor.
pub fn issue_for_actor(actor: &Actor, scopes: &[String], now: &str) -> IssuedCredential {
    let (ops, credential_id, bearer, scopes) =
        issue_credential_ops(&actor.id, &actor.org, scopes, None, now);
    IssuedCredential {
        ops,
        actor_id: actor.id.clone(),
        credential_id,
        bearer,
        scopes,
    }
}

/// Rotate: a new credential for the same actor, the old one revoked.
pub fn rotate_credential(
    actor: &Actor,
    old: &Credential,
    reason: Option<&str>,
    now: &str,
) -> IssuedCredential {
    let (mut ops, credential_id, bearer, scopes) = issue_credential_ops(
        &actor.id,
        &actor.org,
        &old.scopes,
        Some(old.id.clone()),
        now,
    );
    ops.push(Op::CredentialRevoked {
        id: old.id.clone(),
        reason: reason
            .map(str::to_string)
            .unwrap_or_else(|| format!("rotated to {credential_id}")),
    });
    IssuedCredential {
        ops,
        actor_id: actor.id.clone(),
        credential_id,
        bearer,
        scopes,
    }
}

fn issue_credential_ops(
    actor_id: &str,
    org: &str,
    scopes: &[String],
    rotated_from: Option<String>,
    now: &str,
) -> (Vec<Op>, String, String, Vec<String>) {
    let secret = new_secret();
    let credential = Credential {
        id: new_id("cred"),
        actor_id: actor_id.to_string(),
        org: org.to_string(),
        audience: AUDIENCE.to_string(),
        scopes: scopes.to_vec(),
        state: CredentialState::Active,
        secret_sha256: digest_secret(&secret),
        created_at: now.to_string(),
        rotated_from,
        revoked_reason: None,
    };
    let bearer = format!("{}.{}", credential.id, secret);
    let id = credential.id.clone();
    let issued_scopes = credential.scopes.clone();
    (
        vec![Op::CredentialIssued { credential }],
        id,
        bearer,
        issued_scopes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-11-08T00:00:00Z";

    fn enrolled(scopes: &[&str]) -> (IdentityStore, IssuedCredential) {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let issued = enroll_actor("test-org", "Test Operator", &scopes, NOW);
        let mut store = IdentityStore::empty();
        store.replay(issued.ops.clone());
        (store, issued)
    }

    #[test]
    fn a_fresh_bearer_resolves_to_its_actor_and_scopes() {
        let (store, issued) = enrolled(&["registry:read", "registry:admin"]);
        let resolved = store.resolve(&issued.bearer).expect("resolves");
        assert_eq!(resolved.actor.org, "test-org");
        assert!(resolved.has_scope("registry:read"));
        assert!(!resolved.has_scope("issuer:write"));
    }

    #[test]
    fn a_wrong_secret_does_not_resolve() {
        let (store, issued) = enrolled(&["registry:read"]);
        let tampered = format!("{}.00", issued.bearer);
        assert!(store.resolve(&tampered).is_none());
        assert!(store.resolve("cred-nothing.00").is_none());
    }

    #[test]
    fn rotation_revokes_the_old_link_and_the_new_resolves() {
        let (mut store, issued) = enrolled(&["issuer:write"]);
        let actor = store.actor(&issued.actor_id).cloned().expect("actor");
        let old = store
            .credential(&issued.credential_id)
            .cloned()
            .expect("cred");
        let rotated = rotate_credential(&actor, &old, None, NOW);
        store.replay(rotated.ops.clone());
        assert!(
            store.resolve(&issued.bearer).is_none(),
            "the old link is revoked"
        );
        let fresh = store
            .resolve(&rotated.bearer)
            .expect("the new link resolves");
        assert!(fresh.has_scope("issuer:write"));
        // The rotation chain reads from the store.
        assert_eq!(
            store
                .credential(&rotated.credential_id)
                .unwrap()
                .rotated_from,
            Some(issued.credential_id.clone())
        );
    }

    #[test]
    fn revocation_and_suspension_refuse() {
        let (mut store, issued) = enrolled(&["registry:read"]);
        store.apply(Op::CredentialRevoked {
            id: issued.credential_id.clone(),
            reason: "lost".into(),
        });
        assert!(store.resolve(&issued.bearer).is_none());
        // A suspended actor refuses even a live credential.
        let (mut store, issued) = enrolled(&["registry:read"]);
        let mut actor = store.actor(&issued.actor_id).cloned().unwrap();
        actor.state = ActorState::Suspended;
        store.apply(Op::ActorUpserted { actor });
        assert!(store.resolve(&issued.bearer).is_none());
    }

    #[test]
    fn an_empty_store_is_the_open_mode() {
        let store = IdentityStore::empty();
        assert!(store.is_empty());
        let (_, issued) = enrolled(&["registry:read"]);
        let mut store = IdentityStore::empty();
        store.replay(issued.ops);
        assert!(!store.is_empty());
    }

    #[test]
    fn the_journal_replays_to_the_same_state() {
        let (_, issued) = enrolled(&["registry:read", "views:read"]);
        let mut a = IdentityStore::empty();
        a.replay(issued.ops.clone());
        let mut b = IdentityStore::empty();
        b.replay(issued.ops);
        assert_eq!(a.credentials().count(), b.credentials().count());
        assert_eq!(
            a.resolve(&issued.bearer).map(|r| r.credential.id),
            b.resolve(&issued.bearer).map(|r| r.credential.id)
        );
    }
}
