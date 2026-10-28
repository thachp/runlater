//! Nonproduction project key lifecycle. No plaintext tokens are persisted or returned.
use crate::{
    core::{Fault, DAY},
    security::{configured_keys, digest, tenant_valid, AuthFault},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Enqueue,
    Read,
    Cancel,
    Redrive,
    Configure,
    ManageKeys,
}
impl Permission {
    pub fn all() -> BTreeSet<Self> {
        [
            Self::Enqueue,
            Self::Read,
            Self::Cancel,
            Self::Redrive,
            Self::Configure,
            Self::ManageKeys,
        ]
        .into_iter()
        .collect()
    }
}
pub struct Credential {
    pub tenant: String,
    pub key_id: String,
    pub verifier: String,
}
pub fn key_id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bootstrap_id(hash: &str) -> String {
    format!(
        "bootstrap_{}",
        &digest(format!("runlater-bootstrap-id:{hash}").as_bytes())[..32]
    )
}
pub fn route_credential(config: &str, token: &str) -> Result<Credential, AuthFault> {
    let keys = configured_keys(config)?;
    if token.len() > 256 || token.is_empty() {
        return Err(AuthFault::Unauthorized);
    }
    let verifier = digest(token.as_bytes());
    if token.starts_with("rl_local.") {
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 4
            || !tenant_valid(parts[1])
            || !keys.values().any(|tenant| tenant == parts[1])
            || !key_id_valid(parts[2])
            || !(16..=128).contains(&parts[3].len())
            || !parts[3]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(AuthFault::Unauthorized);
        }
        return Ok(Credential {
            tenant: parts[1].into(),
            key_id: parts[2].into(),
            verifier,
        });
    }
    let tenant = keys.get(&verifier).ok_or(AuthFault::Unauthorized)?;
    Ok(Credential {
        tenant: tenant.clone(),
        key_id: bootstrap_id(&verifier),
        verifier,
    })
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NewKey {
    pub key_id: String,
    pub token_sha256: String,
    pub permissions: BTreeSet<Permission>,
    #[serde(default)]
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub spec: NewKey,
    pub created_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub rotated_from: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyView {
    pub key_id: String,
    pub permissions: BTreeSet<Permission>,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub created_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub rotated_from: Option<String>,
}
impl KeyRecord {
    pub fn view(&self) -> KeyView {
        KeyView {
            key_id: self.spec.key_id.clone(),
            permissions: self.spec.permissions.clone(),
            not_before_ms: self.spec.not_before_ms,
            expires_at_ms: self.spec.expires_at_ms,
            created_ms: self.created_ms,
            revoked_at_ms: self.revoked_at_ms,
            rotated_from: self.rotated_from.clone(),
        }
    }
    fn active(&self, now: i64) -> bool {
        now >= self.spec.not_before_ms
            && now < self.spec.expires_at_ms
            && self.revoked_at_ms.is_none_or(|at| now < at)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Audit {
    pub actor_key_id: String,
    pub target_key_id: String,
    pub action: String,
    pub at_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Rotation {
    source: String,
    revoke_old_at_ms: i64,
    spec: NewKey,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Keyring {
    pub tenant: String,
    pub keys: BTreeMap<String, KeyRecord>,
    pub audit: Vec<Audit>,
    pub rotations: BTreeMap<String, Rotation>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum AccessFault {
    Unauthorized,
    Forbidden,
}
#[derive(Clone)]
pub struct Actor {
    pub tenant: String,
    pub key_id: String,
    pub permissions: BTreeSet<Permission>,
}
pub enum KeyCommand {
    Create(NewKey),
    Revoke {
        key_id: String,
    },
    Rotate {
        key_id: String,
        new_key: NewKey,
        revoke_old_at_ms: i64,
    },
}
pub enum KeyQuery {
    List,
    Audit,
}
impl Keyring {
    pub fn bootstrap(config: &str, tenant: &str) -> Result<Self, AuthFault> {
        let mut keys = BTreeMap::new();
        for (hash, project) in configured_keys(config)? {
            if project == tenant {
                let id = bootstrap_id(&hash);
                keys.insert(
                    id.clone(),
                    KeyRecord {
                        spec: NewKey {
                            key_id: id,
                            token_sha256: hash,
                            permissions: Permission::all(),
                            not_before_ms: 0,
                            expires_at_ms: i64::MAX,
                        },
                        created_ms: 0,
                        revoked_at_ms: None,
                        rotated_from: None,
                    },
                );
            }
        }
        if keys.len() > 64 {
            return Err(AuthFault::InvalidConfiguration);
        }
        Ok(Self {
            tenant: tenant.into(),
            keys,
            audit: vec![],
            rotations: BTreeMap::new(),
        })
    }
    pub fn authorize(
        &self,
        c: &Credential,
        permission: Permission,
        now: i64,
    ) -> Result<Actor, AccessFault> {
        if c.tenant != self.tenant {
            return Err(AccessFault::Unauthorized);
        }
        let key = self.keys.get(&c.key_id).ok_or(AccessFault::Unauthorized)?;
        if !key.active(now)
            || key
                .spec
                .token_sha256
                .as_bytes()
                .ct_eq(c.verifier.as_bytes())
                .unwrap_u8()
                != 1
        {
            return Err(AccessFault::Unauthorized);
        }
        if !key.spec.permissions.contains(&permission) {
            return Err(AccessFault::Forbidden);
        }
        Ok(Actor {
            tenant: self.tenant.clone(),
            key_id: c.key_id.clone(),
            permissions: key.spec.permissions.clone(),
        })
    }
    fn validate_new(spec: &NewKey, actor: &Actor, now: i64) -> Result<(), Fault> {
        if !key_id_valid(&spec.key_id)
            || spec.key_id.starts_with("bootstrap_")
            || !hash_valid(&spec.token_sha256)
            || spec.permissions.is_empty()
            || spec.not_before_ms < 0
            || spec.not_before_ms >= spec.expires_at_ms
            || spec.expires_at_ms <= now
            || spec.expires_at_ms > now.saturating_add(30 * DAY)
        {
            return Err(Fault::Invalid);
        }
        if !spec.permissions.is_subset(&actor.permissions) {
            return Err(Fault::Forbidden);
        }
        Ok(())
    }
    fn record(&mut self, actor: &Actor, target: &str, action: &str, now: i64) {
        self.audit.push(Audit {
            actor_key_id: actor.key_id.clone(),
            target_key_id: target.into(),
            action: action.into(),
            at_ms: now,
        });
        if self.audit.len() > 256 {
            self.audit.remove(0);
        }
    }
    fn target(&self, id: &str, actor: &Actor) -> Result<KeyRecord, Fault> {
        let record = self.keys.get(id).ok_or(Fault::NotFound)?;
        if !record.spec.permissions.is_subset(&actor.permissions) {
            return Err(Fault::Forbidden);
        }
        Ok(record.clone())
    }
    pub fn command(
        &mut self,
        actor: &Actor,
        c: KeyCommand,
        now: i64,
    ) -> Result<(KeyView, bool), Fault> {
        if actor.tenant != self.tenant {
            return Err(Fault::Forbidden);
        }
        let current = self.keys.get(&actor.key_id).ok_or(Fault::Forbidden)?;
        if !current.active(now) || current.spec.permissions != actor.permissions {
            return Err(Fault::Forbidden);
        }
        if !actor.permissions.contains(&Permission::ManageKeys) {
            return Err(Fault::Forbidden);
        }
        match c {
            KeyCommand::Create(spec) => {
                if let Some(existing) = self.keys.get(&spec.key_id) {
                    if existing.spec != spec || existing.rotated_from.is_some() {
                        return Err(Fault::Conflict);
                    }
                    if !spec.permissions.is_subset(&actor.permissions) {
                        return Err(Fault::Forbidden);
                    }
                    return Ok((existing.view(), false));
                }
                Self::validate_new(&spec, actor, now)?;
                if self.keys.len() >= 64 {
                    return Err(Fault::Capacity);
                }
                let record = KeyRecord {
                    spec,
                    created_ms: now,
                    revoked_at_ms: None,
                    rotated_from: None,
                };
                let view = record.view();
                self.keys.insert(view.key_id.clone(), record);
                self.record(actor, &view.key_id, "created", now);
                Ok((view, true))
            }
            KeyCommand::Revoke { key_id } => {
                self.target(&key_id, actor)?;
                let record = self.keys.get_mut(&key_id).ok_or(Fault::NotFound)?;
                let changed = record.revoked_at_ms.is_none_or(|at| at > now);
                record.revoked_at_ms = Some(record.revoked_at_ms.unwrap_or(now).min(now));
                let view = record.view();
                if changed {
                    self.record(actor, &key_id, "revoked", now)
                }
                Ok((view, false))
            }
            KeyCommand::Rotate {
                key_id,
                new_key,
                revoke_old_at_ms,
            } => {
                if let Some(rotation) = self.rotations.get(&new_key.key_id) {
                    if rotation.source != key_id
                        || rotation.spec != new_key
                        || rotation.revoke_old_at_ms != revoke_old_at_ms
                    {
                        return Err(Fault::Conflict);
                    }
                    self.target(&key_id, actor)?;
                    let record = self.target(&new_key.key_id, actor)?;
                    if record.rotated_from.as_deref() != Some(key_id.as_str()) {
                        return Err(Fault::Conflict);
                    }
                    return Ok((record.view(), false));
                }
                let old = self.target(&key_id, actor)?;
                if !old.active(now)
                    || new_key.key_id == key_id
                    || self.keys.contains_key(&new_key.key_id)
                {
                    return Err(Fault::Conflict);
                }
                Self::validate_new(&new_key, actor, now)?;
                if revoke_old_at_ms < now
                    || revoke_old_at_ms > now.saturating_add(DAY)
                    || new_key.not_before_ms
                        > revoke_old_at_ms
                            .min(old.spec.expires_at_ms)
                            .min(old.revoked_at_ms.unwrap_or(revoke_old_at_ms))
                    || new_key.expires_at_ms <= revoke_old_at_ms
                {
                    return Err(Fault::Invalid);
                }
                if self.keys.len() >= 64 {
                    return Err(Fault::Capacity);
                }
                let record = KeyRecord {
                    spec: new_key.clone(),
                    created_ms: now,
                    revoked_at_ms: None,
                    rotated_from: Some(key_id.clone()),
                };
                let view = record.view();
                self.keys
                    .get_mut(&key_id)
                    .ok_or(Fault::NotFound)?
                    .revoked_at_ms = Some(
                    old.revoked_at_ms
                        .unwrap_or(revoke_old_at_ms)
                        .min(revoke_old_at_ms),
                );
                self.keys.insert(view.key_id.clone(), record);
                self.rotations.insert(
                    view.key_id.clone(),
                    Rotation {
                        source: key_id.clone(),
                        spec: new_key,
                        revoke_old_at_ms,
                    },
                );
                self.record(actor, &key_id, "rotation_scheduled", now);
                self.record(actor, &view.key_id, "created_by_rotation", now);
                Ok((view, true))
            }
        }
    }
    pub fn query(&self, q: KeyQuery) -> serde_json::Value {
        match q {
            KeyQuery::List => {
                serde_json::json!({"keys":self.keys.values().map(KeyRecord::view).collect::<Vec<_>>()})
            }
            KeyQuery::Audit => serde_json::json!({"events":self.audit}),
        }
    }
}
pub fn required_permission(method: &str, path: &str) -> Option<Permission> {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["v1", "tasks"])
        | ("GET", ["v1", "tasks", _])
        | ("GET", ["v1", "tasks", _, "attempts"])
        | ("GET", ["v1", "tasks", _, "inspection"])
        | ("GET", ["v1", "queue", "dead-letters"])
        | ("GET", ["v1", "queue", "dead-letters", _])
        | ("GET", ["v1", "queue", "metrics"])
        | ("GET", ["v1", "queue", "health"])
        | ("GET", ["v1", "queue", "audit"])
        | ("GET", ["v1", "queue"]) => Some(Permission::Read),
        ("POST", ["v1", "tasks"]) => Some(Permission::Enqueue),
        ("POST", ["v1", "tasks", _, "cancel"]) => Some(Permission::Cancel),
        ("POST", ["v1", "tasks", _, "redrive"]) => Some(Permission::Redrive),
        ("POST", ["v1", "queue", "dead-letters"])
        | ("POST", ["v1", "queue", "dead-letters", _, "reconcile"]) => Some(Permission::Configure),
        ("POST", ["v1", "queue", "maintenance"]) => Some(Permission::Configure),
        ("PUT", ["v1", "queue"]) => Some(Permission::Configure),
        ("GET", ["v1", "keys"])
        | ("GET", ["v1", "keys", "audit"])
        | ("POST", ["v1", "keys"])
        | ("POST", ["v1", "keys", _, "revoke"])
        | ("POST", ["v1", "keys", _, "rotate"]) => Some(Permission::ManageKeys),
        _ => None,
    }
}
