//! Offline purchase accounting contract. No routes, credentials, network, or activation path.
//! All authority and verifiers are trusted application context, never request-body fields.
use runlater::{
    funding,
    security::{digest, tenant_valid},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod entitlements;

pub const SAFE: u64 = 9_007_199_254_740_991;
pub const MAX_INTENTS: usize = funding::MAX_GRANTS;
pub const MAX_EVENTS: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Disabled,
    Invalid,
    Forbidden,
    Conflict,
    StaleRevision,
    Expired,
    CapExceeded,
    Overflow,
    Capacity,
    Unverified,
    Binding,
    ClockRegressed,
    Corrupt,
    Funding(funding::Error),
    Task(runlater::core::Fault),
}
impl From<runlater::core::Fault> for Error {
    fn from(e: runlater::core::Fault) -> Self {
        Self::Task(e)
    }
}
impl From<funding::Error> for Error {
    fn from(e: funding::Error) -> Self {
        Self::Funding(e)
    }
}
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b)
        .filter(|n| *n <= SAFE)
        .ok_or(Error::Overflow)
}
fn mul(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_mul(b)
        .filter(|n| *n <= SAFE)
        .ok_or(Error::Overflow)
}
fn timestamp(n: i64) -> bool {
    n > 0 && n as u64 <= SAFE
}
fn positive(n: u64) -> bool {
    n > 0 && n <= SAFE
}

/// Synthetic terms only. No default trial, currency, duration, or commercial price.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub attempt_units: u64,
    pub quote_ttl_ms: i64,
    pub admission_ttl_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegateCap {
    pub per_purchase_minor: u64,
    pub window_minor: u64,
}
/// A single explicit, immutable spending window. No rollover or automatic top-up.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub offer: Offer,
    pub starts_at_ms: i64,
    pub ends_at_ms: i64,
    pub project_window_minor: u64,
    pub purchasers: BTreeMap<String, DelegateCap>,
}
impl Policy {
    fn validate(&self) -> Result<(), Error> {
        let o = &self.offer;
        if !positive(self.version)
            || !tenant_valid(&o.id)
            || !positive(o.amount_minor)
            || !positive(o.attempt_units)
            || o.currency.len() != 3
            || !o.currency.bytes().all(|b| b.is_ascii_lowercase())
            || !timestamp(o.quote_ttl_ms)
            || !timestamp(o.admission_ttl_ms)
            || o.admission_ttl_ms <= o.quote_ttl_ms
            || !timestamp(self.starts_at_ms)
            || !timestamp(self.ends_at_ms)
            || self.ends_at_ms <= self.starts_at_ms
            || !positive(self.project_window_minor)
            || self.purchasers.is_empty()
            || self.purchasers.len() > MAX_INTENTS
            || self.purchasers.iter().any(|(id, c)| {
                !tenant_valid(id)
                    || !positive(c.per_purchase_minor)
                    || !positive(c.window_minor)
                    || c.per_purchase_minor > c.window_minor
            })
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
/// Obtained by a future server-side purchase authorizer. Task permission is separate.
/// Not deserializable: an HTTP body cannot supply this trusted context.
#[derive(Clone, Debug)]
pub enum Authority<'a> {
    Task {
        project: &'a str,
        principal: &'a str,
    },
    Purchase {
        project: &'a str,
        principal: &'a str,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: String,
    pub project_id: String,
    pub purchaser: String,
    pub idempotency_key: String,
    pub policy_version: u64,
    pub offer_id: String,
    pub packs: u64,
    pub amount_minor: u64,
    pub currency: String,
    pub grant: funding::GrantSpec,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
impl Intent {
    pub fn digest(&self) -> String {
        digest(&serde_json::to_vec(self).expect("intent serialization"))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reversal {
    FullRefund,
    FullReversal,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    Settled {
        payment_id: String,
        paid_at_ms: i64,
    },
    Reversed {
        payment_id: String,
        reason: Reversal,
    },
    /// Definitive no-payment result from the trusted verifier; timeout is insufficient.
    NoPaymentFinal,
}
/// Normalized adapter output, never client-supplied evidence. No Deserialize implementation.
/// A future MPP/Stripe adapter must verify protocol bindings AND provider settlement first.
/// ```compile_fail
/// use runlater_offline_credit_purchases::VerifiedEvent;
/// let fabricated: VerifiedEvent = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VerifiedEvent {
    pub fixture_only: bool,
    pub event_id: String,
    pub project_id: String,
    pub intent_id: String,
    pub intent_digest: String,
    pub amount_minor: u64,
    pub currency: String,
    pub observed_at_ms: i64,
    pub kind: EventKind,
}
pub trait SettlementVerifier {
    /// Opaque bytes are untrusted. Implementations are installed by the application,
    /// must be side-effect-free, and may not charge or settle a payment from this call.
    fn verify(&self, intent: &Intent, evidence: &[u8]) -> Result<VerifiedEvent, Error>;
}
/// The only shipped adapter. Refuses every payment claim.
pub struct DisabledVerifier;
impl SettlementVerifier for DisabledVerifier {
    fn verify(&self, _: &Intent, _: &[u8]) -> Result<VerifiedEvent, Error> {
        Err(Error::Disabled)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub payment_id: Option<String>,
    pub paid_at_ms: Option<i64>,
    pub reversed: Option<Reversal>,
    pub no_payment_final: bool,
    pub entitlement_order: Option<u64>,
    pub reversal_order: Option<u64>,
}
impl Receipt {
    fn pending() -> Self {
        Self {
            payment_id: None,
            paid_at_ms: None,
            reversed: None,
            no_payment_final: false,
            entitlement_order: None,
            reversal_order: None,
        }
    }
    fn held(&self) -> bool {
        self.payment_id.is_none() && !self.no_payment_final
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Purchase {
    intent: Intent,
    receipt: Receipt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "Snapshot")]
pub struct OfflineLedger {
    schema: u8,
    project_id: String,
    policy: Option<Policy>,
    revision: u64,
    clock_ms: i64,
    purchases: BTreeMap<String, Purchase>,
    /// Immutable event tombstones; never purge and reuse payment evidence.
    events: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    project_id: String,
    policy: Option<Policy>,
    revision: u64,
    clock_ms: i64,
    purchases: BTreeMap<String, Purchase>,
    events: BTreeMap<String, String>,
}
impl TryFrom<Snapshot> for OfflineLedger {
    type Error = String;
    fn try_from(s: Snapshot) -> Result<Self, String> {
        let ledger = Self {
            schema: s.schema,
            project_id: s.project_id,
            policy: s.policy,
            revision: s.revision,
            clock_ms: s.clock_ms,
            purchases: s.purchases,
            events: s.events,
        };
        ledger
            .validate()
            .map_err(|e| format!("invalid offline snapshot: {e:?}"))?;
        Ok(ledger)
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CapBalance {
    pub pending_minor: u64,
    pub gross_committed_minor: u64,
}
impl CapBalance {
    fn total(&self) -> Result<u64, Error> {
        add(self.pending_minor, self.gross_committed_minor)
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Balance {
    pub activation_enabled: bool,
    pub fixture_only: bool,
    pub sampled_at_ms: i64,
    pub revision: u64,
    pub available: u64,
    pub selected_grant: Option<String>,
    pub admission_available: u64,
    pub reserved: u64,
    pub spent: u64,
    pub retired: u64,
    pub spending: CapBalance,
}
impl OfflineLedger {
    pub fn new(project_id: &str, policy: Option<Policy>) -> Result<Self, Error> {
        if !tenant_valid(project_id) {
            return Err(Error::Invalid);
        }
        if let Some(p) = &policy {
            p.validate()?;
        }
        Ok(Self {
            schema: 1,
            project_id: project_id.into(),
            policy,
            revision: 1,
            clock_ms: 0,
            purchases: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    fn check(&self, expected: u64, now: i64) -> Result<(), Error> {
        if expected != self.revision {
            return Err(Error::StaleRevision);
        }
        if !timestamp(now) || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        Ok(())
    }
    fn commit(&mut self, mut next: Self, now: i64) -> Result<(), Error> {
        next.revision = add(self.revision, 1)?;
        next.clock_ms = now;
        next.validate()?;
        *self = next;
        Ok(())
    }
    fn project(&self, project: &str) -> Result<(), Error> {
        if project != self.project_id {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn cap_balance(&self, purchaser: Option<&str>) -> Result<CapBalance, Error> {
        let mut b = CapBalance {
            pending_minor: 0,
            gross_committed_minor: 0,
        };
        for p in self
            .purchases
            .values()
            .filter(|p| purchaser.is_none_or(|id| p.intent.purchaser == id))
        {
            if p.receipt.held() {
                b.pending_minor = add(b.pending_minor, p.intent.amount_minor)?;
            } else if p.receipt.payment_id.is_some() {
                // Refunds never replenish delegated purchase authority.
                b.gross_committed_minor = add(b.gross_committed_minor, p.intent.amount_minor)?;
            }
        }
        b.total()?;
        Ok(b)
    }
    pub fn create_intent(
        &mut self,
        expected: u64,
        authority: Authority<'_>,
        key: &str,
        packs: u64,
        now: i64,
    ) -> Result<Intent, Error> {
        self.check(expected, now)?;
        let Authority::Purchase { project, principal } = authority else {
            return Err(Error::Forbidden);
        };
        self.project(project)?;
        let policy = self.policy.as_ref().ok_or(Error::Disabled)?;
        let cap = policy.purchasers.get(principal).ok_or(Error::Forbidden)?;
        if !tenant_valid(key) || packs == 0 {
            return Err(Error::Invalid);
        }
        let id = format!(
            "purchase_{}",
            &digest(&serde_json::to_vec(&(project, principal, key)).unwrap())[..40]
        );
        if let Some(p) = self.purchases.get(&id) {
            if p.intent.packs != packs {
                return Err(Error::Conflict);
            }
            // Same immutable quote/receipt, including after expiry or settlement.
            return Ok(p.intent.clone());
        }
        if now < policy.starts_at_ms || now >= policy.ends_at_ms {
            return Err(Error::Expired);
        }
        if self.purchases.len() >= MAX_INTENTS {
            return Err(Error::Capacity);
        }
        let amount = mul(policy.offer.amount_minor, packs)?;
        let units = mul(policy.offer.attempt_units, packs)?;
        let prior_units = self
            .purchases
            .values()
            .try_fold(0, |total, p| add(total, p.intent.grant.total_attempt_units))?;
        add(prior_units, units)?;
        if amount > cap.per_purchase_minor
            || add(self.cap_balance(None)?.total()?, amount)? > policy.project_window_minor
            || add(self.cap_balance(Some(principal))?.total()?, amount)? > cap.window_minor
        {
            return Err(Error::CapExceeded);
        }
        let expiry = now
            .checked_add(policy.offer.quote_ttl_ms)
            .filter(|n| timestamp(*n))
            .ok_or(Error::Overflow)?;
        let admission_expiry = now
            .checked_add(policy.offer.admission_ttl_ms)
            .filter(|n| timestamp(*n))
            .ok_or(Error::Overflow)?;
        let intent = Intent {
            id: id.clone(),
            project_id: project.into(),
            purchaser: principal.into(),
            idempotency_key: key.into(),
            policy_version: policy.version,
            offer_id: policy.offer.id.clone(),
            packs,
            amount_minor: amount,
            currency: policy.offer.currency.clone(),
            grant: funding::GrantSpec {
                grant_id: id.clone(),
                total_attempt_units: units,
                admission_expires_at_ms: admission_expiry,
            },
            issued_at_ms: now,
            expires_at_ms: expiry.min(policy.ends_at_ms),
        };
        let mut next = self.clone();
        next.purchases.insert(
            id,
            Purchase {
                intent: intent.clone(),
                receipt: Receipt::pending(),
            },
        );
        self.commit(next, now)?;
        Ok(intent)
    }
    /// Read the immutable quote from trusted persisted purchase state. A codec must
    /// not replace this lookup with a caller-supplied quote or task authority.
    pub fn intent(&self, project: &str, id: &str) -> Result<&Intent, Error> {
        self.project(project)?;
        Ok(&self.purchases.get(id).ok_or(Error::Invalid)?.intent)
    }
    pub fn receipt(&self, project: &str, id: &str) -> Result<&Receipt, Error> {
        self.project(project)?;
        Ok(&self.purchases.get(id).ok_or(Error::Invalid)?.receipt)
    }
    pub fn reconcile(
        &mut self,
        expected: u64,
        project: &str,
        id: &str,
        evidence: &[u8],
        verifier: &impl SettlementVerifier,
        now: i64,
    ) -> Result<Receipt, Error> {
        self.check(expected, now)?;
        self.project(project)?;
        let p = self.purchases.get(id).ok_or(Error::Invalid)?;
        if evidence.len() > 8192 {
            return Err(Error::Invalid);
        }
        let event = verifier.verify(&p.intent, evidence)?;
        if !event.fixture_only {
            return Err(Error::Disabled);
        }
        if !tenant_valid(&event.event_id)
            || event.project_id != self.project_id
            || event.intent_id != id
            || event.intent_digest != p.intent.digest()
            || event.amount_minor != p.intent.amount_minor
            || event.currency != p.intent.currency
            || !timestamp(event.observed_at_ms)
            || event.observed_at_ms < p.intent.issued_at_ms
            || event.observed_at_ms > now
        {
            return Err(Error::Binding);
        }
        let hash = digest(&serde_json::to_vec(&event).unwrap());
        if let Some(old) = self.events.get(&event.event_id) {
            return if old == &hash {
                Ok(p.receipt.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.events.len() >= MAX_EVENTS {
            return Err(Error::Capacity);
        }
        let payment = match &event.kind {
            EventKind::Settled {
                payment_id,
                paid_at_ms,
            } => {
                if *paid_at_ms < p.intent.issued_at_ms
                    || *paid_at_ms >= p.intent.expires_at_ms
                    || *paid_at_ms > event.observed_at_ms
                {
                    return Err(Error::Expired);
                }
                Some(payment_id)
            }
            EventKind::Reversed { payment_id, .. } => Some(payment_id),
            EventKind::NoPaymentFinal => None,
        };
        if let Some(payment) = payment {
            if !tenant_valid(payment) {
                return Err(Error::Binding);
            }
            if p.receipt
                .payment_id
                .as_ref()
                .is_some_and(|old| old != payment)
                || self.purchases.values().any(|other| {
                    other.intent.id != id && other.receipt.payment_id.as_ref() == Some(payment)
                })
            {
                return Err(Error::Conflict);
            }
            if p.receipt.no_payment_final {
                return Err(Error::Conflict);
            }
        }
        let mut next = self.clone();
        let receipt = &mut next.purchases.get_mut(id).unwrap().receipt;
        match event.kind {
            EventKind::Settled {
                payment_id,
                paid_at_ms,
            } => {
                if receipt.paid_at_ms.is_some_and(|old| old != paid_at_ms) {
                    return Err(Error::Conflict);
                }
                receipt.payment_id = Some(payment_id);
                receipt.paid_at_ms = Some(paid_at_ms);
                // A reversal arriving first permanently suppresses entitlement issuance.
                if receipt.reversed.is_none() && receipt.entitlement_order.is_none() {
                    receipt.entitlement_order = Some(add(self.revision, 1)?);
                }
            }
            EventKind::Reversed { payment_id, reason } => {
                if receipt.reversed.as_ref().is_some_and(|old| old != &reason) {
                    return Err(Error::Conflict);
                }
                receipt.payment_id = Some(payment_id);
                receipt.reversed = Some(reason);
                if receipt.reversal_order.is_none() {
                    receipt.reversal_order = Some(add(self.revision, 1)?);
                }
            }
            EventKind::NoPaymentFinal => {
                if receipt.payment_id.is_some() {
                    return Err(Error::Conflict);
                }
                receipt.no_payment_final = true;
            }
        }
        let result = receipt.clone();
        next.events.insert(event.event_id, hash);
        self.commit(next, now)?;
        Ok(result)
    }
    /// Synthetic grant directives, to be committed together with the purchase ledger by
    /// a future application adapter. Never merge this policy into a live operator project.
    pub fn funding_updates(&self, after_revision: u64) -> Result<Vec<funding::Policy>, Error> {
        if after_revision > self.revision {
            return Err(Error::StaleRevision);
        }
        let mut orders = std::collections::BTreeSet::from([self.revision]);
        for p in self.purchases.values() {
            orders.extend(p.receipt.entitlement_order);
            orders.extend(p.receipt.reversal_order);
        }
        Ok(orders
            .into_iter()
            .filter(|order| *order > after_revision)
            .map(|order| {
                let active = self
                    .purchases
                    .values()
                    .filter(|p| {
                        p.receipt.entitlement_order.is_some_and(|o| o <= order)
                            && !p.receipt.reversal_order.is_some_and(|o| o <= order)
                    })
                    .max_by_key(|p| p.receipt.entitlement_order);
                funding::Policy {
                    version: 1,
                    project_id: self.project_id.clone(),
                    revision: order,
                    active_grant: active.map(|p| p.intent.grant.clone()),
                    revoked_grants: self
                        .purchases
                        .values()
                        .filter(|p| p.receipt.reversal_order.is_some_and(|o| o <= order))
                        .map(|p| p.intent.id.clone())
                        .collect(),
                }
            })
            .collect())
    }
    /// Persist the returned cursor with the funding state in one transaction. Applying
    /// all missing directives preserves every grant after crash/lost-response recovery.
    pub fn sync_funding(
        &self,
        state: &mut funding::State,
        after_revision: u64,
        now: i64,
    ) -> Result<u64, Error> {
        if !timestamp(now) || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        if after_revision > 0 {
            state.project(&self.project_id)?;
        }
        let mut next = state.clone();
        for policy in self.funding_updates(after_revision)? {
            next.apply(&policy, now)?;
        }
        next.advance(now)?;
        *state = next;
        Ok(self.revision)
    }
    /// Pure sampled projection; never use a balance read to authorize a purchase or task.
    pub fn balance(
        &self,
        project: &str,
        funding: &funding::State,
        applied_revision: u64,
        now: i64,
    ) -> Result<Balance, Error> {
        self.project(project)?;
        if !timestamp(now) || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        let mut view = funding.clone();
        self.sync_funding(&mut view, applied_revision, now)?;
        let selected_grant = self
            .funding_updates(self.revision - 1)?
            .pop()
            .and_then(|policy| policy.active_grant)
            .map(|g| g.grant_id);
        let admission_available = selected_grant
            .as_deref()
            .and_then(|id| view.grant(id))
            .map_or(0, |g| g.available);
        let mut result = Balance {
            activation_enabled: false,
            fixture_only: true,
            sampled_at_ms: now,
            revision: self.revision,
            available: 0,
            selected_grant,
            admission_available,
            reserved: 0,
            spent: 0,
            retired: 0,
            spending: self.cap_balance(None)?,
        };
        for p in self.purchases.values() {
            if let Some(g) = view.grant(&p.intent.id) {
                if g.spec != p.intent.grant {
                    return Err(Error::Corrupt);
                }
                result.available = add(result.available, g.available)?;
                result.reserved = add(result.reserved, g.reserved)?;
                result.spent = add(result.spent, g.spent)?;
                result.retired = add(result.retired, g.retired)?;
            }
        }
        Ok(result)
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::Corrupt)
    }
    /// Trusted durable storage only; snapshots are not purchase/payment API inputs.
    pub fn restore(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 256 * 1024 {
            return Err(Error::Capacity);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema != 1
            || !tenant_valid(&self.project_id)
            || !positive(self.revision)
            || self.clock_ms < 0
            || self.clock_ms as u64 > SAFE
            || self.purchases.len() > MAX_INTENTS
            || self.events.len() > MAX_EVENTS
            || self.events.iter().any(|(id, hash)| {
                !tenant_valid(id)
                    || hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(Error::Corrupt);
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
            if self.cap_balance(None)?.total()? > policy.project_window_minor {
                return Err(Error::Corrupt);
            }
            for (id, cap) in &policy.purchasers {
                if self.cap_balance(Some(id))?.total()? > cap.window_minor {
                    return Err(Error::Corrupt);
                }
            }
            let mut payments = BTreeMap::new();
            let mut orders = std::collections::BTreeSet::new();
            let mut total_units = 0;
            for (id, p) in &self.purchases {
                let i = &p.intent;
                total_units = add(total_units, i.grant.total_attempt_units)?;
                for order in [p.receipt.entitlement_order, p.receipt.reversal_order]
                    .into_iter()
                    .flatten()
                {
                    if !orders.insert(order) {
                        return Err(Error::Corrupt);
                    }
                }
                let cap = policy.purchasers.get(&i.purchaser).ok_or(Error::Corrupt)?;
                let expected_id = format!(
                    "purchase_{}",
                    &digest(
                        &serde_json::to_vec(&(&i.project_id, &i.purchaser, &i.idempotency_key))
                            .unwrap()
                    )[..40]
                );
                if id != &i.id
                    || id != &expected_id
                    || i.grant.grant_id != *id
                    || i.project_id != self.project_id
                    || !tenant_valid(&i.idempotency_key)
                    || i.packs == 0
                    || i.policy_version != policy.version
                    || i.offer_id != policy.offer.id
                    || i.currency != policy.offer.currency
                    || i.amount_minor != mul(i.packs, policy.offer.amount_minor)?
                    || i.amount_minor > cap.per_purchase_minor
                    || i.grant.total_attempt_units != mul(i.packs, policy.offer.attempt_units)?
                    || i.issued_at_ms < policy.starts_at_ms
                    || i.issued_at_ms >= policy.ends_at_ms
                    || i.issued_at_ms > self.clock_ms
                    || !timestamp(i.expires_at_ms)
                    || i.expires_at_ms
                        != i.issued_at_ms
                            .checked_add(policy.offer.quote_ttl_ms)
                            .ok_or(Error::Overflow)?
                            .min(policy.ends_at_ms)
                    || !timestamp(i.grant.admission_expires_at_ms)
                    || i.grant.admission_expires_at_ms
                        != i.issued_at_ms
                            .checked_add(policy.offer.admission_ttl_ms)
                            .ok_or(Error::Overflow)?
                    || p.receipt.no_payment_final && p.receipt.payment_id.is_some()
                    || p.receipt.paid_at_ms.is_some() && p.receipt.payment_id.is_none()
                    || p.receipt.paid_at_ms.is_some()
                        && p.receipt.reversed.is_none()
                        && p.receipt.entitlement_order.is_none()
                    || p.receipt.reversed.is_some() && p.receipt.payment_id.is_none()
                    || p.receipt.reversed.is_some() != p.receipt.reversal_order.is_some()
                    || p.receipt
                        .reversal_order
                        .is_some_and(|o| o <= 1 || o > self.revision)
                    || p.receipt.paid_at_ms.is_some_and(|paid| {
                        paid < i.issued_at_ms || paid >= i.expires_at_ms || paid > self.clock_ms
                    })
                    || p.receipt.entitlement_order.is_some_and(|order| {
                        order <= 1
                            || order > self.revision
                            || p.receipt.paid_at_ms.is_none()
                            || p.receipt.reversal_order.is_some_and(|r| r <= order)
                    })
                {
                    return Err(Error::Corrupt);
                }
                if let Some(payment) = &p.receipt.payment_id {
                    if !tenant_valid(payment) || payments.insert(payment, id).is_some() {
                        return Err(Error::Corrupt);
                    }
                }
            }
        } else if !self.purchases.is_empty() || !self.events.is_empty() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
