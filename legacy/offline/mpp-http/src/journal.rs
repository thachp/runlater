//! Restart-safe, offline-only challenge/submission journal. No I/O or provider calls.
//! A host must atomically validate the CURRENT purchase-ledger revision and journal
//! revision, then persist the mutation BEFORE any hypothetical dispatch. Journal CAS
//! alone cannot detect a stale ledger clone; this module supplies no storage engine. A binding means the outcome may be unknown, never permission to retry a
//! charge. Snapshots are trusted storage, not public request or payment evidence.
use crate::{
    hash, stripe, Challenge, CredentialField, Error, IssuedChallenge, OfflineMerchantContext,
};
use runlater_offline_credit_purchases::{self as credit, Intent, OfflineLedger, Receipt, SAFE};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const MAX_CHALLENGES: usize = credit::MAX_INTENTS;
pub const MAX_SNAPSHOT: usize = 256 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum JournalError {
    Codec(Error),
    Purchase(credit::Error),
    StaleRevision,
    ClockRegressed,
    Conflict,
    Completed,
    Missing,
    Capacity,
    Corrupt,
}
impl From<Error> for JournalError {
    fn from(value: Error) -> Self {
        Self::Codec(value)
    }
}
impl From<credit::Error> for JournalError {
    fn from(value: credit::Error) -> Self {
        Self::Purchase(value)
    }
}

/// An immutable recovery locator, not a token, request body, verified payment or
/// dispatch instruction. No raw SPT or credential is retained in the journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub provider_idempotency_key: String,
    pub credential_fingerprint: String,
    pub request_fingerprint: String,
    pub bound_at_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    intent: Intent,
    context: OfflineMerchantContext,
    challenge: Challenge,
    issued_at_ms: i64,
    submission: Option<Submission>,
}
impl Entry {
    fn issued(&self) -> IssuedChallenge {
        IssuedChallenge {
            challenge: self.challenge.clone(),
            intent: self.intent.clone(),
            context: self.context.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    fixture_only: bool,
    revision: u64,
    clock_ms: i64,
    #[serde(deserialize_with = "unique_entries")]
    entries: BTreeMap<String, Entry>,
}
// serde's default map decoder accepts repeated keys. Persistent identity maps
// must reject them rather than silently discard an earlier tombstone.
fn unique_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Entry>, D::Error> {
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<String, Entry>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("unique challenge entries")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
            let mut entries = BTreeMap::new();
            while let Some((id, entry)) = access.next_entry::<String, Entry>()? {
                if entries.len() >= MAX_CHALLENGES || entries.insert(id, entry).is_some() {
                    return Err(de::Error::custom(
                        "duplicate or excessive challenge entries",
                    ));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(Unique)
}
#[derive(Clone)]
pub struct OfflineJournal {
    state: Snapshot,
}
impl fmt::Debug for OfflineJournal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("OfflineJournal(<redacted>, fixture_only=true, activation=false)")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryState {
    /// No credential was durably pinned. This is not proof of provider nonpayment.
    Unbound,
    /// Includes crash-before-dispatch, timeout and lost-response cases. Reconcile
    /// authoritatively; do not create a fresh key/token or infer failure from expiry.
    ReconcileRequired,
    /// An independently verified ledger event records the current credit outcome.
    /// Later settlement/refund events must still be reconciled; this is not provider
    /// finality or permission to stop observing an actual payment.
    LedgerRecorded,
}
/// Diagnostic projection only; never a settlement proof.
/// ```compile_fail
/// use runlater_offline_mpp_http::journal::Recovery;
/// use runlater_offline_credit_purchases::VerifiedEvent;
/// fn fabricate(recovery: Recovery) -> VerifiedEvent { recovery.into() }
/// ```
#[derive(Clone, Debug)]
pub struct Recovery {
    pub fixture_only: bool,
    pub activation_enabled: bool,
    pub challenge_id: String,
    pub intent_id: String,
    pub intent_digest: String,
    pub submission: Option<Submission>,
    pub receipt: Receipt,
    pub state: RecoveryState,
}
fn resolved(receipt: &Receipt) -> bool {
    receipt.payment_id.is_some() || receipt.no_payment_final
}
fn timestamp(now: i64) -> bool {
    now > 0 && now as u64 <= SAFE
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Default for OfflineJournal {
    fn default() -> Self {
        Self::new()
    }
}
impl OfflineJournal {
    pub fn new() -> Self {
        Self {
            state: Snapshot {
                schema: 1,
                fixture_only: true,
                revision: 1,
                clock_ms: 0,
                entries: BTreeMap::new(),
            },
        }
    }
    pub fn revision(&self) -> u64 {
        self.state.revision
    }
    fn check(&self, expected: u64, now: i64) -> Result<(), JournalError> {
        if expected != self.revision() {
            return Err(JournalError::StaleRevision);
        }
        if !timestamp(now) || now < self.state.clock_ms {
            return Err(JournalError::ClockRegressed);
        }
        Ok(())
    }
    fn commit(&mut self, mut next: Self, now: i64) -> Result<(), JournalError> {
        next.state.revision = self
            .revision()
            .checked_add(1)
            .filter(|n| *n <= SAFE)
            .ok_or(JournalError::Capacity)?;
        next.state.clock_ms = now;
        next.validate()?;
        // Every committed journal must fit in its own restore envelope.
        if serde_json::to_vec(&next.state)
            .map_err(|_| JournalError::Corrupt)?
            .len()
            > MAX_SNAPSHOT
        {
            return Err(JournalError::Capacity);
        }
        *self = next;
        Ok(())
    }
    /// Read the cap-reserved quote from the ledger. One immutable challenge per
    /// purchase and one purchase per challenge ID; no rotate-on-timeout operation.
    /// Exact issuance replay returns the same challenge, including after expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        expected: u64,
        ledger: &OfflineLedger,
        project: &str,
        intent_id: &str,
        context: OfflineMerchantContext,
        challenge_id: &str,
        body: &[u8],
        field: CredentialField,
        now: i64,
    ) -> Result<Challenge, JournalError> {
        self.check(expected, now)?;
        let intent = ledger.intent(project, intent_id)?;
        let issued = IssuedChallenge::offline(intent, context, challenge_id, body, field)?;
        if let Some(old) = self.state.entries.get(challenge_id) {
            if old.intent != *intent
                || old.context != issued.context
                || old.challenge != issued.challenge
            {
                return Err(JournalError::Conflict);
            }
            return Ok(old.challenge.clone());
        }
        if self
            .state
            .entries
            .values()
            .any(|e| e.intent.project_id == project && e.intent.id == intent_id)
        {
            return Err(JournalError::Conflict);
        }
        if resolved(ledger.receipt(project, intent_id)?) {
            return Err(JournalError::Completed);
        }
        if now < intent.issued_at_ms || now >= intent.expires_at_ms {
            return Err(Error::Expired.into());
        }
        if self.state.entries.len() >= MAX_CHALLENGES {
            return Err(JournalError::Capacity);
        }
        let result = issued.challenge.clone();
        let mut next = self.clone();
        next.state.entries.insert(
            challenge_id.into(),
            Entry {
                intent: intent.clone(),
                context: issued.context,
                challenge: issued.challenge,
                issued_at_ms: now,
                submission: None,
            },
        );
        self.commit(next, now)?;
        Ok(result)
    }
    /// Recover a lost issuance response using the immutable purchase identity. The
    /// caller need not remember or allocate a replacement challenge ID after restart.
    /// This remains read-only after quote expiry or a recorded ledger event.
    pub fn challenge_for_purchase(
        &self,
        ledger: &OfflineLedger,
        project: &str,
        intent_id: &str,
    ) -> Result<&Challenge, JournalError> {
        let intent = ledger.intent(project, intent_id)?;
        let entry = self
            .state
            .entries
            .values()
            .find(|entry| entry.intent.project_id == project && entry.intent.id == intent_id)
            .ok_or(JournalError::Missing)?;
        if intent != &entry.intent {
            return Err(Error::Binding.into());
        }
        Ok(&entry.challenge)
    }
    /// Pin the first credential and exact provider descriptor before a hypothetical
    /// side effect. Only fingerprints and the provider idempotency key are stored.
    /// A different credential for the same purchase, or the same credential for a
    /// different purchase/project in this journal, conflicts permanently.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        &mut self,
        expected: u64,
        ledger: &OfflineLedger,
        project: &str,
        challenge_id: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        now: i64,
    ) -> Result<Submission, JournalError> {
        self.check(expected, now)?;
        let entry = self
            .state
            .entries
            .get(challenge_id)
            .ok_or(JournalError::Missing)?;
        let intent = ledger.intent(project, &entry.intent.id)?;
        if resolved(ledger.receipt(project, &entry.intent.id)?) {
            return Err(JournalError::Completed);
        }
        let credential = entry
            .issued()
            .decode_credential(intent, project, headers, body, now)?;
        let request = stripe::encode(&credential)?;
        let candidate = Submission {
            provider_idempotency_key: request.idempotency_key().into(),
            credential_fingerprint: hash(credential.spt.as_bytes()),
            request_fingerprint: hash(
                &serde_json::to_vec(&(
                    request.operation(),
                    request.url(),
                    request.api_version(),
                    request.content_type(),
                    request.idempotency_key(),
                    request.form_body_for_inspection(),
                ))
                .map_err(|_| JournalError::Corrupt)?,
            ),
            bound_at_ms: now,
        };
        if let Some(old) = &entry.submission {
            if old.provider_idempotency_key != candidate.provider_idempotency_key
                || old.credential_fingerprint != candidate.credential_fingerprint
                || old.request_fingerprint != candidate.request_fingerprint
            {
                return Err(JournalError::Conflict);
            }
            return Ok(old.clone());
        }
        if self
            .state
            .entries
            .values()
            .filter_map(|e| e.submission.as_ref())
            .any(|s| s.credential_fingerprint == candidate.credential_fingerprint)
        {
            return Err(JournalError::Conflict);
        }
        let mut next = self.clone();
        next.state.entries.get_mut(challenge_id).unwrap().submission = Some(candidate.clone());
        self.commit(next, now)?;
        Ok(candidate)
    }
    /// Query after restart, even after quote expiry. Never treats untrusted receipt
    /// syntax, timeout or expiry as settlement or definitive no-payment evidence.
    pub fn recovery(
        &self,
        ledger: &OfflineLedger,
        project: &str,
        challenge_id: &str,
    ) -> Result<Recovery, JournalError> {
        let entry = self
            .state
            .entries
            .get(challenge_id)
            .ok_or(JournalError::Missing)?;
        let intent = ledger.intent(project, &entry.intent.id)?;
        if intent != &entry.intent {
            return Err(Error::Binding.into());
        }
        let receipt = ledger.receipt(project, &entry.intent.id)?.clone();
        let state = if resolved(&receipt) {
            RecoveryState::LedgerRecorded
        } else if entry.submission.is_some() {
            RecoveryState::ReconcileRequired
        } else {
            RecoveryState::Unbound
        };
        Ok(Recovery {
            fixture_only: true,
            activation_enabled: false,
            challenge_id: challenge_id.into(),
            intent_id: intent.id.clone(),
            intent_digest: intent.digest(),
            submission: entry.submission.clone(),
            receipt,
            state,
        })
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, JournalError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.state).map_err(|_| JournalError::Corrupt)?;
        if bytes.len() > MAX_SNAPSHOT {
            return Err(JournalError::Capacity);
        }
        Ok(bytes)
    }
    /// Trusted, integrity-protected storage only. Shape validation is not a MAC,
    /// provider signature, durable CAS, or protection against storage rollback.
    pub fn restore(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() > MAX_SNAPSHOT {
            return Err(JournalError::Capacity);
        }
        let state = serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
        let journal = Self { state };
        journal.validate()?;
        Ok(journal)
    }
    fn validate(&self) -> Result<(), JournalError> {
        let s = &self.state;
        if s.schema != 1
            || !s.fixture_only
            || s.revision == 0
            || s.revision > SAFE
            || s.clock_ms < 0
            || s.clock_ms as u64 > SAFE
            || s.entries.len() > MAX_CHALLENGES
        {
            return Err(JournalError::Corrupt);
        }
        let mut purchases = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut minimum_revision = 1;
        let mut latest_mutation = 0;
        for (id, e) in &s.entries {
            minimum_revision += 1;
            latest_mutation = latest_mutation.max(e.issued_at_ms);
            if id != &e.challenge.id
                || !purchases.insert((&e.intent.project_id, &e.intent.id))
                || !timestamp(e.issued_at_ms)
                || e.issued_at_ms < e.intent.issued_at_ms
                || e.issued_at_ms >= e.intent.expires_at_ms
                || e.issued_at_ms > s.clock_ms
            {
                return Err(JournalError::Corrupt);
            }
            // Rebuild every quote/context binding, retaining only the validated
            // body digest. Raw request bytes are deliberately not persisted.
            e.challenge.validate().map_err(|_| JournalError::Corrupt)?;
            let mut canonical = IssuedChallenge::offline(
                &e.intent,
                e.context.clone(),
                id,
                b"",
                if e.challenge.header.is_some() {
                    CredentialField::PaymentAuthorization
                } else {
                    CredentialField::Authorization
                },
            )
            .map_err(|_| JournalError::Corrupt)?;
            if e.challenge.digest.is_none() {
                return Err(JournalError::Corrupt);
            }
            canonical.challenge.digest = e.challenge.digest.clone();
            if canonical.challenge != e.challenge {
                return Err(JournalError::Corrupt);
            }
            if let Some(submission) = &e.submission {
                minimum_revision += 1;
                latest_mutation = latest_mutation.max(submission.bound_at_ms);
                let suffix = submission
                    .provider_idempotency_key
                    .strip_prefix("runlater-offline-mpp-")
                    .ok_or(JournalError::Corrupt)?;
                if !digest_valid(suffix)
                    || !digest_valid(&submission.credential_fingerprint)
                    || !digest_valid(&submission.request_fingerprint)
                    || !credentials.insert(&submission.credential_fingerprint)
                    || !keys.insert(&submission.provider_idempotency_key)
                    || submission.bound_at_ms < e.issued_at_ms
                    || submission.bound_at_ms >= e.intent.expires_at_ms
                    || submission.bound_at_ms > s.clock_ms
                {
                    return Err(JournalError::Corrupt);
                }
            }
        }
        if s.revision != minimum_revision || s.clock_ms != latest_mutation {
            return Err(JournalError::Corrupt);
        }
        Ok(())
    }
}
