//! Bounded tenant-local observations, not billing counters or provider Queue telemetry.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const MINUTE_MS: i64 = 60_000;
pub const BUCKETS: usize = 60;
pub const MAX_COUNT: u64 = 1_000_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    AdmissionActiveTasksDenied,
    AdmissionPayloadDenied,
    AdmissionRetainedTasksDenied,
    ClaimPaused,
    PausedAgeExpired,
    ClaimReferences,
    ClaimIgnored,
    ClaimMissing,
    ClaimRateDenied,
    ClaimConcurrencyDenied,
    ClaimAgeExpired,
    AttemptStarted,
    AttemptSucceeded,
    AttemptTimeout,
    AttemptRetryableHttp,
    AttemptPermanentHttp,
    AttemptLeaseExpiredUnknown,
    AttemptUnknownFailure,
    StaleResultsIgnored,
    ClockRegressedObservations,
}
impl Kind {
    pub const ALL: [Self; 20] = [
        Self::AdmissionActiveTasksDenied,
        Self::AdmissionPayloadDenied,
        Self::AdmissionRetainedTasksDenied,
        Self::ClaimPaused,
        Self::PausedAgeExpired,
        Self::ClaimReferences,
        Self::ClaimIgnored,
        Self::ClaimMissing,
        Self::ClaimRateDenied,
        Self::ClaimConcurrencyDenied,
        Self::ClaimAgeExpired,
        Self::AttemptStarted,
        Self::AttemptSucceeded,
        Self::AttemptTimeout,
        Self::AttemptRetryableHttp,
        Self::AttemptPermanentHttp,
        Self::AttemptLeaseExpiredUnknown,
        Self::AttemptUnknownFailure,
        Self::StaleResultsIgnored,
        Self::ClockRegressedObservations,
    ];
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    values: BTreeMap<Kind, u64>,
    saturated: bool,
}
impl Counts {
    fn add(&mut self, kind: Kind, count: u64) {
        let value = self.values.entry(kind).or_default();
        let next = (*value).min(MAX_COUNT).saturating_add(count.min(MAX_COUNT));
        *value = next.min(MAX_COUNT);
        self.saturated |= next >= MAX_COUNT;
    }
    fn get(&self, kind: Kind) -> u64 {
        self.values.get(&kind).copied().unwrap_or(0).min(MAX_COUNT)
    }
    fn merge(&mut self, other: &Self) {
        for kind in Kind::ALL {
            self.add(kind, other.get(kind));
        }
        self.saturated |= other.saturated || other.values.values().any(|n| *n >= MAX_COUNT);
    }
    fn view(&self) -> Value {
        let values: BTreeMap<_, _> = Kind::ALL.into_iter().map(|k| (k, self.get(k))).collect();
        let errors = [
            Kind::AttemptTimeout,
            Kind::AttemptRetryableHttp,
            Kind::AttemptPermanentHttp,
            Kind::AttemptLeaseExpiredUnknown,
            Kind::AttemptUnknownFailure,
        ]
        .into_iter()
        .map(|k| self.get(k))
        .sum::<u64>();
        let completed = errors + self.get(Kind::AttemptSucceeded);
        let saturated = self.saturated || self.values.values().any(|n| *n >= MAX_COUNT);
        json!({"counts":values,"saturated":saturated,"attempt_completed":completed,"attempt_errors_or_unknown":errors,"attempt_error_ratio":if completed==0||saturated{None}else{Some(errors as f64/completed as f64)}})
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    minute: i64,
    counts: Counts,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    last_observed_ms: Option<i64>,
    totals: Counts,
    buckets: Vec<Bucket>,
}
impl Metrics {
    pub fn observe(&mut self, kind: Kind, now: i64) {
        let at = now.max(0).max(self.last_observed_ms.unwrap_or(0));
        let minute = at / MINUTE_MS;
        self.buckets
            .retain(|b| b.minute >= minute - (BUCKETS as i64 - 1) && b.minute <= minute);
        let index = if let Some(i) = self.buckets.iter().position(|b| b.minute == minute) {
            i
        } else {
            self.buckets.push(Bucket {
                minute,
                counts: Counts::default(),
            });
            self.buckets.len() - 1
        };
        if now < at {
            self.totals.add(Kind::ClockRegressedObservations, 1);
            self.buckets[index]
                .counts
                .add(Kind::ClockRegressedObservations, 1);
        }
        self.totals.add(kind, 1);
        self.buckets[index].counts.add(kind, 1);
        self.last_observed_ms = Some(at);
    }
    /// Pure projection: old slots expire logically without a write or new alarm.
    pub fn view(&self, now: i64) -> Value {
        let effective = now.max(0).max(self.last_observed_ms.unwrap_or(0));
        let minute = effective / MINUTE_MS;
        let windows: Vec<Value> = [1i64, 5, 60]
            .into_iter()
            .map(|width| {
                let start = minute - (width - 1);
                let mut counts = Counts::default();
                for bucket in &self.buckets {
                    if bucket.minute >= start && bucket.minute <= minute {
                        counts.merge(&bucket.counts);
                    }
                }
                json!({"bucket_minutes":width,"start_inclusive_ms":start.saturating_mul(MINUTE_MS),"end_exclusive_ms":minute.saturating_add(1).saturating_mul(MINUTE_MS),"observed_through_ms":effective,"observations":counts.view()})
            })
            .collect();
        json!({"sampled_at_ms":now,"effective_sample_ms":effective,"last_observed_at_ms":self.last_observed_ms,"clock_regressed":now<effective,"bucket_width_ms":MINUTE_MS,"retained_bucket_capacity":BUCKETS,"windows":windows,"totals":self.totals.view()})
    }
}
