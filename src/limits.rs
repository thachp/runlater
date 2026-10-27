//! Durable, tenant-wide limits for the single default logical queue.
use crate::core::{Fault, LimitReason};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueueLimits {
    pub max_active_tasks: u32,
    pub max_payload_bytes: u32,
    pub max_concurrent: u32,
    pub dispatch_per_second: u32,
    pub dispatch_burst: u32,
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_active_tasks: 1000,
            max_payload_bytes: 128 * 1024,
            max_concurrent: 4,
            dispatch_per_second: 20,
            dispatch_burst: 20,
        }
    }
}
impl QueueLimits {
    pub fn validate(&self) -> Result<(), Fault> {
        if !(1..=1000).contains(&self.max_active_tasks)
            || !(1..=128 * 1024).contains(&self.max_payload_bytes)
            || !(1..=64).contains(&self.max_concurrent)
            || !(1..=100).contains(&self.dispatch_per_second)
            || !(1..=100).contains(&self.dispatch_burst)
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bucket {
    pub available_milli: u64,
    pub refilled_ms: i64,
}
impl Bucket {
    pub fn new(limits: &QueueLimits, now: i64) -> Self {
        Self {
            available_milli: limits.dispatch_burst as u64 * 1000,
            refilled_ms: now,
        }
    }
    pub fn refill(&mut self, limits: &QueueLimits, now: i64) {
        let elapsed = now.saturating_sub(self.refilled_ms).max(0) as u64;
        self.available_milli = self
            .available_milli
            .saturating_add(elapsed.saturating_mul(limits.dispatch_per_second as u64))
            .min(limits.dispatch_burst as u64 * 1000);
        self.refilled_ms = self.refilled_ms.max(now);
    }
    pub fn take(&mut self, limits: &QueueLimits, now: i64) -> Result<(), Fault> {
        self.refill(limits, now);
        if self.available_milli < 1000 {
            let missing = 1000 - self.available_milli;
            let refill_ms = missing.div_ceil(limits.dispatch_per_second as u64) as i64;
            // Include any backwards-clock gap: no future tokens are minted early.
            return Err(Fault::Limited {
                reason: LimitReason::DispatchRate,
                retry_after_ms: self
                    .refilled_ms
                    .saturating_sub(now)
                    .max(0)
                    .saturating_add(refill_ms),
            });
        }
        self.available_milli -= 1000;
        Ok(())
    }
}
