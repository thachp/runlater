//! Product limits from `docs/spec/PRODUCT.md`. Change them there first.

pub const SECOND_MS: i64 = 1_000;
pub const MINUTE_MS: i64 = 60 * SECOND_MS;
pub const DAY_MS: i64 = 86_400_000;

pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 32;
/// Sum of name and value lengths across caller-supplied headers.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_SCHEDULE_AHEAD_MS: i64 = 7 * DAY_MS;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;
pub const MAX_ATTEMPTS: u32 = 5;
pub const ATTEMPT_TIMEOUT_MS: i64 = 10 * SECOND_MS;
/// How long a claimed attempt may run before recovery treats its result as unknown.
/// Must comfortably exceed the attempt timeout.
pub const LEASE_MS: i64 = 30 * SECOND_MS;

pub const RETRY_BASE_MS: i64 = 10 * SECOND_MS;
pub const RETRY_CAP_MS: i64 = 10 * MINUTE_MS;

/// Tasks a project may hold at once, finished ones included until they are purged.
/// Bounds storage even when tasks are scheduled and canceled without using attempts.
pub const MAX_RETAINED_TASKS: i64 = 1_000;

/// Terminal tasks and their attempts are kept this long, then purged.
pub const RETENTION_MS: i64 = 30 * DAY_MS;

pub const TRIAL_ATTEMPTS: u32 = 100;
pub const TRIAL_DURATION_MS: i64 = 7 * DAY_MS;

const _: () = assert!(LEASE_MS > 2 * ATTEMPT_TIMEOUT_MS);
const _: () = assert!(DEFAULT_MAX_ATTEMPTS <= MAX_ATTEMPTS);
